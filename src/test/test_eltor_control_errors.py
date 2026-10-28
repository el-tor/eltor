#!/usr/bin/env python3
"""Integration regression for EXTENDPAIDCIRCUIT cleanup (no network needed).

Usage: python3 test_eltor_control_errors.py /path/to/tor [--eltord]
"""
import pathlib, signal, socket, subprocess, sys, tempfile, time

binary=str(pathlib.Path(sys.argv[1]).resolve())
embedded='--eltord' in sys.argv[2:]
with tempfile.TemporaryDirectory(prefix='eltor-control-test-') as temporary:
    base=pathlib.Path(temporary);ctrl=base/'control';config=base/'torrc'
    config.write_text(f'DataDirectory {base}/data\nSocksPort 0\nControlSocket {ctrl}\n'
                      'CookieAuthentication 1\nDisableNetwork 1\nRunAsDaemon 0\nLog notice stdout\n')
    with (base/'process.log').open('wb') as log:
        child=subprocess.Popen([binary,*(['client'] if embedded else []),'-f',str(config)],
                               cwd=base,stdout=log,stderr=subprocess.STDOUT)
        try:
            for _ in range(100):
                if ctrl.exists():break
                assert child.poll() is None, 'Tor exited during initialization'
                time.sleep(.05)
            cookie=(base/'data/control_auth_cookie').read_bytes().hex()
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
                sock.settimeout(3);sock.connect(str(ctrl));reader=sock.makefile('rb')
                sock.sendall(f'AUTHENTICATE {cookie}\r\n'.encode());assert reader.readline()==b'250 OK\r\n'
                for circuit,body in [('4294967295','invalid'),('not-an-id','invalid'),('0','invalid')]*5:
                    sock.sendall(f'+EXTENDPAIDCIRCUIT {circuit}\r\n{body}\r\n.\r\n'.encode())
                    response=reader.readline()
                    assert response.startswith(b'5'), repr(response)
                    sock.sendall(b'GETINFO version\r\n')
                    assert reader.readline().startswith(b'250-version=')
                    assert reader.readline()==b'250 OK\r\n'
                assert child.poll() is None, 'Tor crashed handling a rejected command'
                print('PASS: 15 rejected payment-circuit commands; Tor remains responsive')
        finally:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
                try:child.wait(timeout=3)
                except subprocess.TimeoutExpired:child.kill();child.wait()
