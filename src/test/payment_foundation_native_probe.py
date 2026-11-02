#!/usr/bin/env python3
"""Construct one unfunded zero-price foundation path on an existing testnet.

Run from the workspace root. Uses existing cookie-authenticated UNIX controls;
never starts Tor, COMMITs, authorizes payment, calls a wallet, or resends a build.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import struct
import time
from pathlib import Path


class Control:
    def __init__(self, node):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(5)
        self.socket.connect(str(node / "control"))
        self.file = self.socket.makefile("rwb", buffering=0)
        if self.command("AUTHENTICATE " +
                        (node / "control_auth_cookie").read_bytes().hex()) != ["250 OK"]:
            raise RuntimeError("control authentication failed")

    def command(self, command):
        self.file.write((command + "\r\n").encode("ascii"))
        lines, size = [], 0

        def line():
            nonlocal size
            data = self.file.readline(32769)
            size += len(data)
            if not data or size > 32768 or not data.endswith(b"\r\n"):
                raise RuntimeError("invalid or oversized control response")
            value = data[:-2].decode("ascii")
            lines.append(value)
            return value

        while True:
            status = line()
            if not re.match(r"^[2456][0-9]{2}[-+ ]", status):
                raise RuntimeError("invalid control status")
            if status[3] == "+":
                while line() != ".":
                    pass
            elif status[3] == " ":
                return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", type=Path, required=True)
    parser.add_argument("--origin", default="005c")
    parser.add_argument("--path", default="006m,007m,004r")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    path = args.path.split(",")
    if not 1 <= len(path) <= 16 or any(
        not re.fullmatch(r"[0-9]{3}[acmr]", name)
        for name in [args.origin] + path
    ):
        raise RuntimeError("invalid generated-node path")
    control = Control(args.nodes / args.origin)
    for name in ("ElTorFoundation", "TestingTorNetwork"):
        if control.command("GETCONF " + name) != ["250 " + name + "=1"]:
            raise RuntimeError("explicit isolated foundation mode required")
    rows = []
    for name in path:
        fingerprint = (args.nodes / name / "fingerprint").read_text().split()[1]
        if not re.fullmatch(r"[0-9A-Fa-f]{40}", fingerprint):
            raise RuntimeError("invalid relay identity")
        descriptor = control.command("GETINFO desc/id/" + fingerprint)
        if "eltor-free-capacity 1 2 128 600000" not in descriptor:
            raise RuntimeError("missing signed base capability")
        terms = [line.split()[-1] for line in descriptor
                 if line.startswith("eltor-payment-start 1 226 227 228 229 ")]
        if len(terms) != 1 or not re.fullmatch(r"[0-9a-f]{110}", terms[0]):
            raise RuntimeError("missing canonical signed initial policy")
        policy = struct.unpack(">BBBQIIIQQIQI", bytes.fromhex(terms[0]))
        if policy[:3] != (1, 1, 10) or policy[3] or policy[10]:
            raise RuntimeError("probe permits only zero-rate/zero-fee policies")
        proof = secrets.token_bytes(32)
        identifiers = [secrets.token_bytes(32) for _ in range(10)]
        material = hashlib.sha256(proof).digest() + proof + b"".join(identifiers)
        rows.append(fingerprint + " " + material.hex())

    # Exactly one constructor dispatch. A lost reply is uncertain, never a
    # reason for this tool to repeat the command or manufacture a new payment.
    reply = control.command("+EXTENDPAIDCIRCUIT 0\r\n" +
                            "\r\n".join(rows) + "\r\n.")
    if len(reply) != 1 or not re.fullmatch(r"250 EXTENDED [1-9][0-9]*", reply[0]):
        raise RuntimeError("native constructor refused")
    circuit = reply[0].split()[-1]
    deadline = time.monotonic() + 10
    while True:
        status = control.command("GETINFO circuit-status")
        if any(line.startswith(circuit + " BUILT ") for line in status):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("native path did not become BUILT")
        time.sleep(0.2)
    binding = control.command("ELTOR_CIRCUIT_BIND 1 " + circuit)
    fields = binding[0].split()
    if len(binding) != 1 or len(fields) != 7 or fields[:3] != ["250", "ELTOR_CIRCUIT", "1"]:
        raise RuntimeError("native circuit binding failed")
    instance, handle = fields[3:5]
    if int(fields[5]) != len(path):
        raise RuntimeError("native path length changed")
    for hop in range(1, len(path) + 1):
        lines = control.command(
            f"ELTOR_INITIAL_REGISTRATION_GET 1 {instance} {handle} {hop}")
        if (len(lines) != 14 or not lines[0].startswith("250-ELTOR_INITIAL_REGISTRATION 1 ")
                or sum(line.startswith("250-BINDING ") for line in lines) != 1
                or sum(line.startswith("250-POLICY ") for line in lines) != 1
                or sum(line.startswith("250-ROUND ") for line in lines) != 10
                or lines[-1] != "250 OK"):
            raise RuntimeError("authenticated native registration incomplete")
    summary = {"built": True, "hops": len(path), "authenticated_registrations": len(path),
               "payment_commands": 0, "wallet_calls": 0,
               "bootstrap": control.command("GETINFO status/bootstrap-phase")[0]}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", opener=lambda path, flags: os.open(path, flags, 0o600)) as output:
        json.dump(summary, output, indent=2)
        output.write("\n")
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
