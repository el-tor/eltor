# Native foundation Chutney check

Run from the El Tor workspace root with the existing `testnet.sh` launcher.
This checks native bootstrap and authenticated base-resource construction. It
does not activate paid rounds, verify settlement, or establish application,
Firefox, onion-service, throughput, or production acceptance. Production
advertisement remains blocked outside `TestingTorNetwork`.

## Preserve the existing network

Check `./testnet.sh status` and coordinate with any active app/controllers before
stopping the network. Do not configure a replacement network, regenerate keys,
change the existing `nodes` symlink, or edit wallet/app configuration for this
check. Keep every test listener on loopback.

Before changing generated configs, save their exact bytes in a private runtime
directory. For example, with the network stopped:

```sh
umask 077
export FOUNDATION_RUN=".runtime/foundation-native/$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$FOUNDATION_RUN"
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
nodes = Path('chutney/net/nodes')
run = Path(os.environ['FOUNDATION_RUN'])
manifest = {'configs': {}, 'keys': {}}
for node in sorted(nodes.iterdir()):
    config = node / 'torrc'
    if not config.is_file():
        continue
    original = config.read_bytes()
    text = original.decode()
    if any(line.split() and line.split()[0].lower() == 'eltorfoundation'
           for line in text.splitlines()):
        raise SystemExit('Inspect the existing foundation configuration first')
    backup = run / node.name
    backup.mkdir(mode=0o700)
    (backup / 'torrc').write_bytes(original)
    manifest['configs'][node.name] = hashlib.sha256(original).hexdigest()
    for key in sorted((node / 'keys').rglob('*')):
        if key.is_file():
            manifest['keys'][str(key.relative_to(nodes))] = hashlib.sha256(
                key.read_bytes()).hexdigest()
    config.write_text(text + '\nElTorFoundation 1\nUseMicrodescriptors 0\n')
(run / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
```

The existing generated configs must already have `TestingTorNetwork 1` and the
local authorities. `UseMicrodescriptors 0` makes full signed capability/policy
metadata available; microdescriptor hints do not substitute for that snapshot.
Omitted `ElTorFoundationTerms` uses only the isolated zero-price candidate: zero
rate/initial fee, 15000 ms grace, 1800000 ms hard age, three periods, 30000 ms
setup and unlimited *paid* quota. Base free limits are unchanged. Existing
`AssumeReachable`, DNS and private-exit verification settings stay intact.

## Build and run

```sh
make -C tor -j2 src/app/tor
./testnet.sh start
./testnet.sh status
python3 tor/src/test/payment_foundation_native_probe.py \
  --nodes chutney/net/nodes --origin 005c --path 006m,007m,004r \
  --output "$FOUNDATION_RUN/base-summary.json"
./testnet.sh wait_for_bootstrap
```

If `start` is waiting for the standalone client to complete a circuit, run the
probe from another terminal during that wait. It dispatches one explicit
constructor, never retries an uncertain build, and requires a signed zero-rate,
zero-fee policy at every selected hop. It uses the existing private UNIX control
socket and cookie; it never prints cookies, proofs, payment IDs, bindings or MAC
keys. It performs no COMMIT, START, authorization or wallet operation. A complete
14-line initial registration for each hop demonstrates successful authenticated
resource negotiation/exporter installation on that path.

Native relay reachability circuits use the same base admission and resource
bounds. Their bandwidth self-test may exhaust the queue/burst and close: that is
expected bounded refusal, not paid throughput. The client intentionally cannot
replace a missing foundation controller with an automatic legacy application
circuit. Ordinary `testnet.sh verify` transmission therefore needs a separately
provisioned foundation client coordinator and all-hop activation; the native
probe alone must not be reported as that transmission test.

The generated TCP controls are `127.0.0.1:8055` through `8059`, then `8061`
through `8063`; standalone client `005c` uses control `8060` and SOCKS `9060`.
Controllers requiring password authentication may use a separately generated
private password/hash while keeping cookie authentication and original backups.
Keep the plaintext in a 0600 runtime file, never in tracked config, argv or logs.

## Restore after the coordinated acceptance run

Stop the test controllers, deactivate the app if used, then stop with
`./testnet.sh stop`. Restore only the generated torrcs saved by this run. Verify
their original hashes and every saved node-key hash; do not overwrite changed
keys or unrelated config additions without investigating them.

```sh
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
nodes = Path('chutney/net/nodes')
run = Path(os.environ['FOUNDATION_RUN'])
manifest = json.loads((run / 'manifest.json').read_text())
for name, digest in manifest['keys'].items():
    assert hashlib.sha256((nodes / name).read_bytes()).hexdigest() == digest
for name, digest in manifest['configs'].items():
    original = (run / name / 'torrc').read_bytes()
    assert hashlib.sha256(original).hexdigest() == digest
    (nodes / name / 'torrc').write_bytes(original)
PY
```

## Executed evidence

On 2026-10-29, native Tor `a9a932fc79b6ea123b024e11e187e273ac26dbd5`
(embedded source mirror `c851e9b`) ran the existing nine-node network. All nine
nodes reported current 100% bootstrap over authenticated, responsive controls.
An explicit `006m → 007m → 004r` circuit reached BUILT in approximately 200 ms;
all three hops returned complete initial registrations. All 68 original saved
node-key hashes were unchanged. No wallet/payment command was issued by the
native probe. The reproducible probe also completed successfully on that stack.

The live run exposed and fixed provisional CREATE queue rejection, a bootstrap
dependency on legacy predicted circuits, and a circuitmux spin when a refused
head remained queued on a closing circuit. Native app/test builds and 13 focused
queue/quota/reachability regressions passed; the queued provisional CREATE test
also verifies that unconfirmed RELAY/payment-control traffic stays forbidden and
that a marked queued circuit cannot stall the real flush loop. Existing keys,
wallets, app resources and unrelated generated settings were preserved.

Raw logs, temporary auth material and constructor proofs remain private runtime
artifacts. These observations are integration evidence, not an independent
cryptographic review, paid settlement result or permission to enable production.
