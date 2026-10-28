# El Tor upstream 0.5.0 integration

## Source baseline

This local integration merges official Tor `main` at
`4792124a79a10fd66ecfd4f16771396372d744a0` into El Tor
`3d251b16378c095aacd6fa21d943c46a3d426077`. The official source is
<https://gitlab.torproject.org/tpo/core/tor.git>. Its version is
**0.5.0.0-alpha-dev**; this is a development snapshot, not a stable release.
The shared ancestor is `7a5d94bcf842299534b667433424ac7a1133d371`.
The integration branch is `merge-upstream-0.5.0`.

## Merge decisions

- Keep upstream's current handshake interfaces, variable key-material lengths,
  relay message abstraction, configuration validation, and removal of TAP and
  legacy EXTEND circuit construction.
- Preserve El Tor's 2048-byte cell payload, per-hop payment metadata, payment
  control commands, payment events, relay descriptors, and reliability fixes.
- Adapt payment inspection to the decoded relay message's body and actual
  length. The standalone build keeps the unpaid extension exception restricted
  to `TestingTorNetwork`; it remains separate from a bounded free allowance.
- Correct `ElTorSatsRate` storage to an integer, matching its configuration type.
  Unit-test configuration validation now checks the declaration.
- Preserve upstream congestion-control algorithms. Their historical reference
  vectors explicitly set the original 31-cell SENDME interval and window
  parameters; production defaults continue to derive from the transport size.
- Update framing tests for the enlarged cell capacity, including padding buffer
  capacity, malformed-length rejection, and payment metadata preservation.

## CGO compatibility boundary

Upstream's CGO construction is specified for a 509-byte cell payload, with
fixed-size cryptographic inputs. El Tor's 2048-byte payload is incompatible.
Negotiating that construction unchanged would leave part of an El Tor cell
outside its cryptographic protection.

Until a separate enlarged-cell profile is specified and independently tested,
El Tor retains TOR1 whole-cell encryption. It does not advertise, recommend,
require, select, or accept `Relay=6` CGO negotiation. Direct initialization of
CGO circuit encryption also fails closed. Upstream CGO primitive vectors remain
in the test suite and retain their original 509-byte inputs; they do not imply
that enlarged-cell CGO is supported. Whole-cell TOR1 round trips and explicit
CGO rejection have regression coverage.

This fork is not wire-compatible with the public Tor network. A future CGO
profile needs its own protocol advertisement and cross-implementation vectors;
changing the primitive constants alone is not a validated migration.

## Embedded source and validation

The companion `libeltor-sys` branch vendors this merged source under
`libtor-src/tor-src`. Its existing `build.sh` and stricter paid-relay extension
policy are preserved. Its Rust crate version labels are historical packaging
metadata; the C source version is 0.5.0.0-alpha-dev.

From the Tor source directory, validation commands are:

```sh
./autogen.sh
./configure --disable-asciidoc --enable-unittests CFLAGS='-O2 -g0'
make -j4
./src/test/test --quiet
make check-TESTS
python3 src/test/test_eltor_control_errors.py src/app/tor
```

The functional suite completed with 32 passing test groups, two environment
skips, and no failures. The complete unit binary and targeted handshake,
framing, payment, congestion-control, protocol-version, and relay-encryption
checks pass. The control regression rejects 15 malformed commands and confirms
that Tor remains responsive.

The aggregate `make check` additionally invokes the style checker. The fork
already contains hundreds of style violations: comparison against the
pre-merge source found 361 diagnostics. These are an existing formatting
backlog, not a passing style result. New merge-specific diagnostics are checked
separately. Upstream's existing trailing blank lines are retained as imported.

Runtime acceptance additionally requires rebuilding the embedded daemon and
Tauri app, nine-node Chutney bootstrap and transmission, app activation, and an
actual Firefox HTTPS page through the app's SOCKS5 router. Workspace launchers
and the root `AGENTS.md` document those steps. A successful free-mode local test
is not a Lightning settlement or public-network interoperability test.
