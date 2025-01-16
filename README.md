El Tor
======

High bandwidth Tor network fork. Incentivized by the Bitcoin Lightning Network. Relays earn sats via BOLT 12 and blinded paths.

#### Projects
- eltor - Fork of the Tor network. Adds paid circuit handling and EXTENDPAIDCIRCUIT RPC https://github.com/el-tor/eltor
- eltord - Main daemon that runs El Tor, connects to wallets, listens for payment events and calls rpc's https://github.com/el-tor/eltord
- eltor-app - VPN-like client to connect to El Tor and remote wallets. UI for running relays and creating hidden services. https://github.com/el-tor/eltor-app

#### Libraries
- libeltor - Fork of libtor. Rust crate for bundling inside your project a fully-running eltord daemon with fallback to the normal Tor network https://github.com/el-tor/libeltor 
- LNI - Lightning node interface library. Standard interface to remote connect to CLN, LND, Phoenixd and other implementations. Rust language bindings for android, ios, and javascript (nodejs, react-native). https://github.com/lightning-node-interface/lni 
    
#### Testnets
- chutney - Tor testnet fork https://github.com/el-tor/chutney

#### Spec:
- [(00) El Tor Spec](https://github.com/el-tor/eltord/blob/master/spec/00_spec.md)
- [(01) El Tor](https://github.com/el-tor/eltord/blob/master/spec/01_paid_circuits.md)


Tor
===

Tor protects your privacy on the internet by hiding the connection between
your Internet address and the services you use. We believe Tor is reasonably
secure, but please ensure you read the instructions and configure it properly.

## Build

To build Tor from source:

```
./configure
make
make install
```

To build Tor from a just-cloned git repository:

```
./autogen.sh
./configure
make
make install
```

## Releases

The tarballs, checksums and signatures can be found here: https://dist.torproject.org

- Checksum: `<tarball-name>.sha256sum`
- Signatures: `<tarball-name>.sha256sum.asc`

### Schedule

You can find our release schedule here:

- https://gitlab.torproject.org/tpo/core/team/-/wikis/NetworkTeam/CoreTorReleases

### Keys that CAN sign a release

The following keys are the maintainers of this repository. One or many of
these keys can sign the releases, do NOT expect them all:

- Alexander Færøy:
    [514102454D0A87DB0767A1EBBE6A0531C18A9179](https://keys.openpgp.org/vks/v1/by-fingerprint/1C1BC007A9F607AA8152C040BEA7B180B1491921)
- David Goulet:
    [B74417EDDF22AC9F9E90F49142E86A2A11F48D36](https://keys.openpgp.org/vks/v1/by-fingerprint/B74417EDDF22AC9F9E90F49142E86A2A11F48D36)
- Nick Mathewson:
    [2133BC600AB133E1D826D173FE43009C4607B1FB](https://keys.openpgp.org/vks/v1/by-fingerprint/2133BC600AB133E1D826D173FE43009C4607B1FB)

## Development

See our hacking documentation in [doc/HACKING/](./doc/HACKING).

## Resources

Home page:

- https://www.torproject.org/

Download new versions:

- https://www.torproject.org/download/tor

How to verify Tor source:

- https://support.torproject.org/little-t-tor/

Documentation and Frequently Asked Questions:

- https://support.torproject.org/

How to run a Tor relay:

- https://community.torproject.org/relay/ 
