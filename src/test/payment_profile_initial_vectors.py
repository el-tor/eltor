#!/usr/bin/env python3
"""Reproduce the synthetic initial-profile C fixtures using Python's stdlib.

From the Tor checkout:
  python3 src/test/payment_profile_initial_vectors.py --check

This is a second codec implementation, not an independent cryptographic review.
Inputs are the first public renewal fixture's artificial seed, exact transcript,
policy and ordered IDs. It is not a valid ntor handshake or a wallet transaction.
"""

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re


def be(value, size):
    return value.to_bytes(size, "big")


def domain(text):
    raw = text.encode("ascii")
    return be(len(raw), 2) + raw


def digest(raw):
    return hashlib.sha256(raw).digest()


def initial_vectors(source):
    fixture = json.loads(source.read_text())["fixtures"][0]
    seed = bytes.fromhex(fixture["ntor_key_seed_hex"])
    client = bytes.fromhex(fixture["client_HDATA_hex"])
    server = bytes.fromhex(fixture["server_HDATA_hex"])
    terms = bytes.fromhex(fixture["terms_hex"])
    ids = bytes.fromhex(fixture["initial_ids_hex"])
    context = digest(be(len(client), 8) + client + be(len(server), 8) + server)
    salt = digest(domain("eltor/payment-renew/v1/extract"))
    prk = hmac.digest(salt, seed, "sha256")

    def expand(label):
        # Each output is 32 bytes, so RFC 5869 Expand needs one block.
        return hmac.digest(prk, domain(label) + context + b"\x01", "sha256")

    binding = expand("eltor/payment-renew/v1/circuit-binding")
    request_key = expand("eltor/payment-start/v1/request-key")
    reply_key = expand("eltor/payment-start/v1/reply-key")
    q = digest(domain("eltor/payment-renew/v1/terms") + terms)
    a0 = digest(domain("eltor/payment-renew/v1/initial") + binding + q + ids)
    nonce = bytes(range(16))

    def authenticate(command, body):
        assert len(body) == 431
        key = request_key if command in (226, 228) else reply_key
        message = (domain("eltor/payment-start/v1/mac") + binding
                   + bytes([command]) + body)
        return body + hmac.digest(key, message, "sha256")

    def request_digest(wire):
        return digest(domain("eltor/payment-start/v1/request") + wire)

    # COMMIT: version, flags, nonce, terms, A0, reserved.
    commit = authenticate(226, b"\x01\x00" + nonce + terms + a0 + bytes(326))
    # COMMITTED success with an illustrative 25000 ms remaining setup budget.
    committed = authenticate(227, b"\x01\x00" + nonce + request_digest(commit)
                             + q + a0 + be(25000, 4) + bytes(313))
    # START round one; this is a distinct request with the same synthetic nonce.
    start = authenticate(228, b"\x01\x00" + nonce + q + a0 + be(1, 8)
                         + bytes(341))
    # ACTIVE round two at elapsed=60123 ms, grace=15000 ms, revision=7.
    # End=120000 ms; nominal/enforcement remaining=59877/74877 ms.
    started = authenticate(229, b"\x01\x03" + nonce + request_digest(start)
                           + q + a0 + be(2, 8) + be(60123, 8)
                           + be(59877, 4) + be(74877, 4) + be(0, 4)
                           + be(7, 8) + bytes(281))
    return [commit.hex(), committed.hex(), start.hex(), started.hex()]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve()
    parser.add_argument("--source", type=Path,
                        default=here.parents[3] / "eltord/spec/vectors/"
                        "payment_renewal_v1.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    vectors = initial_vectors(args.source)
    if args.check:
        code = here.with_name("test_payment_profile.c").read_text()
        section = code.split("static const char *initial_fixtures[] = {", 1)[1]
        section = section.split("};", 1)[0]
        embedded = ["".join(re.findall(r'"([0-9a-f]+)"', entry))
                    for entry in section.split(",") if entry.strip()]
        if vectors != embedded:
            raise SystemExit("initial-profile C fixtures differ from generator")
        print("Four initial-profile fixtures match the Python generator.")
    else:
        print("static const char *initial_fixtures[] = {")
        for vector in vectors:
            for start in range(0, len(vector), 70):
                suffix = "," if start + 70 >= len(vector) else ""
                print(f'    "{vector[start:start+70]}"{suffix}')
        print("};")


if __name__ == "__main__":
    main()
