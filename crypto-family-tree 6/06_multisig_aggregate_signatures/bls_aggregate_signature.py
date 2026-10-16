"""
BLS aggregate signatures over BLS12-381, via py_ecc's reference
implementation of the IETF "G2ProofOfPossession" ciphersuite.

Requires: pip install -r requirements.txt

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import os

from py_ecc.bls import G2ProofOfPossession as bls


def run_demo():
    print("== BLS aggregate signatures (BLS12-381) ==")

    names = ["Alice", "Bob", "Carol"]
    keys = {name: bls.KeyGen(os.urandom(32)) for name in names}
    pubkeys = {name: bls.SkToPk(sk) for name, sk in keys.items()}
    pops = {name: bls.PopProve(sk) for name, sk in keys.items()}

    for name in names:
        assert bls.PopVerify(pubkeys[name], pops[name]), "bad POP"
    print(f"All {len(names)} validators' proofs-of-possession verified "
          f"(defends against rogue-key attacks).")

    message = b"attest: block #874213 is valid"
    sigs = [bls.Sign(keys[name], message) for name in names]
    agg_sig = bls.Aggregate(sigs)
    print(f"\n{len(names)} signatures on the SAME message aggregated into "
          f"ONE constant-size signature.")

    ok = bls.FastAggregateVerify(list(pubkeys.values()), message, agg_sig)
    print(f"FastAggregateVerify (single pairing check for all signers): {ok}")

    messages = {
        "Alice": b"attest: block #874214 is valid",
        "Bob": b"attest: block #874215 is valid",
        "Carol": b"attest: block #874216 is valid",
    }
    sigs_diff = [bls.Sign(keys[name], messages[name]) for name in names]
    agg_sig_diff = bls.Aggregate(sigs_diff)
    print(f"\n{len(names)} signatures on DIFFERENT messages also "
          f"aggregate into ONE signature.")

    ok_diff = bls.AggregateVerify(
        list(pubkeys.values()), list(messages.values()), agg_sig_diff
    )
    print(f"AggregateVerify (one pairing check, different messages "
          f"per signer): {ok_diff}")

    tampered = list(messages.values())
    tampered[0] = b"attest: block #999999 is valid"
    bad = bls.AggregateVerify(list(pubkeys.values()), tampered, agg_sig_diff)
    print(f"\nAggregateVerify against a tampered message list: {bad}")


if __name__ == "__main__":
    run_demo()
