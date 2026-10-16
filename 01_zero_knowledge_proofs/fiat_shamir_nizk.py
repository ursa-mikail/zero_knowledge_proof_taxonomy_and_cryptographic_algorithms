"""
Fiat-Shamir transform: turns the interactive Schnorr proof into a
non-interactive one (NIZK) by deriving the challenge from a hash of the
transcript instead of asking a live verifier.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import hashlib
import secrets

from schnorr_sigma_protocol import P, Q, G, keygen


def hash_challenge(*ints) -> int:
    h = hashlib.sha256()
    for i in ints:
        h.update(i.to_bytes((i.bit_length() + 7) // 8 or 1, "big"))
    return int.from_bytes(h.digest(), "big") % Q


def prove(x, y):
    r = secrets.randbelow(Q - 1) + 1
    t = pow(G, r, P)
    c = hash_challenge(G, y, t)
    s = (r + c * x) % Q
    return t, s


def verify(y, t, s):
    c = hash_challenge(G, y, t)
    return pow(G, s, P) == (t * pow(y, c, P)) % P


def run_demo():
    print("== Fiat-Shamir non-interactive proof of knowledge ==")
    x, y = keygen()

    proof = prove(x, y)
    print(f"Proof is just two numbers: (t, s) -- no interaction needed")

    ok = verify(y, *proof)
    print(f"Verifier (offline, no prover contact) accepts: {ok}")

    t, s = proof
    tampered_ok = verify(y, t, (s + 1) % Q)
    print(f"Verifier accepts a tampered proof: {tampered_ok}")


if __name__ == "__main__":
    run_demo()
