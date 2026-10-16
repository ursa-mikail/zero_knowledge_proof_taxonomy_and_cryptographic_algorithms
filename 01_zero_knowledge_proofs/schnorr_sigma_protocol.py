"""
Schnorr sigma protocol: interactive zero-knowledge proof of knowledge of a
discrete logarithm.

Prover knows x such that y = g^x mod p, and proves it without revealing x.

NOT FOR PRODUCTION USE. See README.md for caveats and a hand-checkable toy example.
"""
import secrets

# RFC 3526 Group 5 (1536-bit MODP) safe prime: p = 2q + 1, q prime.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC7"
    "4020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14"
    "374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B"
    "7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163"
    "BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208"
    "552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
G = 2


def keygen():
    x = secrets.randbelow(Q - 1) + 1
    y = pow(G, x, P)
    return x, y


def prover_commit():
    r = secrets.randbelow(Q - 1) + 1
    t = pow(G, r, P)
    return r, t


def prover_response(r, x, c):
    return (r + c * x) % Q


def verifier_check(y, t, c, s):
    lhs = pow(G, s, P)
    rhs = (t * pow(y, c, P)) % P
    return lhs == rhs


def run_demo():
    print("== Schnorr sigma protocol ==")
    x, y = keygen()
    print(f"Prover's secret x is {x.bit_length()} bits (not shown)")
    print(f"Public key y = g^x mod p published")

    r, t = prover_commit()
    print("\nStep 1 (prover -> verifier): commitment t")

    c = secrets.randbelow(Q)
    print("Step 2 (verifier -> prover): random challenge c")

    s = prover_response(r, x, c)
    print("Step 3 (prover -> verifier): response s")

    ok = verifier_check(y, t, c, s)
    print(f"\nVerifier accepts: {ok}")

    fake_s = secrets.randbelow(Q)
    print(f"Cheating prover guessing s at random -> accepted: "
          f"{verifier_check(y, t, c, fake_s)}")


if __name__ == "__main__":
    run_demo()
