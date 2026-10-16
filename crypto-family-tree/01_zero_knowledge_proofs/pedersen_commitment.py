"""
Pedersen commitment: commit(v, r) = g^v * h^r mod p. Perfectly hiding,
computationally binding. Used inside SNARKs, Bulletproofs, Feldman VSS.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import secrets

from schnorr_sigma_protocol import P, Q, G

H = pow(G, 2, P)  # toy-only: real systems must NOT know log_G(H)


def commit(v: int, r: int) -> int:
    return (pow(G, v, P) * pow(H, r, P)) % P


def run_demo():
    print("== Pedersen commitment ==")
    v = 42
    r = secrets.randbelow(Q)

    c = commit(v, r)
    print(f"Committer publishes commitment c (reveals nothing about v={v})")

    recomputed = commit(v, r)
    print(f"Verifier recomputes commit(v, r) and checks it matches c: "
          f"{recomputed == c}")

    v_prime, r_prime = 43, secrets.randbelow(Q)
    print(f"Trying to open the same c as a different value v'={v_prime}: "
          f"{commit(v_prime, r_prime) == c}")

    c_a = commit(0, secrets.randbelow(Q))
    c_b = commit(1, secrets.randbelow(Q))
    print("Two commitments to 0 and 1 look like random group elements:")
    print(f"  c(0) = {c_a}")
    print(f"  c(1) = {c_b}")


if __name__ == "__main__":
    run_demo()
