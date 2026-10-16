"""
Pedersen Distributed Key Generation: n parties jointly create a shared
public/private key pair such that no single party ever learns the full
private key.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import secrets

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


def _eval_poly(coeffs, x, mod):
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % mod
    return result


def run_demo():
    print("== Pedersen distributed key generation (3-of-3 for simplicity) ==")
    n, t = 3, 3
    party_ids = list(range(1, n + 1))

    per_party_coeffs = {}
    per_party_commitments = {}
    per_party_shares_sent = {}
    for i in party_ids:
        coeffs = [secrets.randbelow(Q) for _ in range(t)]
        per_party_coeffs[i] = coeffs
        per_party_commitments[i] = [pow(G, c, P) for c in coeffs]
        per_party_shares_sent[i] = {
            j: _eval_poly(coeffs, j, Q) for j in party_ids
        }
    print(f"All {n} parties each contribute a random secret + Shamir-share it.")

    def verify(x, y, commitments):
        lhs = pow(G, y, P)
        rhs = 1
        for j, cj in enumerate(commitments):
            rhs = (rhs * pow(cj, pow(x, j), P)) % P
        return lhs == rhs

    all_ok = True
    for i in party_ids:
        for j in party_ids:
            share = per_party_shares_sent[j][i]
            ok = verify(i, share, per_party_commitments[j])
            all_ok &= ok
    print(f"Every party verifies every share it received: all valid = {all_ok}")

    final_shares = {}
    for i in party_ids:
        final_shares[i] = sum(
            per_party_shares_sent[j][i] for j in party_ids
        ) % Q

    group_pubkey = 1
    for i in party_ids:
        group_pubkey = (group_pubkey * per_party_commitments[i][0]) % P
    print(f"\nGroup public key derived from public commitments only "
          f"(no secret ever assembled in one place).")

    def lagrange_at_zero(points, prime):
        total = 0
        for j, (xj, yj) in enumerate(points):
            num, den = 1, 1
            for m, (xm, _) in enumerate(points):
                if m == j:
                    continue
                num = (num * -xm) % prime
                den = (den * (xj - xm)) % prime
            total = (total + yj * num * pow(den, -1, prime)) % prime
        return total

    implied_secret = lagrange_at_zero(
        [(i, final_shares[i]) for i in party_ids], Q
    )
    check = pow(G, implied_secret, P) == group_pubkey
    print(f"Consistency check (test-only): g^(implied secret) == "
          f"published group public key: {check}")


if __name__ == "__main__":
    run_demo()
