"""
Feldman Verifiable Secret Sharing: Shamir sharing plus public commitments to
the polynomial's coefficients, so each shareholder can verify their share is
consistent WITHOUT trusting the dealer.

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


def dealer_share(secret: int, n: int, t: int):
    coeffs = [secret] + [secrets.randbelow(Q) for _ in range(t - 1)]
    shares = [(i, _eval_poly(coeffs, i, Q)) for i in range(1, n + 1)]
    commitments = [pow(G, a, P) for a in coeffs]
    return shares, commitments


def verify_share(x: int, y: int, commitments: list[int]) -> bool:
    lhs = pow(G, y, P)
    rhs = 1
    for j, cj in enumerate(commitments):
        rhs = (rhs * pow(cj, pow(x, j), P)) % P
    return lhs == rhs


def run_demo():
    print("== Feldman verifiable secret sharing ==")
    secret = 999999
    n, t = 5, 3

    shares, commitments = dealer_share(secret, n, t)
    print(f"Dealer publishes {t} commitments (one per polynomial coefficient)")

    print("\nEach party independently verifies its own share:")
    for x, y in shares:
        ok = verify_share(x, y, commitments)
        print(f"  party {x}: share consistent with public commitments? {ok}")

    print("\nNow simulate a dishonest dealer sending party 3 a bad share:")
    bad_shares = list(shares)
    x, y = bad_shares[2]
    bad_shares[2] = (x, (y + 1) % Q)
    x, y = bad_shares[2]
    ok = verify_share(x, y, commitments)
    print(f"  party 3 checks its share against the SAME public commitments "
          f"-> consistent? {ok}")
    print("  (party 3 catches the cheating dealer without trusting anyone)")


if __name__ == "__main__":
    run_demo()
