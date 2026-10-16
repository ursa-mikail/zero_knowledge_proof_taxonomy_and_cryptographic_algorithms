"""
Shamir's Secret Sharing: split a secret into n shares such that any t
reconstruct it, but t-1 reveal nothing.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import secrets

PRIME = 2**521 - 1


def _eval_poly(coeffs, x, mod):
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % mod
    return result


def split_secret(secret: int, n: int, t: int, prime: int = PRIME):
    assert 1 <= t <= n
    coeffs = [secret] + [secrets.randbelow(prime) for _ in range(t - 1)]
    shares = [(i, _eval_poly(coeffs, i, prime)) for i in range(1, n + 1)]
    return shares


def _lagrange_interpolate_at_zero(shares, prime):
    total = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * -xm) % prime
            den = (den * (xj - xm)) % prime
        total = (total + yj * num * pow(den, -1, prime)) % prime
    return total


def reconstruct(shares, prime: int = PRIME):
    return _lagrange_interpolate_at_zero(shares, prime)


def run_demo():
    print("== Shamir secret sharing ==")
    secret = 123456789012345
    n, t = 5, 3
    print(f"Secret: {secret}  |  n={n} shares, threshold t={t}")

    shares = split_secret(secret, n, t)
    print(f"Shares distributed to {n} parties: "
          f"{[s[0] for s in shares]} (values withheld)")

    subset = shares[:t]
    recovered = reconstruct(subset)
    print(f"\nReconstructing from shares {[s[0] for s in subset]}: "
          f"{recovered} (matches original: {recovered == secret})")

    other_subset = [shares[0], shares[2], shares[4]]
    recovered2 = reconstruct(other_subset)
    print(f"Reconstructing from shares {[s[0] for s in other_subset]}: "
          f"{recovered2} (matches original: {recovered2 == secret})")

    too_few = shares[: t - 1]
    wrong = reconstruct(too_few)
    print(f"\nReconstructing from only {t-1} shares (below threshold): "
          f"{wrong}\n(garbage -- with t-1 shares every secret is equally "
          f"consistent with the data)")


if __name__ == "__main__":
    run_demo()
