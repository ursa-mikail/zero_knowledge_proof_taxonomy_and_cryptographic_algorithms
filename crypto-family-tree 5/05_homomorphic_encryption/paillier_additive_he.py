"""
Paillier cryptosystem: additively homomorphic public-key encryption.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import secrets
import math


def _is_probable_prime(n: int, rounds: int = 20) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(c):
            return c


def _lcm(a, b):
    return a * b // math.gcd(a, b)


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def keygen(bits=256):
    p, q = _random_prime(bits // 2), _random_prime(bits // 2)
    n = p * q
    g = n + 1
    lam = _lcm(p - 1, q - 1)
    mu = pow(lam, -1, n)
    return (n, g), (lam, mu, n)


def encrypt(pub, m: int) -> int:
    n, g = pub
    r = secrets.randbelow(n - 1) + 1
    while _gcd(r, n) != 1:
        r = secrets.randbelow(n - 1) + 1
    return (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)


def decrypt(priv, c: int) -> int:
    lam, mu, n = priv
    n2 = n * n
    x = pow(c, lam, n2)
    l_val = (x - 1) // n
    return (l_val * mu) % n


def run_demo():
    print("== Paillier additively homomorphic encryption ==")
    pub, priv = keygen()

    a, b = 15, 27
    ca, cb = encrypt(pub, a), encrypt(pub, b)
    print(f"Two encrypted values ca=Enc({a}), cb=Enc({b}) published "
          f"(ciphertexts reveal nothing about a, b)")

    n = pub[0]
    c_sum = (ca * cb) % (n * n)
    print("\nAnyone (no decryption key needed) computes ca * cb mod n^2")

    result = decrypt(priv, c_sum)
    print(f"Decrypting the RESULT (not the inputs): {result}")
    print(f"Expected {a} + {b} = {a + b}   Match: {result == a + b}")

    k = 3
    c_scaled = pow(ca, k, n * n)
    scaled_result = decrypt(priv, c_scaled)
    print(f"\nEnc({a})^{k} decrypts to: {scaled_result} "
          f"(expected {a}*{k}={a*k})  Match: {scaled_result == a*k}")


if __name__ == "__main__":
    run_demo()
