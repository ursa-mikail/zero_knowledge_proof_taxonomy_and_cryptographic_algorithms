"""
1-out-of-2 Oblivious Transfer (textbook RSA-blinding version).

Sender holds two messages m0, m1. Receiver picks a bit b and learns m_b --
the sender never learns b, and the receiver learns nothing about m_(1-b).

NOT FOR PRODUCTION USE. See README.md for caveats -- real systems use OT
extension (IKNP), not raw RSA blinding.
"""
import secrets


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
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def keygen(bits=512):
    p = _random_prime(bits // 2)
    q = _random_prime(bits // 2)
    n = p * q
    e = 65537
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    return (n, e), d


def run_demo():
    print("== 1-out-of-2 oblivious transfer ==")
    (n, e), d = keygen()
    m0, m1 = 1111, 2222
    print(f"Sender has two secret messages, e.g. m0={m0}, m1={m1}")

    x0, x1 = secrets.randbelow(n), secrets.randbelow(n)

    b = 1
    print(f"Receiver secretly wants message index b={b} (sender never learns this)")

    k = secrets.randbelow(n)
    x_b = x0 if b == 0 else x1
    v = (x_b + pow(k, e, n)) % n

    k0 = pow((v - x0) % n, d, n)
    k1 = pow((v - x1) % n, d, n)

    c0 = (m0 + k0) % n
    c1 = (m1 + k1) % n
    print("Sender sends back two masked messages c0, c1 (both, always)")

    recovered = (c1 - k) % n if b == 1 else (c0 - k) % n
    print(f"\nReceiver recovers message: {recovered} "
          f"(expected m{b}={m1 if b == 1 else m0})")
    print(f"Match: {recovered == (m1 if b == 1 else m0)}")

    other = (c0 - k) % n if b == 1 else (c1 - k) % n
    print(f"Receiver's attempt to also decode the OTHER message gives "
          f"garbage: {other}")


if __name__ == "__main__":
    run_demo()
