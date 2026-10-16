"""
ElGamal encryption: multiplicatively homomorphic.

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


def keygen():
    x = secrets.randbelow(Q - 1) + 1
    y = pow(G, x, P)
    return x, y


def encrypt(y, m: int):
    r = secrets.randbelow(Q - 1) + 1
    c1 = pow(G, r, P)
    c2 = (m * pow(y, r, P)) % P
    return c1, c2


def decrypt(x, ciphertext):
    c1, c2 = ciphertext
    s = pow(c1, x, P)
    return (c2 * pow(s, -1, P)) % P


def run_demo():
    print("== ElGamal multiplicatively homomorphic encryption ==")
    x, y = keygen()

    a, b = 6, 7
    ca, cb = encrypt(y, a), encrypt(y, b)
    print(f"Two encrypted values ca=Enc({a}), cb=Enc({b}) published")

    c_product = ((ca[0] * cb[0]) % P, (ca[1] * cb[1]) % P)
    print("\nAnyone computes the pointwise product of the two ciphertexts")
    print("(no decryption key needed)")

    result = decrypt(x, c_product)
    print(f"\nDecrypting the RESULT: {result}")
    print(f"Expected {a} * {b} = {a * b}   Match: {result == a * b}")

    print("\nNote: this scheme is multiplicative, not additive. Scaling a")
    print("ciphertext by a public constant k gives Enc(a*k), not Enc(a+k).")
    k = 5
    c_scaled = (ca[0], (ca[1] * k) % P)
    scaled_result = decrypt(x, c_scaled)
    print(f"Enc({a}) with c2 scaled by k={k} decrypts to: {scaled_result} "
          f"(expected {a*k})  Match: {scaled_result == a*k}")


if __name__ == "__main__":
    run_demo()
