"""
MuSig-style Schnorr key & signature aggregation: n signers produce ONE
signature, verified against ONE aggregate public key.

Simplified for clarity -- see README.md for what's omitted.
NOT FOR PRODUCTION USE.
"""
import hashlib
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
    return x, pow(G, x, P)


def h_int(*ints) -> int:
    hasher = hashlib.sha256()
    for i in ints:
        hasher.update(i.to_bytes((i.bit_length() + 7) // 8 or 1, "big"))
    return int.from_bytes(hasher.digest(), "big") % Q


def run_demo():
    print("== MuSig-style Schnorr aggregation (3 signers -> 1 signature) ==")
    signers = {name: keygen() for name in ("Alice", "Bob", "Carol")}
    pubkeys = [y for _, y in signers.values()]
    message = b"approve payroll run #42"

    L = h_int(*pubkeys)
    coeffs = {name: h_int(L, y) for name, (_, y) in signers.items()}

    Y = 1
    for name, (_, y) in signers.items():
        Y = (Y * pow(y, coeffs[name], P)) % P
    print(f"Aggregate public key Y computed from all 3 individual pubkeys "
          f"(published once, looks like a normal single key)")

    nonces = {name: secrets.randbelow(Q - 1) + 1 for name in signers}
    R_i = {name: pow(G, r, P) for name, r in nonces.items()}
    R = 1
    for r_pub in R_i.values():
        R = (R * r_pub) % P

    c = h_int(R, Y, int.from_bytes(hashlib.sha256(message).digest(), "big"))

    partial = {}
    for name, (x, _) in signers.items():
        a_i = coeffs[name]
        partial[name] = (nonces[name] + c * a_i * x) % Q

    s = sum(partial.values()) % Q
    print("All partial signatures combined into ONE (R, s) pair.")

    ok = pow(G, s, P) == (R * pow(Y, c, P)) % P
    print(f"\nVerifier (using the SAME check as single-signer Schnorr) "
          f"accepts: {ok}")
    print("On-chain footprint: identical to a single signer's signature,")
    print("regardless of how many of Alice/Bob/Carol were actually involved.")


if __name__ == "__main__":
    run_demo()
