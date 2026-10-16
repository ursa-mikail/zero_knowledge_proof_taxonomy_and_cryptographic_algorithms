"""
Naive n-of-n multisig: n independent Schnorr signatures, all required, all
individually visible and individually verified.

NOT FOR PRODUCTION USE. See README.md for caveats.
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


def hash_challenge(*ints) -> int:
    h = hashlib.sha256()
    for i in ints:
        h.update(i.to_bytes((i.bit_length() + 7) // 8 or 1, "big"))
    return int.from_bytes(h.digest(), "big") % Q


def sign(x, y, message: bytes):
    r = secrets.randbelow(Q - 1) + 1
    t = pow(G, r, P)
    c = hash_challenge(y, t, int.from_bytes(hashlib.sha256(message).digest(), "big"))
    s = (r + c * x) % Q
    return t, s


def verify(y, message: bytes, sig):
    t, s = sig
    c = hash_challenge(y, t, int.from_bytes(hashlib.sha256(message).digest(), "big"))
    return pow(G, s, P) == (t * pow(y, c, P)) % P


def run_demo():
    print("== Naive n-of-n multisig (3 independent signatures required) ==")
    signers = {name: keygen() for name in ("Alice", "Bob", "Carol")}
    message = b"approve payroll run #42"

    print(f"Policy: ALL {len(signers)} of {[n for n in signers]} must sign.")
    print(f"On-chain footprint: {len(signers)} full (pubkey, sig) pairs "
          f"-- visibly a multisig, size grows with signer count.\n")

    sigs = {}
    for name, (x, y) in signers.items():
        sigs[name] = sign(x, y, message)

    all_valid = True
    for name, (x, y) in signers.items():
        ok = verify(y, message, sigs[name])
        print(f"Verifying {name}'s signature independently: {ok}")
        all_valid &= ok

    print(f"\nTransaction accepted (all {len(signers)} required sigs valid): "
          f"{all_valid}")

    del sigs["Carol"]
    print(f"\nIf Carol's signature is missing, transaction is rejected "
          f"under an n-of-n policy (only {len(sigs)}/{len(signers)} present).")


if __name__ == "__main__":
    run_demo()
