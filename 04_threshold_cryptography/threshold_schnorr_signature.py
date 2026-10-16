"""
Threshold Schnorr signing: t-of-n parties, each holding a Shamir share of a
group private key, jointly produce a single Schnorr signature valid under
the group's public key. This is the core idea behind FROST.

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


def _eval_poly(coeffs, x, mod):
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % mod
    return result


def lagrange_coeff(i, participant_ids, prime):
    num, den = 1, 1
    for j in participant_ids:
        if j == i:
            continue
        num = (num * -j) % prime
        den = (den * (i - j)) % prime
    return (num * pow(den, -1, prime)) % prime


def hash_challenge(*ints) -> int:
    h = hashlib.sha256()
    for i in ints:
        h.update(i.to_bytes((i.bit_length() + 7) // 8 or 1, "big"))
    return int.from_bytes(h.digest(), "big") % Q


def run_demo():
    print("== Threshold Schnorr signature (2-of-3) ==")
    n, t = 3, 2

    secret_key = secrets.randbelow(Q)
    coeffs = [secret_key] + [secrets.randbelow(Q) for _ in range(t - 1)]
    all_ids = [1, 2, 3]
    shares = {i: _eval_poly(coeffs, i, Q) for i in all_ids}
    group_pubkey = pow(G, secret_key, P)
    print(f"Group public key published; secret key never exists in one "
          f"place after setup.")

    signers = [1, 3]
    message = b"transfer 10 BTC to bc1qxyz..."
    print(f"\nSigners for this message: parties {signers} (any {t} of "
          f"{n} would work)")

    nonces = {i: secrets.randbelow(Q) for i in signers}
    commitments = {i: pow(G, r, P) for i, r in nonces.items()}
    R = 1
    for c in commitments.values():
        R = (R * c) % P

    c = hash_challenge(R, group_pubkey, int.from_bytes(
        hashlib.sha256(message).digest(), "big"))

    partial_sigs = {}
    for i in signers:
        lam = lagrange_coeff(i, signers, Q)
        partial_sigs[i] = (nonces[i] + c * lam * shares[i]) % Q

    s = sum(partial_sigs.values()) % Q
    print("Signers combine partial signatures into one aggregate signature "
          "(R, s).")

    ok = pow(G, s, P) == (R * pow(group_pubkey, c, P)) % P
    print(f"\nStandard Schnorr verifier accepts (R, s) against group pubkey: {ok}")
    print("(Verifier cannot tell this was produced by 2 of 3 parties instead")
    print(" of a single key holder -- same verification equation either way.)")


if __name__ == "__main__":
    run_demo()
