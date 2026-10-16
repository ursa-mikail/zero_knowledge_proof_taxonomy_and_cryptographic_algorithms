"""
Hash-based commitment: commit(v) = H(v || r) for random nonce r.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import hashlib
import secrets


def commit(value: bytes, nonce: bytes = None):
    nonce = nonce or secrets.token_bytes(32)
    digest = hashlib.sha256(value + nonce).digest()
    return digest, nonce


def verify(digest: bytes, value: bytes, nonce: bytes) -> bool:
    return hashlib.sha256(value + nonce).digest() == digest


def run_demo():
    print("== Hash-based commit-reveal ==")
    print("Sealed-bid auction: three bidders commit before revealing.\n")

    bids = {"Alice": b"1500", "Bob": b"1200", "Carol": b"1800"}
    commitments = {}
    nonces = {}
    for name, bid in bids.items():
        digest, nonce = commit(bid)
        commitments[name] = digest
        nonces[name] = nonce
        print(f"{name} publishes a commitment (bid amount hidden)")

    print("\n-- reveal phase: everyone submits (bid, nonce) --")
    revealed = {}
    for name, bid in bids.items():
        ok = verify(commitments[name], bid, nonces[name])
        revealed[name] = int(bid) if ok else None
        print(f"{name} reveals {bid.decode()} -- matches earlier "
              f"commitment: {ok}")

    winner = max(revealed, key=revealed.get)
    print(f"\nHighest valid bid wins: {winner} at {revealed[winner]}")

    print("\nCarol tries to claim she actually bid 2500 instead of 1800:")
    cheat_ok = verify(commitments["Carol"], b"2500", nonces["Carol"])
    print(f"Verification of the changed bid against her original "
          f"commitment: {cheat_ok}")


if __name__ == "__main__":
    run_demo()
