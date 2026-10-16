"""
Merkle tree: commit to an ordered list of values with one root hash, and
prove membership of any single element in O(log n) hashes.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import hashlib


def h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def build_tree(leaves: list[bytes]) -> list[list[bytes]]:
    level = [h(leaf) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level = level + [level[-1]]
        next_level = [h(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(next_level)
        level = next_level
    return levels


def merkle_root(leaves: list[bytes]) -> bytes:
    return build_tree(leaves)[-1][0]


def merkle_proof(levels: list[list[bytes]], index: int) -> list[tuple[bytes, str]]:
    proof = []
    idx = index
    for level in levels[:-1]:
        level = level if len(level) % 2 == 0 else level + [level[-1]]
        sibling_idx = idx ^ 1
        side = "L" if sibling_idx < idx else "R"
        proof.append((level[sibling_idx], side))
        idx //= 2
    return proof


def verify_proof(leaf: bytes, proof: list[tuple[bytes, str]], root: bytes) -> bool:
    current = h(leaf)
    for sibling, side in proof:
        current = h(sibling + current) if side == "L" else h(current + sibling)
    return current == root


def run_demo():
    print("== Merkle tree commitment ==")
    transactions = [
        b"tx: Alice pays Bob 5",
        b"tx: Bob pays Carol 3",
        b"tx: Carol pays Dave 1",
        b"tx: Dave pays Alice 2",
        b"tx: Alice pays Carol 4",
    ]
    levels = build_tree(transactions)
    root = levels[-1][0]
    print(f"Committed to {len(transactions)} transactions with one root "
          f"hash (publishable on-chain, in a block header, etc.)")

    idx = 2
    proof = merkle_proof(levels, idx)
    print(f"\nProving transaction #{idx} is in the committed set: "
          f"{len(proof)} sibling hashes needed "
          f"(O(log n) instead of revealing all {len(transactions)})")

    ok = verify_proof(transactions[idx], proof, root)
    print(f"Verifier (who only has the root + this proof) confirms "
          f"membership: {ok}")

    fake_tx = b"tx: Dave pays Alice 999999"
    bad = verify_proof(fake_tx, proof, root)
    print(f"\nSame proof path but a forged transaction content -> "
          f"verifies: {bad}")


if __name__ == "__main__":
    run_demo()
