"""
Secure sum via additive secret sharing: N parties each hold a private value
and learn only the total sum, nothing about each other's individual values.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import secrets

PRIME = 2**127 - 1


def additive_share(value: int, n_parties: int, mod: int = PRIME):
    shares = [secrets.randbelow(mod) for _ in range(n_parties - 1)]
    last = (value - sum(shares)) % mod
    shares.append(last)
    return shares


def run_demo():
    print("== Secure sum via additive secret sharing ==")
    parties_private_values = {"Alice": 71000, "Bob": 95000, "Carol": 63000}
    names = list(parties_private_values)
    n = len(names)

    shares_matrix = {
        owner: additive_share(v, n) for owner, v in parties_private_values.items()
    }
    print("Each party secret-shares its private salary among all parties.")
    print("No single message reveals anything about the salary it came from.")

    received_sums = {}
    for i, recipient in enumerate(names):
        received_sums[recipient] = sum(
            shares_matrix[owner][i] for owner in names
        ) % PRIME

    total = sum(received_sums.values()) % PRIME
    print(f"\nPartial sums published by each party: "
          f"{ {k: '...' for k in received_sums} }")
    print(f"Reconstructed total: {total}")
    print(f"Actual total:        {sum(parties_private_values.values())}")
    print(f"Match: {total == sum(parties_private_values.values())}")

    print("\nWhat leaked: only the total. Alice never learns Bob's or")
    print("Carol's individual salary, only that all three sum to the total.")


if __name__ == "__main__":
    run_demo()
