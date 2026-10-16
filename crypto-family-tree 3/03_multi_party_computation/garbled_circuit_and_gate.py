"""
Yao's garbled circuit protocol, walked through on a single AND gate.

NOT FOR PRODUCTION USE. See README.md for caveats.
"""
import hashlib
import secrets


def label(nbytes=16) -> bytes:
    return secrets.token_bytes(nbytes)


def enc(key_a: bytes, key_b: bytes, plaintext: bytes) -> bytes:
    pad = hashlib.sha256(key_a + key_b).digest()[: len(plaintext)]
    return bytes(p ^ q for p, q in zip(pad, plaintext))


def dec(key_a: bytes, key_b: bytes, ciphertext: bytes) -> bytes:
    return enc(key_a, key_b, ciphertext)


def run_demo():
    print("== Garbled AND gate (Yao's protocol) ==")

    a0, a1 = label(), label()
    b0, b1 = label(), label()
    out0, out1 = label(), label()

    truth_table = {
        (0, 0): out0, (0, 1): out0,
        (1, 0): out0, (1, 1): out1,
    }
    wire_label = {0: {0: a0, 1: b0}, 1: {0: a1, 1: b1}}

    garbled_rows = []
    for (av, bv), out_label in truth_table.items():
        ka = wire_label[0][av]
        kb = wire_label[1][bv]
        garbled_rows.append(enc(ka, kb, out_label))
    secrets.SystemRandom().shuffle(garbled_rows)
    print("Generator ships a shuffled table of 4 encrypted rows -- the")
    print("evaluator cannot tell which row corresponds to which input pair.")

    generator_bit = 1
    evaluator_bit = 0
    print(f"\nGenerator's private bit: (not revealed)  "
          f"Evaluator's private bit: (not revealed)")

    my_label = a1 if generator_bit == 1 else a0
    their_label = b1 if evaluator_bit == 1 else b0
    print("Evaluator gets its own input label via oblivious transfer;")
    print("generator does not learn which one was picked.")

    result_label = None
    for row in garbled_rows:
        candidate = dec(my_label, their_label, row)
        if candidate in (out0, out1):
            result_label = candidate
            break

    output_bit = 1 if result_label == out1 else 0
    print(f"\nEvaluator decrypts exactly one row and learns the OUTPUT "
          f"label only.")
    print(f"Recovered output bit: {output_bit}  "
          f"(expected AND({generator_bit}, {evaluator_bit}) = "
          f"{generator_bit & evaluator_bit})")
    print(f"Match: {output_bit == (generator_bit & evaluator_bit)}")
    print("\nNeither party ever saw the other's raw input bit --")
    print("only wire labels, which look like random bytes.")


if __name__ == "__main__":
    run_demo()
