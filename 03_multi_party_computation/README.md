# Multi-party computation (MPC)

Multiple parties jointly compute a function over their private inputs,
learning only the output — nothing about each other's inputs.

## Files

- `additive_secret_sharing_mpc_sum.py` — secure sum via additive shares (the
  "hello world" of secret-sharing-based MPC, in the style of SPDZ/BGW)
- `oblivious_transfer_1_of_2.py` — RSA-based 1-out-of-2 OT, the primitive
  garbled circuits and OT-extension protocols are built from
- `garbled_circuit_and_gate.py` — Yao's garbled circuit protocol, worked
  through on a single AND gate

---

## 1. Secure sum via additive secret sharing — step by step

**The idea in one sentence:** split each private number into random-looking
pieces that add up to it, hand out the pieces, and let addition (which
"passes through" the splitting) do the rest.

### Steps

1. **Fix a modulus** `p` larger than any possible sum (so nothing wraps
   around and corrupts the result).
2. **Each party additively shares its own value.** To share value `v_i`
   among `n` parties: pick `n-1` uniformly random numbers `r_1, ..., r_{n-1}`
   mod `p`, and set the last share to `r_n = v_i - (r_1 + ... + r_{n-1}) mod p`.
   By construction, `r_1 + ... + r_n = v_i mod p` — the shares sum back to
   the original value, but any `n-1` of them look completely random on
   their own (exactly the same information-theoretic hiding property as
   Shamir secret sharing, just with a simpler "sum" structure instead of a
   polynomial).
3. **Distribute:** party `i` sends one share of `v_i` to every other party
   (including one to itself).
4. **Each party locally sums the shares it received** — one share from
   every contributor.
5. **Publish and add the partial sums.** Because addition mod `p` is
   commutative and associative, summing everyone's partial sum gives back
   `Σ v_i mod p` exactly — the total — without any partial sum on its own
   revealing anything about a single `v_i`.

### Why this works (the algebra)

Let `share_i[j]` be the share party `i` sent to party `j`. Party `j`'s
partial sum is `Σ_i share_i[j]`. Summing partial sums over all `j`:

```
Σ_j Σ_i share_i[j]  =  Σ_i ( Σ_j share_i[j] )  =  Σ_i v_i
```

The inner sum `Σ_j share_i[j]` collapses back to `v_i` because that's
exactly how party `i` constructed its shares in step 2 — you're just
reordering the same sum, so nothing is lost and nothing extra leaks.

### Worked example (toy modulus p = 101, 2 parties)

Alice has `a = 5`, Bob has `b = 7`.

- Alice splits `a=5` into shares `(23, 83)` — note `23+83 = 106 mod 101 = 5` ✓
- Bob splits `b=7` into shares `(40, 68)` — note `40+68 = 108 mod 101 = 7` ✓
- Alice keeps her own first share (23) and Bob's first share (40); her
  partial sum: `23+40 = 63`.
- Bob keeps his own second share (68) and Alice's second share (83); his
  partial sum: `68+83 = 151 mod 101 = 50`.
- Combine partial sums: `63 + 50 = 113 mod 101 = 12` — matches `a+b = 12`. ✓

Neither Alice nor Bob ever saw a share that, by itself, revealed the other's
value — `23`, `83`, `40`, `68` are each consistent with *any* possible
original value once you don't know the matching share.

Run `additive_secret_sharing_mpc_sum.py` for a 3-party version with a real
127-bit prime.

---

## 2. 1-out-of-2 Oblivious Transfer — step by step

**The idea in one sentence:** the sender always sends back *two* masked
messages, but structures the masking (via RSA) so the receiver can only
peel off the mask for the ONE message it asked for — and the sender never
learns which one that was.

### Steps

1. **Sender generates an RSA keypair** `(n, e, d)` and publishes `(n, e)`.
2. **Sender also generates two random "index" values** `x0, x1 mod n` and
   sends them (with the public key) to the receiver.
3. **Receiver secretly decides which message it wants**, `b ∈ {0, 1}`, and
   picks a random blinding value `k`.
4. **Receiver blinds `k` using the index for its chosen bit:**
   `v = x_b + k^e mod n`, and sends `v` to the sender. Because `v` is a
   single number that could have come from either `x0 + (something)^e` or
   `x1 + (something)^e`, the sender cannot tell which index was used —
   that's exactly where `b` stays hidden.
5. **Sender, not knowing `b`, computes BOTH possibilities:**
   `k0 = (v - x0)^d mod n` and `k1 = (v - x1)^d mod n`. Only the one
   matching the receiver's real `b` will equal the receiver's actual `k`;
   the other comes out as an unrelated, meaningless number (an RSA
   decryption of essentially-random input).
6. **Sender masks both real messages** with the two candidate keys:
   `c0 = m0 + k0 mod n`, `c1 = m1 + k1 mod n`, and sends **both**, always.
7. **Receiver un-masks only the one it can:** it knows its own `k`, so it
   computes `m_b = c_b - k mod n`. It could try `c_{1-b} - k` too, but that
   subtracts the *wrong* key from the *wrong* ciphertext and produces
   garbage, not `m_{1-b}`.

### Why the sender never learns `b`

`v = x_b + k^e mod n` is (assuming RSA encryption of `k` looks like a
uniformly random group element, which is the standard RSA assumption) 
statistically indistinguishable whether `b=0` or `b=1` — from the sender's
perspective, `v` is just "some number," equally plausible under either
choice of `x0` or `x1` as the starting point.

### Why the receiver can't also learn `m_{1-b}`

Getting `m_{1-b}` correctly would require correctly computing
`k_{1-b} = (v - x_{1-b})^d mod n`. But the receiver doesn't know `d` (the
sender's private RSA exponent) — it only knows the one `k` that it itself
chose. Without `d`, it can't invert the other candidate.

### Worked example (toy RSA: p=7, q=11, n=77, e=7, d=43)

Sender's messages: `m0 = 5, m1 = 9`. Sender's random indices:
`x0 = 15, x1 = 50`.

1. Receiver wants `b = 1`, picks blinding `k = 6`.
2. `v = x1 + k^7 mod 77`. Computing `6^7 mod 77 = 41`, so
   `v = 50 + 41 = 91 mod 77 = 14`.
3. Sender computes both candidates:
   - `k0 = (14 - 15 mod 77)^43 mod 77 = 76^43 mod 77 = 76`
   - `k1 = (14 - 50 mod 77)^43 mod 77 = 41^43 mod 77 = 6`  ← matches the
     receiver's real `k=6`, because the receiver used `x1` when blinding.
4. Sender masks: `c0 = 5 + 76 mod 77 = 4`, `c1 = 9 + 6 mod 77 = 15`. Sends
   both `(4, 15)`.
5. Receiver computes `m1 = c1 - k mod 77 = 15 - 6 = 9` ✓ — correct!
6. If the receiver tries the other slot: `c0 - k = 4 - 6 mod 77 = 75` —
   nowhere near `m0 = 5`. Garbage, as expected.

Run `oblivious_transfer_1_of_2.py` for the same flow with real 512-bit RSA.

---

## 3. Garbled circuits (Yao's protocol) — step by step

**The idea in one sentence:** replace 0/1 wire values with random-looking
labels, encrypt each gate's truth table under combinations of input labels,
and let the evaluator decrypt exactly one row — the one matching the real
inputs — without ever seeing the actual 0/1 values.

### Setup, for one AND gate with inputs from Generator (wire A) and
Evaluator (wire B)

1. **Generator picks two random labels per wire:** `a0, a1` for wire A
   (meaning bit 0 / bit 1), `b0, b1` for wire B, and `out0, out1` for the
   output wire. These labels are just random byte strings — they carry no
   inherent meaning except "the label the generator privately associates
   with that bit value."
2. **Build the garbled truth table.** For every combination of input bits
   `(av, bv)`, encrypt the *correct output label* under the *pair of input
   labels* for that combination:
   `row(av, bv) = Enc(label_A[av], label_B[bv], out_label(AND(av, bv)))`.
   There are 4 rows (00, 01, 10, 11 for AND — three map to `out0`, one to
   `out1`).
3. **Shuffle the 4 rows** and send the shuffled table to the evaluator. The
   evaluator has no way to tell which row corresponds to which input
   combination — that mapping only existed before shuffling.

### The actual evaluation

4. **Generator sends its own input label directly** — the one matching its
   real bit, e.g. if the generator's bit is 1, it sends `a1`.
5. **Evaluator gets its own input label via Oblivious Transfer** (step 2
   above, plugged in as a subroutine): the evaluator picks the label
   matching its real bit without revealing which bit that is, and the
   generator never learns which label was transferred.
6. **Evaluator tries to decrypt every row** using its two labels (one from
   the generator, one from OT). Only the row that was actually encrypted
   under exactly those two labels will decrypt to something that looks like
   a valid output label; the other three decrypt to nonsense.
7. **Evaluator learns the output label**, and — if this is the final
   gate — the generator tells it which label corresponds to which bit (or a
   further garbled gate consumes the label as its own input, chaining
   gates together for a whole circuit).

### Why neither party learns the other's bit

The generator only ever sees an OT transcript that (by OT's own security
property) reveals nothing about which label the evaluator chose. The
evaluator only ever sees random-looking labels and an encrypted table it
can decrypt exactly once — it never sees the generator's *actual* bit, only
the *label* the generator associated with it, which is meaningless on its
own.

### Worked walkthrough (AND gate, generator bit=1, evaluator bit=0)

1. Generator has labels `a0, a1, b0, b1, out0, out1` (16-byte random
   strings — no small "toy" version makes sense here, since security comes
   entirely from the labels being unguessable).
2. Table has 4 encrypted rows, shuffled, sent to evaluator.
3. Generator's real bit is 1 → sends `a1` directly.
4. Evaluator's real bit is 0 → obtains `b0` via OT (generator doesn't know
   this happened).
5. Evaluator tries decrypting all 4 rows with `(a1, b0)`. Only the row that
   was encrypted as `Enc(a1, b0, out0)` (since `AND(1,0)=0`) decrypts to a
   value matching one of the two known output labels — specifically `out0`.
6. Output bit = 0, matching the true `AND(1, 0) = 0`.

Run `garbled_circuit_and_gate.py` to see this with real random 128-bit
labels and SHA-256-based encryption.

---

## When to use

- Multiple mutually distrustful parties need a joint computation (e.g.
  benchmarking salaries, matching private sets, joint fraud detection)
  without a trusted third party seeing raw inputs.
- As the substrate for threshold signing — the "compute the signature"
  circuit is run under MPC over secret-shared key material.

## When *not* to use

- A trusted third party is actually acceptable in your threat model —
  plain MPC is slower and more complex than "send it to a trusted server."
- You need a *proof* that a computation was done correctly for a third
  party to check later — that's ZK proofs / SNARKs, not MPC (MPC gives the
  *participants* correctness guarantees, not an externally verifiable proof).
- Round-trip latency matters a lot — garbled circuits and OT-extension
  protocols require multiple network round trips per computation.

## Caveats in this code

- All three demos are semi-honest (passive) secure: they protect against
  parties who follow the protocol but try to learn extra info from
  messages. None of them defend against a party who deviates from the
  protocol (malicious security needs added ZK proofs / cut-and-choose).
- The garbled circuit demo garbles exactly one AND gate to keep the labeling
  scheme visible; real garbled-circuit libraries chain thousands of gates
  and add free-XOR / point-and-permute optimizations omitted here.
- The OT demo uses textbook RSA blinding, which is malleable and not
  IND-CPA secure on its own — real systems use OT extension (IKNP) with a
  handful of base OTs plus a PRG, not raw RSA per transfer.

---

## Real-world examples

- **Additive secret-sharing MPC**: Google's Secure Aggregation protocol for
  federated learning (used in Gboard's on-device keyboard prediction
  training) has clients mask their model updates with pairwise random
  values that cancel out only when the server sums *all* of them — the
  same additive-masking idea as the secure-sum demo here, at production
  scale. The 2008 Danish Sugar Beet Auction is the frequently-cited first
  large-scale real-world MPC deployment, letting farmers and a sugar
  producer jointly compute market-clearing prices without revealing
  individual bids.
- **Oblivious transfer**: the core primitive underneath private set
  intersection (PSI) systems like Google's Password Checkup (checks your
  passwords against breach databases without either side learning the
  other's full data) and various private ad-conversion-measurement systems
  built on PSI (e.g. "Private Join and Compute"-style protocols).
- **Garbled circuits**: used in academic and commercial secure-computation
  toolkits (EMP-toolkit, ABY) for two-party computations where one side
  needs to evaluate a function of both parties' private data — e.g. secure
  benchmarking (a company compares its metrics against an industry average
  without disclosing raw numbers to a rival or platform operator).

## Decision guide: which one do I need?

- **Is the function you want to compute (mostly) additions/linear
  combinations across many parties' private numbers?**
  → Additive secret-sharing MPC — cheapest and simplest option.
- **Do exactly two parties need to compute something, and one holds a small
  set of candidate messages the other should pick exactly one of, without
  revealing which?**
  → Oblivious transfer, often as a subroutine of something bigger.
- **Do exactly two parties need to jointly evaluate an arbitrary (not just
  linear) function — comparisons, AND/OR logic, lookups?**
  → Garbled circuits (Yao's protocol) — general-purpose but requires
  building/compiling the function as a Boolean circuit first.
- **Do more than two parties need to evaluate an arbitrary function, with
  a dishonest-majority threat model?**
  → Neither demo here directly — look at SPDZ-family protocols (mentioned
  in this folder's "the math" section) or a production framework like
  MP-SPDZ.
