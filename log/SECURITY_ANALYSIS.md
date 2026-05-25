# Security Analysis of Re-LWE Hash v2 (Recursive Chaotic Error LWE Hash)

## 1. Design Overview & Novelty

Re-LWE Hash v2 is an experimental hash construction inspired by Module-LWE arithmetic and ARX-style diffusion. It operates over the custom quotient ring:

```text
R = Z_3329[x] / (x^256 + x^128 + 1)
```

with default parameters:

```text
n = 256
q = 3329
k = 3
rounds = 48
output_bits = 256
```

The implementation absorbs the message with SHA3/SHAKE-based domain separation, expands it into a module state of `k` ring polynomials, and then applies multiple rounds of Module-LWE-like mixing. Each round uses:

- A round matrix over the ring.
- Matrix-vector polynomial multiplication.
- A recursive error vector.
- Feedback from the previous state and previous error.
- ARX operations for deterministic error evolution.
- A final SHA3-256 or SHA3-512 squeeze.

The distinctive feature is the recursive chaotic error mechanism:

```text
e_i = ARX(e_{i-1}, s + salt_i, b_{i-1})
```

where `salt_i` depends on the round number, seed, previous state, and previous error. The seed also evolves every round. This gives the construction a feedback-driven structure: the error is not sampled independently per round, but deterministically evolves from prior internal state.

This is novel as a puzzle/educational design, but novelty should not be confused with cryptographic assurance. The construction has not undergone formal analysis, standardization, third-party review, or reductionist proof.

## 2. Security Goals

The construction appears to aim for the following properties:

- **Preimage resistance:** Given a digest, finding a message with that digest should be computationally infeasible.
- **Second-preimage resistance:** Given a message, finding another message with the same digest should be infeasible.
- **Collision resistance:** Finding any two messages with the same full digest should require birthday-level work.
- **Avalanche behavior:** A 1-bit input change should affect approximately half of the output bits.
- **Differential resistance:** Small structured input differences should not produce biased, low-weight, or predictable output differences.
- **Linear resistance:** Simple input/output parity relations should not exhibit measurable bias.
- **Deterministic chaos:** The recursive error mechanism should amplify small differences while remaining fully deterministic.

The practical implementation also tries to preserve:

- Configurability of module rank, rounds, and output size.
- Efficient polynomial multiplication through NTT-style acceleration.
- File hashing and CLI usability.

These goals are reasonable for an experimental hash, but they are not yet achieved in a formally defensible sense. Current evidence is empirical only.

## 3. Avalanche Analysis

The latest local statistical avalanche test was run with:

```text
attack: stat-avalanche
rounds: 48
k: 3
output_bits: 256
trials: 5000
tracked input bits: 256
threads: 16
```

Command:

```bash
GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack --attacks stat-avalanche --stat-avalanche-trials 5000 --stat-avalanche-rounds 48 --stat-input-bits 256 --threads 16
```

Observed Hamming-distance statistics for 1-bit input flips:

```text
mean: 127.936 bits (49.975%)
stddev: 8.033 bits
min: 99 bits
max: 160 bits
45~55% range: 115..140 changed bits
45~55% ratio: 89.72%
Avalanche quality: Good
elapsed: 41.527s
```

For a 256-bit ideal random output difference, the expected mean is 128 changed bits and the expected standard deviation is approximately:

```text
sqrt(256 * 0.5 * 0.5) = 8
```

The measured mean and standard deviation are very close to this ideal model.

Output bit flip probabilities were also measured:

```text
output flip probability range: 0.4784..0.5190
mean absolute bias from 0.5: 0.0056
max absolute bias from 0.5: 0.0216
```

Worst observed output-bit deviations:

```text
out_bit=144 flip_prob=0.4784 bias=-0.0216
out_bit=205 flip_prob=0.5190 bias=+0.0190
out_bit=  5 flip_prob=0.5188 bias=+0.0188
out_bit=180 flip_prob=0.5186 bias=+0.0186
out_bit=250 flip_prob=0.4824 bias=-0.0176
out_bit= 58 flip_prob=0.4824 bias=-0.0176
out_bit=107 flip_prob=0.5176 bias=+0.0176
out_bit=222 flip_prob=0.4826 bias=-0.0174
```

This is a good empirical result for a 5,000-sample test. No output bit showed an extreme global flip-rate bias.

The input/output conditional dependence test reported the strongest observed conditional deviations:

```text
in_bit=222 out_bit=156 n=24 prob=0.0833 z=4.08
in_bit= 68 out_bit= 98 n=24 prob=0.9167 z=4.08
in_bit=  0 out_bit=136 n=26 prob=0.8846 z=3.92
in_bit=175 out_bit=201 n=19 prob=0.0526 z=3.90
```

These conditional samples are thin because 5,000 trials are spread across 256 tracked input bit positions. Each input bit receives only about 19-26 observations. Therefore, the largest conditional deviations should be treated as candidates for follow-up testing, not as confirmed weaknesses.

Summary:

- The overall avalanche behavior is strong in this sample.
- Output-bit independence looks reasonable.
- Conditional input/output bit statistics need larger targeted trials before drawing conclusions.

## 4. Differential & Linear Cryptanalysis Resistance

### Differential Testing

The latest local differential test used:

```text
rounds: 1..12
flip counts: 1, 2, 4, 8
trials per round/flip count: 16
characteristic searches per round/flip count: 8
message length: 32 bytes
threads: 16
```

Command:

```bash
GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack --attacks differential --differential-rounds 12 --differential-trials 16 --differential-flips 1,2,4,8 --differential-searches 8 --message-len 32 --threads 16
```

Observed mean output differences stayed near 50% across tested rounds and flip counts. Representative rows:

```text
round 1, flips 1: mean 129.88 bits (50.73%)
round 1, flips 8: mean 124.50 bits (48.63%)
round 6, flips 2: mean 131.19 bits (51.25%)
round 8, flips 8: mean 125.81 bits (49.15%)
round 12, flips 1: mean 122.88 bits (48.00%)
round 12, flips 8: mean 130.19 bits (50.85%)
```

The characteristic search tested 384 candidate fixed input-difference patterns. The best low-weight candidates still had mean output differences close to half the digest:

```text
rounds=1  flips=1 best_mean=123.19 bits
rounds=5  flips=1 best_mean=123.06 bits
rounds=6  flips=2 best_mean=123.00 bits
rounds=12 flips=1 best_mean=124.81 bits
```

No tested characteristic produced a clearly exploitable low-weight output difference. However, this is a shallow search:

- Only 1..12 rounds were tested.
- Only 384 fixed characteristics were searched.
- Only 16 trials per characteristic were used.
- The full default hash uses 48 rounds.

The current result supports "no obvious differential weakness found in this limited test," not "differential security proven."

### Linear Approximation Testing

The latest local linear approximation test used:

```text
rounds: 48
k: 3
trials: 5000
masks: 64
message_bits: 512
output_bits: 256
```

Command:

```bash
GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack --attacks linear --linear-rounds 48 --linear-trials 5000 --linear-masks 64 --linear-message-len 64 --threads 16
```

Observed result:

```text
mean absolute linear bias: 0.00479
max absolute linear bias: 0.01460 (2.06 sigma)
```

Top observed approximation:

```text
prob=0.48540
bias=-0.01460
input=[173]
output=[43,47,174,199]
```

A 2.06-sigma maximum over 64 random masks is not alarming. It is consistent with ordinary sampling noise. No strong linear approximation was found in this limited test.

Limitations:

- Only random low-weight masks were tested.
- Mask search was not adaptive.
- Higher-order linear, algebraic, rotational, and structural distinguishers were not tested.
- The final SHA3 squeeze may hide internal linear structure from this black-box test.

## 5. Birthday & Collision Resistance

The full digest is 256 bits by default. For an ideal 256-bit hash, generic collision resistance is about 2^128 work. No full collision was found or expected in local testing.

A truncated birthday test was run with:

```text
rounds: 48
k: 3
output_bits: 256
prefix_bits: 24
attempts: 10000
threads: 16
```

Command:

```bash
GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack --attacks birthday --birthday-rounds 48 --birthday-attempts 10000 --prefix-bits 24 --threads 16
```

Observed result:

```text
Found 24-bit truncated collision after 4459 messages.
prefix: 044334
```

Digests:

```text
digest A: 044334ca803c086decc3b7333c7479c80aae3e63359b2ac2c59a25863221c068
digest B: 0443340825c092b59f3a5d8555b69e43be49cf8aab7ed555357f3b1f8b2a5da8
```

This is not a break. A 24-bit prefix collision is expected after roughly:

```text
sqrt(pi/2 * 2^24) ~= 5134 attempts
```

The observed collision after 4,459 messages is consistent with the birthday bound.

Important distinction:

- A 24-bit prefix collision is expected and only validates the test harness.
- A full 256-bit collision would be a serious break.
- No full digest collision has been observed.

For a 512-bit output configuration, generic collision resistance would nominally rise to about 2^256 work, assuming the construction behaves like a random oracle after squeezing. That assumption is unproven.

## 6. Known Limitations & Potential Weaknesses

The design has significant limitations:

### No Formal Security Proof

Despite using Module-LWE-like arithmetic, this is not a reduction from Module-LWE hardness. The security of the hash does not follow from Kyber, ML-KEM, Ring-LWE, or Module-LWE assumptions.

Reasons:

- LWE hardness concerns distinguishing/search problems with specific sampling distributions.
- This hash uses deterministic message-derived state and recursive error.
- The adversary controls the input message and therefore influences the seed.
- The final digest is produced through a custom permutation-like process plus SHA3 squeezing.

### Custom Ring

The ring is:

```text
Z_3329[x] / (x^256 + x^128 + 1)
```

This is not Kyber's standard negacyclic ring:

```text
Z_3329[x] / (x^256 + 1)
```

The custom modulus polynomial may have algebraic structure that has not been analyzed. The current implementation may be correct as arithmetic, but correctness is not equivalent to cryptographic suitability.

### Recursive Error May Introduce Structure

The recursive error is intended to improve diffusion, but deterministic feedback can also create hidden correlations. The ARX update is custom and not derived from a vetted block cipher, permutation, or sponge construction.

Potential risks:

- State cycles for some seeds.
- Input-controlled low-dimensional subspaces.
- Round-to-round correlation in error evolution.
- Structural distinguishers not visible in simple avalanche tests.

### SHA3 Absorb and Squeeze Complicate Interpretation

The design uses SHA3/SHAKE in the absorption, expansion, feedback, and final squeeze path. This is useful for domain separation and diffusion, but it makes the construction less independently meaningful as a hash candidate.

If SHA3 is already used heavily, the security may be dominated by SHA3 rather than the Re-LWE core. Conversely, if the custom core has a flaw, SHA3 at the end may hide it in black-box tests without eliminating all possible structural issues.

### Parameter Sensitivity

The test results apply to the tested defaults:

```text
k = 3
rounds = 48
output_bits = 256
```

Reduced-round or altered-parameter variants should be considered weaker until separately tested.

### Limited Test Coverage

Current tests include:

- Avalanche statistics.
- Output bit flip probability.
- Conditional input/output bit flip measurements.
- Random low-weight differential search.
- Random linear approximation tests.
- Truncated birthday tests.

They do not include:

- Formal indifferentiability analysis.
- Preimage attack analysis.
- Algebraic normal form analysis.
- SAT/SMT-based reduced-round attacks.
- Meet-in-the-middle attacks.
- Rotational cryptanalysis.
- State recovery attempts.
- Chosen-prefix collision attacks.
- Large-scale GPU collision search.
- Deep structural analysis of the custom quotient ring.

## 7. Comparison with SHA-3 and Kyber

### Compared with SHA-3

SHA-3 is a standardized cryptographic hash family based on Keccak. It has received extensive public cryptanalysis, has a well-defined sponge construction, and is suitable for real-world security use.

Re-LWE Hash v2 is not comparable in maturity:

| Property | SHA-3 | Re-LWE Hash v2 |
|---|---:|---:|
| Standardized | Yes | No |
| Public cryptanalysis | Extensive | Minimal/local |
| Formal construction framework | Sponge | Custom recursive Module-LWE-like design |
| Security recommendation | Production use | Educational/experimental only |
| Known security margin | Strongly studied | Unknown |
| Implementation portability | Broad | Prototype |

Re-LWE Hash v2 shows promising empirical avalanche behavior, but SHA-3 remains the correct choice for real hashing.

### Compared with Kyber / ML-KEM

Kyber, standardized as ML-KEM, is a post-quantum key encapsulation mechanism based on Module-LWE. It is not a hash function.

Re-LWE Hash v2 borrows some surface-level ingredients:

- `q = 3329`
- polynomial/module arithmetic
- small error terminology
- Module-LWE-inspired matrix-vector mixing

But it does not inherit Kyber's security proof or design assurance.

Important differences:

- Kyber uses carefully specified distributions, compression, reconciliation/KEM logic, and a standard ring.
- Re-LWE Hash v2 uses a custom ring and deterministic recursive error.
- Kyber's security target is key encapsulation, not collision resistance or random-oracle-like hashing.
- A Module-LWE flavor does not automatically imply post-quantum hash security.

The most accurate description is:

```text
Re-LWE Hash v2 is PQ-inspired, not PQ-proven.
```

## 8. Security Conclusion & Recommendations

Re-LWE Hash v2 has some encouraging empirical properties under the latest local tests:

- 48-round avalanche behavior is close to ideal for 256-bit output.
- Output bit flip probabilities are near 50%.
- No obvious low-weight differential characteristic was found in shallow tests.
- No strong random low-weight linear approximation was observed.
- Truncated birthday collisions occur at the expected birthday scale.

However, the construction should not be used for real security.

The main reasons are:

- No formal security proof.
- No third-party cryptanalysis.
- Custom ring not used by Kyber.
- Custom ARX/error feedback mechanism.
- Heavy use of SHA3 makes it unclear what security is contributed by the Re-LWE core.
- Existing tests are statistical and limited.

Recommended use:

- Educational experiments.
- Cryptography puzzles.
- Demonstrations of polynomial rings, Module-LWE-style mixing, avalanche tests, and attack harnesses.
- Research prototyping where failure is acceptable.

Not recommended for:

- Password hashing.
- File integrity in production.
- Digital signatures.
- Commitments.
- MACs.
- Key derivation.
- Blockchain/consensus use.
- Any security boundary.

Final assessment:

```text
Re-LWE Hash v2 is an interesting educational and experimental hash design with good preliminary avalanche statistics, but it has no validated security claim. Treat it as a toy construction. Use SHA-3, BLAKE2, BLAKE3, or another vetted hash for real systems.
```

Warning:

```text
This is a toy hash for educational/puzzle purposes only. Do not use for real security.
```
