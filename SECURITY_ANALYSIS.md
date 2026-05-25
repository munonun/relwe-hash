# Security Analysis: Re-LWE Hash v1.0

## Summary

Re-LWE Hash v1.0 is an experimental pure recursive lattice + ARX hash. The default configuration is 32 rounds. The 48-round path remains available through `--rounds 48` for conservative experiments.

The design goal is not to wrap an existing hash. It is to preserve a strong self-referential Re-LWE feedback loop:

```text
error_r + state_r + seed_r
  -> ARX feedback and salt
  -> evolved error_{r+1}
  -> modified Ring-LWE matrix mixing
  -> state self-product
  -> evolved seed_{r+1}
```

The construction has promising empirical behavior, but it has no formal proof, no standardization, and no third-party audit. Treat it as research software.

## v1.0 Baseline

```text
mode:        Pure recursive only
rounds:      32 by default
high mode:   48 via --rounds 48
ring:        Z_3329[x] / (x^256 + x^128 + 1)
n:           256
q:           3329
k:           3
eta:         2
output:      256 bits by default
```

Tree Hybrid has been removed. There is no split/local/merge phase in v1.0.

## Security Goals

The intended goals are:

- Preimage resistance.
- Second-preimage resistance.
- Collision resistance near the generic 256-bit digest birthday bound.
- Strong avalanche under small input changes.
- No obvious low-weight differential characteristic.
- No obvious low-weight linear approximation.
- Preservation of recursive `e <-> b` chaos across all rounds.

These are goals and empirical observations, not proven guarantees.

## Avalanche: 32 Rounds

The strongest current default-round test is a 500,000-trial statistical avalanche run:

```text
rounds: 32
k: 3
eta: 2
output_bits: 256
trials: 500000

mean: 128.007 bits (50.003%)
stddev: 7.994 bits
min: 92 bits
max: 165 bits
45-55% range: 115..140 changed bits
45-55% ratio: 89.59%
Avalanche quality: Good
```

For an ideal random 256-bit output difference:

```text
expected mean:   128 bits
expected stddev: sqrt(256 * 0.5 * 0.5) = 8
```

The observed 32-round distribution is close to ideal.

Output-bit independence from the same run:

```text
output flip probability range: 0.4983..0.5019
mean absolute bias from 0.5: 0.0005
max absolute bias from 0.5: 0.0019
```

This is the main reason 32 rounds became the v1.0 default.

## 32 Rounds vs 48 Rounds

Large avalanche comparison:

```text
32 rounds:
mean: 128.007 bits (50.003%)
stddev: 7.994 bits
45-55% ratio: 89.59%

48 rounds:
mean: 128.003 bits (50.001%)
stddev: 8.001 bits
45-55% ratio: 89.53%
```

In these tests, 32 rounds and 48 rounds were practically indistinguishable on avalanche quality. 48 rounds still provides a wider experimental margin and remains available as high mode.

## Differential Search

A 32-round reduced differential characteristic search used:

```text
flips: 1,2,4,8
candidates: 64 per flip count
trials: 64 per candidate
tested characteristics: 256
```

Best candidates:

```text
flips=1 best_mean=125.97 bits min=108 max=143
flips=2 best_mean=126.22 bits min=106 max=141
flips=4 best_mean=125.44 bits min=105 max=141
flips=8 best_mean=126.16 bits min=105 max=145
```

The best observed candidates stayed near half the digest width. No obvious low-output-weight differential characteristic was found in this search.

Limitations:

- The search was randomized and shallow.
- It does not cover the full input-difference space.
- It does not rule out advanced structural distinguishers.

## Collision Testing

Birthday experiments so far are truncated-prefix tests, not full digest collisions.

For 32 rounds, a 32-bit prefix collision appeared after 80,594 random messages. This is consistent with the birthday scale:

```text
sqrt(2^32) = 2^16 = 65536
```

This is expected and is not a break. A full 256-bit digest collision would be a serious finding. None has been observed.

If Re-LWE Hash behaves like an ideal 256-bit hash, generic collision resistance would be about `2^128` work. That "if" remains empirical and unproven.

## Known Risks

Open risks remain:

- No formal reduction from Re-LWE Hash to LWE/RLWE hardness.
- Non-standard ring: `x^256 + x^128 + 1`.
- Deterministic error evolution may hide structure.
- Algebraic, SAT/SMT, MILP, and Gröbner-style attacks are not exhausted.
- Random avalanche and differential tests can miss structural weaknesses.
- No public third-party cryptanalysis.

The primitive is intentionally chaotic and self-referential, but chaos is not a proof.

## Performance Context

The v1.0 default is 32 rounds because it gives a strong empirical security/performance balance:

```text
Go Pure 32r historical benchmark: 117.07 MB/s
C AVX2 Pure 32r local benchmark: 4045.38 MB/s
```

The optimized C path reaches BLAKE3-class multi-threaded bulk throughput without restoring Tree Hybrid and without weakening the recursive core.

## Recommendation

For experiments:

- Use default 32 rounds.
- Use `--rounds 48` for conservative/high-margin experiments.
- Keep running larger avalanche, differential, algebraic, and collision tests.

For production security:

- Use SHA-2, SHA-3, BLAKE2, BLAKE3, or another vetted standard hash.

## Self-Test Vectors

Message:

```text
self-test
```

Expected digests:

```text
32 rounds:
9893280ff26e5cd7c640bcda8a4ccd6aea5ba14fac861d38d55fc620d8004ae3

48 rounds:
31e86769b004819435a8ca42b29bdc646ea9e550266727ebbe42ac044e6186f6
```

Go and C must match byte-for-byte for these vectors.
