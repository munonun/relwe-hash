# Pure Re-LWE Hash Eta Sweep

This note describes how to compare the toy noise parameter `eta` for
Pure Re-LWE Hash. The default is `eta=2`, which preserves the previous
implementation behavior. Values `eta=3` and `eta=4` are useful experimental
points for checking whether wider recursive error noise changes observable
attack statistics.

Warning: Pure Re-LWE Hash is educational and experimental. These tests do not
establish real cryptographic security.

## Common Setup

Run each experiment with the same `k`, output size, rounds, trial counts, and
thread count. Change only `--eta`.

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks avalanche \
    --eta "$eta" \
    --stat-avalanche-rounds 48 \
    --stat-avalanche-trials 5000 \
    -k 3
done
```

For faster smoke tests, reduce trial counts first, then rerun promising cases
with larger counts.

## Avalanche Metrics

Compare:

- Mean Hamming distance of the digest after a one-bit input flip.
- Standard deviation.
- Min/max Hamming distance.
- Ratio inside the 45~55% changed-bit band.
- Worst output-bit flip probability bias.
- Worst input/output conditional avalanche pair.

For a 256-bit digest, the target mean is close to 128 changed bits. Large
movement away from 128, unusually low min values, or repeated high conditional
bias warnings are more important than tiny eta-to-eta differences.

## Differential Search

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks differential \
    --eta "$eta" \
    --differential-rounds 4,8,12,16,24,32,48 \
    --differential-flips 1,2,4,8 \
    --differential-searches 128 \
    --differential-trials 64 \
    -k 3
done
```

Compare the best mean output difference for each `(rounds, flips)` row. A best
mean below 110 bits for 256-bit output is treated by the CLI as a potential
weak differential characteristic.

## SAT/SMT Thresholds

The SAT/SMT mode exports reduced mini-core constraints. It is not a full
48-round proof attempt.

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks sat-smt \
    --eta "$eta" \
    --sat-rounds 4 \
    --sat-message-bits 16 \
    --sat-output-bits 16 \
    --sat-mode differential
done
```

Then run the suggested `z3` command for each exported file. Compare the largest
round/output-bit setting where Z3 still returns `sat` quickly, where it returns
`unsat`, and where it times out or returns `unknown`.

Interpretation:

- `sat`: the reduced condition is reachable in the mini-core.
- `unsat`: the condition is impossible in that exported mini-core model.
- `unknown` or timeout: increase timeout or reduce model size.

## MILP-Style Active Bit Propagation

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks milp \
    --eta "$eta" \
    --milp-rounds 1,2,4,8,12,16 \
    --milp-message-bits 16 \
    --milp-output-bits 16
done
```

Compare minimum active output bits and warnings. This is a conservative
mini-core abstraction, so treat it as a search guide rather than a proof.

## Algebraic Degree

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks algebraic \
    --eta "$eta" \
    --algebraic-rounds 1,2,4,8,12,16 \
    --algebraic-message-bits 16 \
    --algebraic-output-bits 16
done
```

Compare estimated max degree and mean degree. A degree that stays low after
several rounds is a structural warning.

## Groebner Export

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks groebner \
    --eta "$eta" \
    --groebner-rounds 1,2 \
    --groebner-message-bits 8 \
    --groebner-output-bits 8
done
```

Compare:

- Number of variables.
- Number of equations.
- Sage runtime.
- Groebner basis size.
- Whether tiny instances become easier or harder as eta changes.

Generated files are written under `out/groebner/`.

## Cycle Detection

```bash
for eta in 2 3 4; do
  GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack \
    --attacks cycle \
    --eta "$eta" \
    --cycle-max-rounds 512 \
    -k 3
done
```

Compare whether any low-entropy message produces a repeated full-state
fingerprint. Any repeat at low rounds is a serious structural warning in this
toy design.

## Suggested Summary Table

| eta | avalanche mean | avalanche stddev | differential best mean | SAT/SMT threshold | Groebner runtime | cycle repeats |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |

