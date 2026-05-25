# Re-LWE Hash v1.0

Pure recursive lattice + ARX hashing with strong self-referential chaos, no SHA3 dependency, and a fast AVX2 C port.

Re-LWE Hash v1.0 is the cleaned-up release line: Tree Hybrid is gone, Pure 32 rounds is the default, and 48 rounds remains available as an explicit high-security mode.

> Re-LWE Hash is experimental cryptographic research software. It is not standardized or third-party audited. Use SHA-2, SHA-3, BLAKE2, BLAKE3, or another vetted hash for production security.

## Philosophy

Re-LWE Hash is built around one idea: keep the internal state dirty, recursive, and hard to simplify.

- **No SHA3/SHAKE/BLAKE inside the primitive.**
- **No reduction of recursive depth for benchmark theater.**
- **Strong recursive self-reference:** the error vector `e`, lattice state `b`, evolved seed, ARX salt, and Ring-LWE mixing feed each other every round.
- **Pure lattice + ARX hybrid:** modified Ring-LWE polynomial multiplication supplies algebraic weight; ARX supplies fast chaotic diffusion.

The construction intentionally keeps the feedback loop tangled:

```text
message
  -> internal ARX absorber
  -> recursive Re-LWE core
       state_r, error_r, seed_r
       -> feedback
       -> ARX error evolution
       -> Ring-LWE matrix mixing + state self-product
       -> seed evolution
  -> ARX squeeze
  -> digest
```

## v1.0 Structure

Default parameters:

```text
mode:        Pure recursive
rounds:      32
high mode:   48 via --rounds 48
ring:        Z_3329[x] / (x^256 + x^128 + 1)
n:           256
q:           3329
k:           3
eta:         2
output:      256 bits
```

## Build

Go:

```bash
cd go
go test ./...
go run ./cmd/relwehash "self-test"
```

C AVX2/OpenMP:

```bash
make clean all
make test
```

The C build uses native AVX2-oriented flags, LTO, loop alignment, OpenMP, and the optimized NTT cache path in `relwe.c`.

## Usage

Hash a string with Go:

```bash
cd go
go run ./cmd/relwehash "hello"
go run ./cmd/relwehash --rounds 48 "hello"
```

Hash a file with Go:

```bash
cd go
go run ./cmd/relwehash --file ./message.bin
```

Hash a string with C:

```bash
./relwehash_c "hello"
./relwehash_c --rounds 48 "hello"
```

Hash a file with C:

```bash
./relwehash_c --file ./message.bin
```

Use from Go:

```go
h := relwe.NewWithParams(relwe.DefaultK, relwe.DefaultRounds, relwe.DefaultOutput)
digest := h.Hash("hello")
```

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

Go and C are expected to match byte-for-byte for the same parameters.

## Benchmark

Historical Go Pure 32r benchmark:

```text
go run ./benchmark --data-mb 10 --iterations 100 --rounds 32
Throughput: 117.07 MB/s
```

Current optimized C AVX2 benchmark on the local 16-thread WSL machine:

```text
./benchmark_c --data-mb 32 --iterations 32 --threads 16 --rounds 32
Throughput: 4045.38 MB/s
```

That is the v1.0 target in one line:

```text
Tree 없이, Pure 32r로, BLAKE3급 bulk throughput.
```

The C benchmark parallelizes independent hash jobs with OpenMP. Single-stream throughput is lower because the primitive is intentionally heavier than conventional ARX-only hashes.

## Security Snapshot

The strongest current default-round avalanche run:

```text
rounds: 32
trials: 500000
mean: 128.007 bits (50.003%)
stddev: 7.994 bits
45-55% ratio: 89.59%
output flip probability range: 0.4983..0.5019
```

Shallow differential search at 32 rounds found no obvious low-weight characteristic:

```text
flips=1 best_mean=125.97 bits
flips=2 best_mean=126.22 bits
flips=4 best_mean=125.44 bits
flips=8 best_mean=126.16 bits
```

See [SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md) for caveats. The short version: empirically strong, structurally interesting, not proven.

## Repository Layout

```text
go/relwe/relwe.go          Go reference implementation
go/cmd/relwehash           Go CLI
go/cmd/relweattack         Experimental analysis harness
go/benchmark               Go benchmark
relwe.h / relwe.c          Optimized C port
benchmark.c                C benchmark
Makefile                   C build/test/bench targets
SECURITY_ANALYSIS.md       v1.0 security notes
LICENSE                    MIT license
log/                       Historical experiment logs
out/                       Generated analysis artifacts
```

## License

MIT. See [LICENSE](LICENSE).
