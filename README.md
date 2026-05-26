# Re-LWE Hash v1.3

Pure recursive lattice + ARX hashing with strong self-referential chaos, XOF support, no SHA3 dependency, and a fast AVX2 C port.

Re-LWE Hash v1.3 is the XOF support release: Tree Hybrid is gone, Pure 32 rounds is the default, 48 rounds remains available as an explicit high-security mode, and fixed hash/XOF outputs are separated by domain tags.

> Re-LWE Hash is experimental cryptographic research software. It is not standardized or third-party audited. Use SHA-2, SHA-3, BLAKE2, BLAKE3, or another vetted hash for production security.

## Philosophy

Re-LWE Hash is built around one idea: keep the internal state dirty, recursive, and hard to simplify.

- **No SHA3/SHAKE/BLAKE inside the primitive.**
- **No borrowed external constants:** the primitive stays self-contained instead of importing SHA-style round constants.
- **No reduction of recursive depth for benchmark theater.**
- **Strong recursive self-reference:** the error vector `e`, lattice state `b`, evolved seed, ARX salt, and Ring-LWE mixing feed each other every round.
- **Pure lattice + ARX hybrid:** modified Ring-LWE polynomial multiplication supplies algebraic weight; ARX supplies fast chaotic diffusion.
- **Domain-separated XOF:** fixed hash and XOF use independent Re-LWE domains, not SHAKE or any external sponge.

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
  -> ARX squeeze / counter squeeze
  -> digest or XOF bytes
```

## v1.3 Structure

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
xof:         arbitrary length, RELWE-XOF-v1 domain
```

Domain separation:

```text
Fixed hash: RELWE-HASH-v1
XOF:        RELWE-XOF-v1
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
go run ./cmd/relwehash --xof-len 64 "hello"
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
./relwehash_c --xof-len 64 "hello"
```

Hash a file with C:

```bash
./relwehash_c --file ./message.bin
```

Use from Go:

```go
h := relwe.NewWithParams(relwe.DefaultK, relwe.DefaultRounds, relwe.DefaultOutput)
digest := h.Hash("hello")
xof := h.XOF([]byte("hello"), 64)
sum := relwe.Sum256([]byte("hello"))
stream := relwe.XOF([]byte("hello"), 1024)
_ = digest
_ = xof
_ = sum
_ = stream
```

Use from C:

```c
uint8_t digest[32];
uint8_t stream[1024];

relwe_hash(digest, msg, msg_len);
relwe_xof(stream, sizeof(stream), msg, msg_len);
```

## Self-Test Vectors

Message:

```text
self-test
```

Expected digests:

```text
32 rounds:
8afaa410180107a133eed056ef7254ae93a389a8b09f1539c5ee41a40de6e707

48 rounds:
4b6d3a56521ef5db650011483668f1911166d318f87f62f8b56d8134acc98d9b

XOF, 64 bytes:
093627fe71a30d4f165463d431a02ac9dd318d5aa78b19e23273eb8958e57dea4c2c3d8854996ff2df2cb9708f89721eb779c1d613adf0a8a995fd9f1115a7a2
```

Go and C are expected to match byte-for-byte for the same parameters and XOF length.

## Benchmark

Historical Go Pure 32r benchmark:

```text
go run ./benchmark --data-mb 10 --iterations 100 --rounds 32
Throughput: 117.07 MB/s
```

Current optimized C AVX2 benchmark on the local 16-thread WSL machine:

```text
./benchmark_c --data-mb 64 --iterations 16 --threads 16 --rounds 32
Best observed throughput: 5856.15 MB/s
```

That is the v1.3 target in one line:

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
SECURITY_ANALYSIS.md       v1.3 security notes
LICENSE                    MIT license
log/                       Historical experiment logs
out/                       Generated analysis artifacts
```

## License

MIT. See [LICENSE](LICENSE).
