#!/usr/bin/env python3
"""
Attack experiments for Re-LWE Hash v2.

This script is for cryptanalytic exploration of the toy hash implemented in
emptytomb_module_ring_hash.py. It does not prove security or insecurity. It
tries practical experiments that are useful for inspecting a new toy design:

    1. Reduced-round collision search for rounds 4, 6, 8, and 12.
    2. Birthday-style collision simulation on many similar messages.
    3. Differential/avalanche tests for 1-bit message differences.
    4. Multi-process random message collision tests.
    5. Statistical avalanche test over thousands of random messages.

Full 256-bit or 512-bit collisions are expected to be infeasible at normal
sample sizes. To make experiments useful, collision searches default to a
truncated digest prefix. Full-digest collisions are still detected and reported
separately if they occur.
"""

from __future__ import annotations

import argparse
import os
import random
import secrets
import statistics
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from Pure_emptytomb_module_ring_hash import ReLWEHashV2


DEFAULT_ROUNDS = (4, 6, 8, 12)
DEFAULT_OUTPUT_BITS = 256
DEFAULT_K = 3


@dataclass(frozen=True)
class CollisionResult:
    """Description of a found digest-prefix or full-digest collision."""

    attempts: int
    digest_key: str
    digest_a: str
    digest_b: str
    message_a: bytes
    message_b: bytes
    full_collision: bool


def _bits_to_hex_chars(bits: int) -> int:
    """Return how many hex characters are needed to cover a bit prefix."""
    if bits <= 0:
        raise ValueError("bits must be positive")
    return (bits + 3) // 4


def _digest_key(digest_hex: str, bits: int) -> str:
    """
    Return a digest prefix key of approximately bits bits.

    The script uses hex strings, so non-multiple-of-4 bit lengths are rounded up
    to the next nibble. For example, 30 bits uses 32 bits of hex prefix.
    """
    return digest_hex[: _bits_to_hex_chars(bits)]


def _hamming_distance_hex(a: str, b: str) -> int:
    """Compute bit Hamming distance between equal-length hex digests."""
    if len(a) != len(b):
        raise ValueError("digests must have the same length")
    return (int(a, 16) ^ int(b, 16)).bit_count()


def _flip_one_bit(data: bytes, bit_index: int) -> bytes:
    """Return a copy of data with one selected bit flipped."""
    if not data:
        raise ValueError("data must be non-empty")
    out = bytearray(data)
    byte_index = bit_index // 8
    bit_in_byte = bit_index % 8
    out[byte_index] ^= 1 << bit_in_byte
    return bytes(out)


def _similar_message(base: bytes, counter: int) -> bytes:
    """
    Generate a family of highly similar messages for birthday simulation.

    The prefix is stable and only a small counter suffix changes. If the hash
    has weak diffusion or short-cycle behavior in reduced rounds, this style of
    input can make it easier to see.
    """
    return base + b"|nonce=" + counter.to_bytes(8, "little")


def _random_message(min_len: int = 1, max_len: int = 96) -> bytes:
    """Generate a random binary message."""
    size = min_len + secrets.randbelow(max_len - min_len + 1)
    return secrets.token_bytes(size)


def _check_collision(
    seen: Dict[str, Tuple[bytes, str]],
    digest_key: str,
    digest: str,
    message: bytes,
    attempts: int,
) -> Optional[CollisionResult]:
    """Insert a digest key into a table, or return collision details."""
    previous = seen.get(digest_key)
    if previous is None:
        seen[digest_key] = (message, digest)
        return None

    previous_message, previous_digest = previous
    if previous_message == message:
        return None

    return CollisionResult(
        attempts=attempts,
        digest_key=digest_key,
        digest_a=previous_digest,
        digest_b=digest,
        message_a=previous_message,
        message_b=message,
        full_collision=(previous_digest == digest),
    )


def _print_collision(result: CollisionResult, label: str, prefix_bits: int) -> None:
    """Print a collision result in a compact, reproducible form."""
    kind = "FULL" if result.full_collision else f"{prefix_bits}-bit truncated"
    print(f"[{label}] Found {kind} collision after {result.attempts} messages!")
    print(f"  key:      {result.digest_key}")
    print(f"  digest A: {result.digest_a}")
    print(f"  digest B: {result.digest_b}")
    print(f"  msg A:    {result.message_a.hex()}")
    print(f"  msg B:    {result.message_b.hex()}")


def reduced_round_collision_search(
    rounds_list: Sequence[int],
    attempts: int,
    prefix_bits: int,
    k: int,
    output_bits: int,
) -> None:
    """
    Search for collisions under reduced rounds.

    This is the first thing to try against an iterative design: reduce the
    number of rounds, generate many simple messages, and look for digest-prefix
    collisions or unexpected full collisions.
    """
    print("\n== Reduced-round collision search ==")
    for rounds in rounds_list:
        h = ReLWEHashV2(k=k, rounds=rounds, output_bits=output_bits)
        seen: Dict[str, Tuple[bytes, str]] = {}
        start = time.time()
        found = None

        for i in range(attempts):
            message = f"re-lwe-v2|reduced|r={rounds}|m={i:016x}".encode()
            digest = h.hash(message)
            key = _digest_key(digest, prefix_bits)
            found = _check_collision(seen, key, digest, message, i + 1)
            if found:
                break

        elapsed = time.time() - start
        label = f"rounds={rounds}"
        if found:
            _print_collision(found, label, prefix_bits)
        else:
            print(f"[{label}] No collision in {attempts} attempts ({elapsed:.2f}s)")


def birthday_attack_simulation(
    rounds: int,
    attempts: int,
    prefix_bits: int,
    k: int,
    output_bits: int,
    base_message: bytes,
) -> None:
    """
    Birthday-style test on many similar messages.

    For a b-bit truncated target, collisions become likely around 2^(b/2)
    attempts. This does not attack full SHA3-sized output directly; it checks
    whether reduced Re-LWE mixing shows odd clustering on related inputs.
    """
    print("\n== Birthday attack simulation on similar messages ==")
    h = ReLWEHashV2(k=k, rounds=rounds, output_bits=output_bits)
    seen: Dict[str, Tuple[bytes, str]] = {}
    start = time.time()

    for i in range(attempts):
        message = _similar_message(base_message, i)
        digest = h.hash(message)
        key = _digest_key(digest, prefix_bits)
        found = _check_collision(seen, key, digest, message, i + 1)
        if found:
            _print_collision(found, f"birthday rounds={rounds}", prefix_bits)
            return

    elapsed = time.time() - start
    print(f"[birthday rounds={rounds}] No collision in {attempts} attempts ({elapsed:.2f}s)")


def differential_avalanche_test(
    max_rounds: int,
    trials: int,
    k: int,
    output_bits: int,
    message_len: int,
) -> None:
    """
    Flip one message bit and measure digest bit changes round by round.

    A healthy hash-like construction should approach a 50 percent output-bit
    flip rate after enough rounds. Reduced rounds often expose weak avalanche.
    """
    print("\n== Differential 1-bit avalanche test ==")
    print("rounds | trials | min flips | mean flips | max flips | mean %")
    print("-------+--------+-----------+------------+-----------+--------")

    if message_len <= 0:
        raise ValueError("message_len must be positive")

    base_rng = random.Random(0x52454C574532)
    bases = [base_rng.randbytes(message_len) for _ in range(trials)]
    bit_positions = [base_rng.randrange(message_len * 8) for _ in range(trials)]

    for rounds in range(1, max_rounds + 1):
        h = ReLWEHashV2(k=k, rounds=rounds, output_bits=output_bits)
        distances = []

        for base, bit_index in zip(bases, bit_positions):
            modified = _flip_one_bit(base, bit_index)
            digest_a = h.hash(base)
            digest_b = h.hash(modified)
            distances.append(_hamming_distance_hex(digest_a, digest_b))

        mean = statistics.fmean(distances)
        percent = 100.0 * mean / output_bits
        print(
            f"{rounds:6d} | {trials:6d} | {min(distances):9d} | "
            f"{mean:10.2f} | {max(distances):9d} | {percent:6.2f}"
        )


def statistical_avalanche_test(
    trials: int,
    rounds: int,
    k: int,
    output_bits: int,
    min_message_len: int,
    max_message_len: int,
    histogram_bin_width: int,
) -> None:
    """
    Run a large statistical avalanche test.

    For each random message, flip exactly one random input bit and measure the
    Hamming distance between the original and modified 256-bit digest. A good
    hash-like avalanche profile should be centered near 128 changed bits with a
    binomial standard deviation near 8 for 256-bit output.
    """
    print("\n== Statistical avalanche test ==")
    if trials <= 0:
        raise ValueError("trials must be positive")
    if output_bits != 256:
        raise ValueError("statistical avalanche test currently expects 256-bit output")
    if min_message_len <= 0 or max_message_len < min_message_len:
        raise ValueError("invalid message length range")
    if histogram_bin_width <= 0:
        raise ValueError("histogram bin width must be positive")

    h = ReLWEHashV2(k=k, rounds=rounds, output_bits=output_bits)
    distances: List[int] = []
    start = time.time()

    for i in range(trials):
        msg_len = min_message_len + secrets.randbelow(max_message_len - min_message_len + 1)
        message = secrets.token_bytes(msg_len)
        bit_index = secrets.randbelow(msg_len * 8)
        modified = _flip_one_bit(message, bit_index)

        digest_a = h.hash(message)
        digest_b = h.hash(modified)
        distances.append(_hamming_distance_hex(digest_a, digest_b))

        done = i + 1
        if trials >= 1000 and done % max(1, trials // 10) == 0:
            print(f"  progress: {done}/{trials}")

    elapsed = time.time() - start
    mean = statistics.fmean(distances)
    stdev = statistics.pstdev(distances)
    lo = int(output_bits * 0.45)
    hi = int(output_bits * 0.55)
    in_band = sum(1 for d in distances if lo <= d <= hi)
    in_band_ratio = in_band / trials
    mean_pct = 100.0 * mean / output_bits

    quality = _avalanche_quality(mean_pct, stdev, in_band_ratio)

    print(f"rounds: {rounds}, k: {k}, trials: {trials}, output_bits: {output_bits}")
    print(f"mean: {mean:.3f} bits ({mean_pct:.3f}%)")
    print(f"stddev: {stdev:.3f} bits")
    print(f"min: {min(distances)} bits")
    print(f"max: {max(distances)} bits")
    print(f"45~55% range: {lo}..{hi} changed bits")
    print(f"45~55% ratio: {in_band_ratio * 100:.2f}%")
    print(f"Avalanche quality: {quality}")
    print(f"elapsed: {elapsed:.2f}s")
    print("\nDistribution histogram:")
    _print_histogram(distances, bin_width=histogram_bin_width)


def _avalanche_quality(mean_pct: float, stdev: float, in_band_ratio: float) -> str:
    """
    Simple heuristic quality label for 256-bit avalanche statistics.

    The ideal independent-bit model has mean 50%, standard deviation 8 bits,
    and about 89% of samples within the 45~55% band for 256 output bits.
    """
    mean_error = abs(mean_pct - 50.0)
    stdev_error = abs(stdev - 8.0)
    if mean_error <= 0.75 and stdev_error <= 1.5 and in_band_ratio >= 0.84:
        return "Good"
    if mean_error <= 2.0 and stdev_error <= 3.0 and in_band_ratio >= 0.70:
        return "Fair"
    return "Poor"


def _print_histogram(distances: Sequence[int], bin_width: int = 4, max_bar: int = 48) -> None:
    """Print a compact text histogram of Hamming distances."""
    low = (min(distances) // bin_width) * bin_width
    high = ((max(distances) + bin_width - 1) // bin_width) * bin_width
    bins = []
    for start in range(low, high + 1, bin_width):
        end = start + bin_width - 1
        count = sum(1 for d in distances if start <= d <= end)
        bins.append((start, end, count))

    peak = max(count for _, _, count in bins) or 1
    for start, end, count in bins:
        bar_len = round(max_bar * count / peak)
        bar = "#" * bar_len
        print(f"{start:3d}-{end:3d}: {count:5d} {bar}")


def _random_worker(
    worker_id: int,
    rounds: int,
    k: int,
    output_bits: int,
    prefix_bits: int,
    attempts: int,
) -> Tuple[int, List[Tuple[str, bytes, str, int]]]:
    """
    Worker for process-parallel random testing.

    It returns local digest-prefix observations. The parent process merges these
    maps after workers finish, avoiding cross-process locking on every hash.
    """
    h = ReLWEHashV2(k=k, rounds=rounds, output_bits=output_bits)
    local_seen: Dict[str, Tuple[bytes, str, int]] = {}

    for i in range(attempts):
        message = b"worker=" + worker_id.to_bytes(4, "little") + b"|" + _random_message()
        digest = h.hash(message)
        key = _digest_key(digest, prefix_bits)

        if key in local_seen and local_seen[key][0] != message:
            previous_message, previous_digest, previous_index = local_seen[key]
            return (
                i + 1,
                [
                    (key, previous_message, previous_digest, previous_index),
                    (key, message, digest, i + 1),
                ],
            )

        local_seen[key] = (message, digest, i + 1)

    return attempts, [(key, msg, digest, idx) for key, (msg, digest, idx) in local_seen.items()]


def multithreaded_random_test(
    rounds: int,
    attempts: int,
    threads: int,
    prefix_bits: int,
    k: int,
    output_bits: int,
) -> None:
    """
    Multi-process random-message collision test.

    The Re-LWE toy hash is CPU-bound pure Python, so normal threads are limited
    by the GIL. This uses ProcessPoolExecutor so --threads actually maps to
    multiple worker processes that can occupy multiple CPU cores.
    """
    print("\n== Multi-process random message test ==")
    if threads <= 0:
        raise ValueError("worker count must be positive")
    if attempts <= 0:
        raise ValueError("attempts must be positive")

    per_worker = [attempts // threads] * threads
    for i in range(attempts % threads):
        per_worker[i] += 1

    global_seen: Dict[str, Tuple[bytes, str, int]] = {}
    completed = 0
    start = time.time()

    print(f"[random rounds={rounds}] workers={threads}, attempts={attempts}")

    with ProcessPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                _random_worker,
                worker_id,
                rounds,
                k,
                output_bits,
                prefix_bits,
                count,
            )
            for worker_id, count in enumerate(per_worker)
            if count > 0
        ]

        for future in as_completed(futures):
            attempts_done, rows = future.result()
            completed += attempts_done
            for key, message, digest, local_index in rows:
                previous = global_seen.get(key)
                if previous is not None and previous[0] != message:
                    result = CollisionResult(
                        attempts=completed,
                        digest_key=key,
                        digest_a=previous[1],
                        digest_b=digest,
                        message_a=previous[0],
                        message_b=message,
                        full_collision=(previous[1] == digest),
                    )
                    _print_collision(result, f"random rounds={rounds}", prefix_bits)
                    return
                global_seen[key] = (message, digest, local_index)

    elapsed = time.time() - start
    print(f"[random rounds={rounds}] No collision in {attempts} attempts ({elapsed:.2f}s)")


def _parse_rounds(value: str) -> Tuple[int, ...]:
    """Parse comma-separated round counts."""
    rounds = tuple(int(part.strip()) for part in value.split(",") if part.strip())
    if not rounds:
        raise argparse.ArgumentTypeError("at least one round count is required")
    if any(r <= 0 for r in rounds):
        raise argparse.ArgumentTypeError("round counts must be positive")
    return rounds


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Cryptanalytic experiments against toy Re-LWE Hash v2."
    )
    parser.add_argument(
        "--attacks",
        default="reduced,birthday,differential,random",
        help="comma-separated attacks: reduced,birthday,differential,random,stat-avalanche",
    )
    parser.add_argument(
        "--reduced-rounds",
        type=_parse_rounds,
        default=DEFAULT_ROUNDS,
        help="comma-separated reduced rounds, default: 4,6,8,12",
    )
    parser.add_argument("--reduced-attempts", type=int, default=256)
    parser.add_argument("--birthday-rounds", type=int, default=8)
    parser.add_argument("--birthday-attempts", type=int, default=512)
    parser.add_argument(
        "--random-rounds",
        type=_parse_rounds,
        default=(8,),
        help="comma-separated round counts for random test, e.g. 12,16,20,24",
    )
    parser.add_argument("--random-attempts", type=int, default=1024)
    parser.add_argument(
        "--threads",
        type=int,
        default=max(1, min(4, os.cpu_count() or 1)),
        help="number of worker processes for the random test",
    )
    parser.add_argument("--prefix-bits", type=int, default=32)
    parser.add_argument("--differential-rounds", type=int, default=12)
    parser.add_argument("--differential-trials", type=int, default=16)
    parser.add_argument("--stat-avalanche-trials", type=int, default=5000)
    parser.add_argument("--stat-avalanche-rounds", type=int, default=48)
    parser.add_argument("--stat-avalanche-min-len", type=int, default=1)
    parser.add_argument("--stat-avalanche-max-len", type=int, default=96)
    parser.add_argument("--histogram-bin-width", type=int, default=4)
    parser.add_argument("--message-len", type=int, default=32)
    parser.add_argument("-k", type=int, default=DEFAULT_K)
    parser.add_argument("--output-bits", type=int, default=DEFAULT_OUTPUT_BITS, choices=(256, 512))
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    attacks = {item.strip().lower() for item in args.attacks.split(",") if item.strip()}
    valid = {"reduced", "birthday", "differential", "random", "stat-avalanche"}
    unknown = attacks - valid
    if unknown:
        parser.error(f"unknown attack(s): {', '.join(sorted(unknown))}")

    print("Re-LWE Hash v2 attack experiments")
    print(f"k={args.k}, output_bits={args.output_bits}, prefix_bits={args.prefix_bits}")
    print("Note: prefix collisions are truncated-digest experiments, not full hash breaks.")

    if "reduced" in attacks:
        reduced_round_collision_search(
            rounds_list=args.reduced_rounds,
            attempts=args.reduced_attempts,
            prefix_bits=args.prefix_bits,
            k=args.k,
            output_bits=args.output_bits,
        )

    if "birthday" in attacks:
        birthday_attack_simulation(
            rounds=args.birthday_rounds,
            attempts=args.birthday_attempts,
            prefix_bits=args.prefix_bits,
            k=args.k,
            output_bits=args.output_bits,
            base_message=b"re-lwe-v2-birthday-base-message",
        )

    if "differential" in attacks:
        differential_avalanche_test(
            max_rounds=args.differential_rounds,
            trials=args.differential_trials,
            k=args.k,
            output_bits=args.output_bits,
            message_len=args.message_len,
        )

    if "random" in attacks:
        for rounds in args.random_rounds:
            multithreaded_random_test(
                rounds=rounds,
                attempts=args.random_attempts,
                threads=args.threads,
                prefix_bits=args.prefix_bits,
                k=args.k,
                output_bits=args.output_bits,
            )

    if "stat-avalanche" in attacks:
        statistical_avalanche_test(
            trials=args.stat_avalanche_trials,
            rounds=args.stat_avalanche_rounds,
            k=args.k,
            output_bits=args.output_bits,
            min_message_len=args.stat_avalanche_min_len,
            max_message_len=args.stat_avalanche_max_len,
            histogram_bin_width=args.histogram_bin_width,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
