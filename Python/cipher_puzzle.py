#!/usr/bin/env python3
"""
Educational cryptography puzzle.

This is a toy cipher for learning and puzzle purposes only. It is not secure
and must not be used for real confidentiality.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import hmac
from typing import Iterable


MOD = 257
BLOCK_SIZE = 128
PAD_MARKER = 256
DEFAULT_MASTER_PASSPHRASE = "cryptography-puzzle"
DEFAULT_SEED = DEFAULT_MASTER_PASSPHRASE
DEFAULT_SEED_ROUNDS = 2
DEFAULT_MIX_ROUNDS = 2
DEFAULT_CIPHER_ROUNDS = 1
DEFAULT_ARX_LAYERS = 1
INTEGRITY_TAG_SIZE = 32

Matrix = list[list[int]]
Vector = list[int]


def mod_inverse(a: int, mod: int = MOD) -> int:
    """Return x such that a * x == 1 (mod mod)."""
    a %= mod
    if a == 0:
        raise ValueError("0 has no modular inverse")

    old_r, r = a, mod
    old_s, s = 1, 0

    while r:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_r != 1:
        raise ValueError(f"{a} has no modular inverse modulo {mod}")
    return old_s % mod


def validate_matrix(A: Matrix, size: int = BLOCK_SIZE) -> None:
    if len(A) != size or any(len(row) != size for row in A):
        raise ValueError(f"A must be a {size}x{size} matrix")


def validate_key(k: Vector, size: int = BLOCK_SIZE) -> None:
    if len(k) != size:
        raise ValueError(f"k must have length {size}")


def validate_rounds(rounds: int, name: str = "rounds") -> None:
    if rounds < 1:
        raise ValueError(f"{name} must be at least 1")


def validate_count(value: int, name: str) -> None:
    if value < 0:
        raise ValueError(f"{name} must be at least 0")


def matrix_inverse_mod(A: Matrix, mod: int = MOD) -> Matrix:
    """Invert a square matrix over integers modulo mod using Gauss-Jordan."""
    validate_matrix(A, len(A))
    n = len(A)

    left = [[value % mod for value in row] for row in A]
    right = [[1 if i == j else 0 for j in range(n)] for i in range(n)]

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if left[row][col] % mod != 0:
                pivot = row
                break

        if pivot is None:
            raise ValueError("A is not invertible modulo 257")

        if pivot != col:
            left[col], left[pivot] = left[pivot], left[col]
            right[col], right[pivot] = right[pivot], right[col]

        inv_pivot = mod_inverse(left[col][col], mod)
        left[col] = [(value * inv_pivot) % mod for value in left[col]]
        right[col] = [(value * inv_pivot) % mod for value in right[col]]

        for row in range(n):
            if row == col:
                continue
            factor = left[row][col] % mod
            if factor == 0:
                continue
            left[row] = [
                (left[row][j] - factor * left[col][j]) % mod for j in range(n)
            ]
            right[row] = [
                (right[row][j] - factor * right[col][j]) % mod for j in range(n)
            ]

    return right


def mat_vec_mul_mod(A: Matrix, x: Vector, mod: int = MOD) -> Vector:
    return [sum(a * b for a, b in zip(row, x)) % mod for row in A]


def rotate_left(value: int, amount: int, width: int = 9) -> int:
    del width
    return (value * pow(2, amount, MOD)) % MOD


def rotate_right(value: int, amount: int, width: int = 9) -> int:
    del width
    return (value * mod_inverse(pow(2, amount, MOD), MOD)) % MOD


def arx_round_constant(round_num: int, mod: int = MOD) -> int:
    return (0x5A5A5A5A + round_num * 0x11111111) % mod


def arx_layer(block: list[int], round_num: int, mod: int = MOD) -> list[int]:
    """Apply one ARX round to a block."""
    block = list(block)
    n = len(block)

    # Addition. This intentionally updates in-place for a chain effect.
    for i in range(n):
        block[i] = (block[i] + block[(i + 1) % n]) % mod

    # Rotation-like diffusion over mod 257. This keeps values in 0..256 and
    # remains reversible, unlike a raw bit rotate followed by modulo reduction.
    for i in range(n):
        rot = (3 + round_num + i) % 8 + 1
        block[i] = rotate_left(block[i], rot, width=9) % mod

    # XOR with a round constant derived from the round number.
    rc = arx_round_constant(round_num, mod)
    for i in range(n):
        block[i] ^= rc

    return block


def inverse_arx_layer(block: list[int], round_num: int, mod: int = MOD) -> list[int]:
    """Reverse one ARX round produced by arx_layer()."""
    block = list(block)
    n = len(block)

    # XOR is its own inverse.
    rc = arx_round_constant(round_num, mod)
    for i in range(n):
        block[i] ^= rc

    # Undo the 9-bit rotations.
    for i in range(n):
        rot = (3 + round_num + i) % 8 + 1
        block[i] = rotate_right(block[i], rot, width=9) % mod

    # Undo the chained addition from the end toward the beginning.
    block[-1] = (block[-1] - block[0]) % mod
    for i in range(n - 2, -1, -1):
        block[i] = (block[i] - block[(i + 1) % n]) % mod

    return block


def derive_master_seed(master_passphrase: str | bytes) -> bytes:
    """Hash the user-friendly passphrase into a 64-byte master seed."""
    passphrase_bytes = (
        master_passphrase.encode("utf-8")
        if isinstance(master_passphrase, str)
        else master_passphrase
    )
    return hashlib.sha3_512(b"master-seed|" + passphrase_bytes).digest()


def derive_seed(
    master_passphrase: str | bytes, seed_rounds: int = DEFAULT_SEED_ROUNDS
) -> bytes:
    """Derive the working seed by repeatedly hashing the master seed."""
    validate_rounds(seed_rounds, "seed_rounds")
    state = derive_master_seed(master_passphrase)
    for _ in range(seed_rounds):
        state = hashlib.sha3_512(b"derived-seed|" + state).digest()
    return state


def integrity_tag(derived_seed: bytes, size: int = INTEGRITY_TAG_SIZE) -> bytes:
    """Return a MAC-like puzzle tag. This is not a real secure MAC."""
    if size < 1:
        raise ValueError("integrity tag size must be at least 1")
    if size > len(derived_seed):
        raise ValueError("integrity tag size cannot exceed derived seed length")
    return derived_seed[:size]


def sha3_mixed_stream(
    seed: bytes, label: bytes, needed: int, mix_rounds: int = DEFAULT_MIX_ROUNDS
) -> bytes:
    """Generate bytes by mixing SHA3-512 and SHA3-384 several times."""
    validate_rounds(mix_rounds, "mix_rounds")
    output = bytearray()
    counter = 0

    while len(output) < needed:
        state = seed + b"|" + label + b"|" + counter.to_bytes(8, "big")
        for _ in range(mix_rounds):
            h512 = hashlib.sha3_512(state).digest()
            h384 = hashlib.sha3_384(state + h512).digest()
            state = (
                hashlib.sha3_512(h512 + h384 + state).digest()
                + hashlib.sha3_384(h384 + h512 + state).digest()
            )
        output.extend(state)
        counter += 1

    return bytes(output[:needed])


def numbers_from_stream(stream: bytes, count: int, mod: int = MOD) -> list[int]:
    values: list[int] = []
    for start in range(0, len(stream) - 1, 2):
        values.append(int.from_bytes(stream[start : start + 2], "big") % mod)
        if len(values) == count:
            return values
    raise ValueError("not enough stream bytes")


def derive_matrix(
    seed: str | bytes, mix_rounds: int = DEFAULT_MIX_ROUNDS, size: int = BLOCK_SIZE
) -> Matrix:
    """Derive an invertible matrix over mod 257 using SHA3-512/SHA3-384."""
    seed_bytes = seed.encode("utf-8") if isinstance(seed, str) else seed

    for attempt in range(10_000):
        label = b"A-matrix|" + attempt.to_bytes(4, "big")
        stream = sha3_mixed_stream(seed_bytes, label, size * size * 2, mix_rounds)
        values = numbers_from_stream(stream, size * size)
        A = [values[row * size : (row + 1) * size] for row in range(size)]
        try:
            matrix_inverse_mod(A)
        except ValueError:
            continue
        return A

    raise ValueError("failed to derive an invertible matrix")


def derive_key(
    seed: str | bytes, mix_rounds: int = DEFAULT_MIX_ROUNDS, size: int = BLOCK_SIZE
) -> Vector:
    """Derive a key vector over mod 257 using SHA3-512."""
    validate_rounds(mix_rounds, "mix_rounds")
    seed_bytes = seed.encode("utf-8") if isinstance(seed, str) else seed
    output = bytearray()
    counter = 0

    while len(output) < size * 2:
        state = seed_bytes + b"|k-vector|" + counter.to_bytes(8, "big")
        for _ in range(mix_rounds):
            state = hashlib.sha3_512(state).digest()
        output.extend(state)
        counter += 1

    return numbers_from_stream(bytes(output), size)


def derive_parameters(
    seed: str | bytes = DEFAULT_SEED, mix_rounds: int = DEFAULT_MIX_ROUNDS
) -> tuple[Matrix, Vector]:
    return derive_matrix(seed, mix_rounds), derive_key(seed, mix_rounds)


def derive_parameters_from_passphrase(
    master_passphrase: str | bytes = DEFAULT_MASTER_PASSPHRASE,
    seed_rounds: int = DEFAULT_SEED_ROUNDS,
    mix_rounds: int = DEFAULT_MIX_ROUNDS,
) -> tuple[Matrix, Vector, bytes]:
    derived_seed = derive_seed(master_passphrase, seed_rounds)
    A, k = derive_parameters(derived_seed, mix_rounds)
    return A, k, derived_seed


def chunked(values: list[int], size: int = BLOCK_SIZE) -> Iterable[Vector]:
    for start in range(0, len(values), size):
        yield values[start : start + size]


def pad_to_blocks(values: list[int], size: int = BLOCK_SIZE) -> list[int]:
    padded = list(values)
    padded.append(PAD_MARKER)
    while len(padded) % size:
        padded.append(PAD_MARKER)
    return padded


def remove_padding(values: list[int]) -> bytes:
    try:
        end = values.index(PAD_MARKER)
    except ValueError as exc:
        raise ValueError("decrypted data has no padding/end marker") from exc

    data = values[:end]
    if any(value < 0 or value > 255 for value in data):
        raise ValueError("decrypted payload contains a non-byte value")
    if any(value != PAD_MARKER for value in values[end:]):
        raise ValueError("invalid padding after end marker")
    return bytes(data)


def encrypt(
    text: str,
    A: Matrix,
    k: Vector,
    rounds: int = DEFAULT_CIPHER_ROUNDS,
    arx_layers: int = DEFAULT_ARX_LAYERS,
) -> list[int]:
    """Encrypt text into a flat list of numbers in the range 0..256."""
    validate_matrix(A)
    validate_key(k)
    validate_rounds(rounds)
    validate_count(arx_layers, "arx_layers")
    matrix_inverse_mod(A)  # Confirms A is invertible before encrypting.

    compressed = gzip.compress(text.encode("utf-8"), mtime=0)
    values = pad_to_blocks(list(compressed))
    cipher: list[int] = []

    for x in chunked(values):
        block = x
        for round_num in range(rounds):
            Ax = mat_vec_mul_mod(A, block)
            block = [(value + key) % MOD for value, key in zip(Ax, k)]
            for layer in range(arx_layers):
                block = arx_layer(block, round_num=round_num * arx_layers + layer)
        cipher.extend(block)

    return cipher


def decrypt(
    cipher: list[int],
    A: Matrix,
    k: Vector,
    rounds: int = DEFAULT_CIPHER_ROUNDS,
    arx_layers: int = DEFAULT_ARX_LAYERS,
) -> str:
    """Decrypt a flat list of numbers produced by encrypt()."""
    validate_matrix(A)
    validate_key(k)
    validate_rounds(rounds)
    validate_count(arx_layers, "arx_layers")
    if len(cipher) % BLOCK_SIZE:
        raise ValueError("cipher length must be a multiple of 5")
    if any(value < 0 or value >= MOD for value in cipher):
        raise ValueError("cipher values must be in the range 0..256")

    A_inv = matrix_inverse_mod(A)
    plain_values: list[int] = []

    for c in chunked(cipher):
        block = c
        for round_num in range(rounds - 1, -1, -1):
            for layer in range(arx_layers - 1, -1, -1):
                block = inverse_arx_layer(
                    block, round_num=round_num * arx_layers + layer
                )
            shifted = [(value - key) % MOD for value, key in zip(block, k)]
            block = mat_vec_mul_mod(A_inv, shifted)
        plain_values.extend(block)

    compressed = remove_padding(plain_values)
    return gzip.decompress(compressed).decode("utf-8")


def encrypt_with_passphrase(
    text: str,
    master_passphrase: str | bytes = DEFAULT_MASTER_PASSPHRASE,
    seed_rounds: int = DEFAULT_SEED_ROUNDS,
    mix_rounds: int = DEFAULT_MIX_ROUNDS,
    rounds: int = DEFAULT_CIPHER_ROUNDS,
    arx_layers: int = DEFAULT_ARX_LAYERS,
) -> list[int]:
    """Encrypt with passphrase-derived A/k and append a 32-byte integrity tag."""
    A, k, derived_seed = derive_parameters_from_passphrase(
        master_passphrase, seed_rounds, mix_rounds
    )
    cipher = encrypt(text, A, k, rounds, arx_layers)
    return cipher + list(integrity_tag(derived_seed))


def decrypt_with_passphrase(
    cipher_with_tag: list[int],
    master_passphrase: str | bytes = DEFAULT_MASTER_PASSPHRASE,
    seed_rounds: int = DEFAULT_SEED_ROUNDS,
    mix_rounds: int = DEFAULT_MIX_ROUNDS,
    rounds: int = DEFAULT_CIPHER_ROUNDS,
    arx_layers: int = DEFAULT_ARX_LAYERS,
) -> str:
    """Verify the appended tag, then decrypt with passphrase-derived A/k."""
    if len(cipher_with_tag) <= INTEGRITY_TAG_SIZE:
        raise ValueError("ciphertext is too short to contain an integrity tag")
    if any(value < 0 or value >= MOD for value in cipher_with_tag):
        raise ValueError("cipher values must be in the range 0..256")

    A, k, derived_seed = derive_parameters_from_passphrase(
        master_passphrase, seed_rounds, mix_rounds
    )
    expected_tag = integrity_tag(derived_seed)
    cipher = cipher_with_tag[:-INTEGRITY_TAG_SIZE]
    actual_tag = cipher_with_tag[-INTEGRITY_TAG_SIZE:]

    if len(cipher) % BLOCK_SIZE:
        raise ValueError("cipher length before tag must be a multiple of 5")
    if any(value > 255 for value in actual_tag):
        raise ValueError("integrity tag values must be bytes in the range 0..255")
    if not hmac.compare_digest(bytes(actual_tag), expected_tag):
        raise ValueError("integrity check failed")

    return decrypt(cipher, A, k, rounds, arx_layers)


def demo(
    text: str,
    master_passphrase: str = DEFAULT_MASTER_PASSPHRASE,
    seed_rounds: int = DEFAULT_SEED_ROUNDS,
    mix_rounds: int = DEFAULT_MIX_ROUNDS,
    rounds: int = DEFAULT_CIPHER_ROUNDS,
    arx_layers: int = DEFAULT_ARX_LAYERS,
) -> None:
    A, k, derived_seed = derive_parameters_from_passphrase(
        master_passphrase, seed_rounds, mix_rounds
    )

    cipher = encrypt_with_passphrase(
        text, master_passphrase, seed_rounds, mix_rounds, rounds, arx_layers
    )
    decrypted = decrypt_with_passphrase(
        cipher, master_passphrase, seed_rounds, mix_rounds, rounds, arx_layers
    )

    print("A mod 257:")
    for row in A:
        print(row)
    print()
    print("A^-1 mod 257:")
    for row in matrix_inverse_mod(A):
        print(row)
    print()
    print("k:")
    print(k)
    print()
    print(f"master passphrase: {master_passphrase}")
    print(f"master seed: {derive_master_seed(master_passphrase).hex()}")
    print(f"derived seed: {derived_seed.hex()}")
    print(f"integrity tag: {integrity_tag(derived_seed).hex()}")
    print(f"seed rounds: {seed_rounds}")
    print(f"sha3 mix rounds: {mix_rounds}")
    print(f"cipher rounds: {rounds}")
    print(f"ARX layers per round: {arx_layers}")
    print()
    print("cipher:")
    print(cipher)
    print()
    print("decrypted:")
    print(decrypted)

    assert decrypted == text


def self_test() -> None:
    A, k, _ = derive_parameters_from_passphrase(
        DEFAULT_MASTER_PASSPHRASE, DEFAULT_SEED_ROUNDS, DEFAULT_MIX_ROUNDS
    )
    samples = [
        "",
        "ascii sample",
        "한글과 emoji 없이 UTF-8 테스트",
        "Line 1\nLine 2\nSymbols: !@#$%^&*()",
    ]

    for text in samples:
        for rounds in (1, 2, 5):
            for arx_layers in (0, 1, 3):
                assert (
                    decrypt(
                        encrypt(text, A, k, rounds, arx_layers),
                        A,
                        k,
                        rounds,
                        arx_layers,
                    )
                    == text
                )
                cipher = encrypt_with_passphrase(
                    text,
                    DEFAULT_MASTER_PASSPHRASE,
                    DEFAULT_SEED_ROUNDS,
                    DEFAULT_MIX_ROUNDS,
                    rounds,
                    arx_layers,
                )
                assert (
                    decrypt_with_passphrase(
                        cipher,
                        DEFAULT_MASTER_PASSPHRASE,
                        DEFAULT_SEED_ROUNDS,
                        DEFAULT_MIX_ROUNDS,
                        rounds,
                        arx_layers,
                    )
                    == text
                )

    tampered = encrypt_with_passphrase("tamper test")
    tampered[-1] ^= 1
    try:
        decrypt_with_passphrase(tampered)
    except ValueError as exc:
        assert "integrity check failed" in str(exc)
    else:
        raise AssertionError("tampered integrity tag was accepted")

    print("self-test passed")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Educational gzip + matrix cipher puzzle over mod 257."
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run decrypt(encrypt(text)) == text tests",
    )
    parser.add_argument(
        "--passphrase",
        "--seed",
        dest="passphrase",
        default=DEFAULT_MASTER_PASSPHRASE,
        help="master passphrase hashed into the master seed; --seed is an alias",
    )
    parser.add_argument(
        "--seed-rounds",
        type=int,
        default=DEFAULT_SEED_ROUNDS,
        help="SHA3-512 rounds for deriving the working seed from the master seed",
    )
    parser.add_argument(
        "--mix-rounds",
        type=int,
        default=DEFAULT_MIX_ROUNDS,
        help="SHA3 mixing rounds for deriving A and k",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_CIPHER_ROUNDS,
        help="cipher rounds to apply to each 5-number block",
    )
    parser.add_argument(
        "--arx-layers",
        type=int,
        default=DEFAULT_ARX_LAYERS,
        help="ARX layers to apply after matrix multiplication and key addition",
    )
    parser.add_argument(
        "text",
        nargs="?",
        default="Hello, 암호 퍼즐! gzip + matrix over mod 257.",
        help="plaintext to encrypt and decrypt",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
    else:
        demo(
            args.text,
            args.passphrase,
            args.seed_rounds,
            args.mix_rounds,
            args.rounds,
            args.arx_layers,
        )


if __name__ == "__main__":
    main()
