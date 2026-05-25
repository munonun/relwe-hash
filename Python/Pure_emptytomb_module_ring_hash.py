#!/usr/bin/env python3
"""
Pure Re-LWE Hash: a 100% pure lattice/ARX toy hash.

WARNING: This is a toy hash for educational/puzzle purposes only.
Do not use for real security.

This file deliberately uses no external hash function at any stage. All
expansion, feedback, salt generation, recursive error evolution, and final
output folding are built from:

    - Ring arithmetic over Z_3329[x] / (x^256 + x^128 + 1)
    - Kyber-style 256-point NTT multiplication
    - ARX operations: Add, Rotate, XOR
    - Recursive chaotic error evolution
    - Module mixing with configurable k, default k=3

The construction is intentionally educational. It is not standardized, not
formally analyzed, and not suitable for real cryptographic use.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Iterable, List, Sequence


Q = 3329
N = 256
MID = N // 2
DEFAULT_K = 3
DEFAULT_ROUNDS = 48
WARNING = "This is a toy hash for educational/puzzle purposes only. Do not use for real security."
MASK32 = 0xFFFFFFFF


def _to_bytes(message: str | bytes) -> bytes:
    """Convert supported message types to bytes deterministically."""
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("message must be str or bytes")


def _rotl32(x: int, r: int) -> int:
    """Rotate a 32-bit word left by r bits."""
    x &= MASK32
    r &= 31
    return ((x << r) | (x >> (32 - r))) & MASK32


def _u32_from_bytes(data: bytes, offset: int) -> int:
    """Read four bytes as little-endian, wrapping for deterministic streams."""
    if not data:
        return 0
    n = len(data)
    return (
        data[offset % n]
        | (data[(offset + 1) % n] << 8)
        | (data[(offset + 2) % n] << 16)
        | (data[(offset + 3) % n] << 24)
    )


def _le32(x: int) -> bytes:
    """Serialize a 32-bit word as little-endian bytes."""
    x &= MASK32
    return bytes((x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF))


def _words_to_bytes(words: Sequence[int]) -> bytes:
    """Serialize 32-bit words."""
    return b"".join(_le32(w) for w in words)


def _bytes_to_words(data: bytes) -> List[int]:
    """Pack bytes into little-endian 32-bit words, zero-padding the last word."""
    out = []
    for i in range(0, len(data), 4):
        chunk = data[i : i + 4]
        value = 0
        for j, b in enumerate(chunk):
            value |= b << (8 * j)
        out.append(value & MASK32)
    return out or [0]


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    """ChaCha-like ARX quarter round over a mutable 32-bit word state."""
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl32(state[b] ^ state[c], 7)


def _arx_permute(words: Sequence[int], rounds: int = 10) -> List[int]:
    """
    Deterministic ARX permutation used for all non-ring expansion.

    This is a small local ARX permutation used only to make this toy
    construction self-contained.
    """
    state = [(w & MASK32) for w in words]
    if len(state) < 16:
        state += [0x9E3779B9 ^ (i * 0x85EBCA6B) for i in range(16 - len(state))]
    state = state[:16]

    for r in range(rounds):
        state[0] = (state[0] + 0x9E3779B9 + r) & MASK32
        state[5] ^= _rotl32(state[0], 3 + (r & 15))
        state[10] = (state[10] + _rotl32(state[15], 11)) & MASK32
        state[15] ^= (0xA5A5A5A5 + 0x01010101 * r) & MASK32

        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)

    return state


class _ARXSponge:
    """
    Small streaming ARX absorber for message bytes.

    It exists to preserve deterministic direct message absorption. The state is
    finalized into a message-derived IV that seeds polynomial expansion,
    feedback, salt, and final folding.
    """

    __slots__ = ("state", "length", "buffer")

    def __init__(self, k: int, rounds: int, output_bits: int):
        self.state = [
            0x70757265,  # "pure"
            0x72656C77,  # "relw"
            0x65486173,  # "eHas"
            0x68327632,  # "h2v2"
            N,
            Q,
            k,
            rounds,
            output_bits,
            0x243F6A88,
            0x85A308D3,
            0x13198A2E,
            0x03707344,
            0xA4093822,
            0x299F31D0,
            0x082EFA98,
        ]
        self.length = 0
        self.buffer = bytearray()

    def update(self, data: bytes) -> None:
        """Absorb bytes directly into the ARX state."""
        if not data:
            return
        self.length += len(data)
        self.buffer.extend(data)
        while len(self.buffer) >= 64:
            block = bytes(self.buffer[:64])
            del self.buffer[:64]
            self._absorb_block(block, full=True)

    def _absorb_block(self, block: bytes, full: bool) -> None:
        words = _bytes_to_words(block)
        while len(words) < 16:
            words.append(0)

        for i in range(16):
            lane = (i * 5 + 3) & 15
            self.state[lane] ^= words[i]
            self.state[(lane + 7) & 15] = (
                self.state[(lane + 7) & 15] + _rotl32(words[i] ^ i, 3 + (i & 15))
            ) & MASK32
        self.state[0] ^= len(block) if full else (0x80000000 | len(block))
        self.state[9] = (self.state[9] + self.length) & MASK32
        self.state[13] ^= (self.length >> 32) & MASK32
        self.state = _arx_permute(self.state, rounds=8)

    def finalize_words(self) -> List[int]:
        """Finalize absorption and return a 16-word message-derived IV."""
        pad = bytes(self.buffer)
        self.buffer.clear()
        self._absorb_block(pad + b"\x80", full=False)
        self.state[1] ^= self.length & MASK32
        self.state[2] ^= (self.length >> 32) & MASK32
        self.state[14] ^= 0xFFFFFFFF
        self.state = _arx_permute(self.state, rounds=16)
        return list(self.state)


class _ARXStream:
    """Deterministic ARX word stream used for domain-separated expansion."""

    __slots__ = ("state", "counter")

    def __init__(self, seed_words: Sequence[int], domain: int):
        base = list(seed_words[:16])
        if len(base) < 16:
            base += [0] * (16 - len(base))
        base[0] ^= domain & MASK32
        base[1] = (base[1] + ((domain * 0x9E3779B1) & MASK32)) & MASK32
        base[7] ^= _rotl32(domain, 13)
        self.state = _arx_permute(base, rounds=12)
        self.counter = 0

    def words(self, count: int) -> List[int]:
        """Return count deterministic 32-bit words."""
        out: List[int] = []
        while len(out) < count:
            block = list(self.state)
            block[0] = (block[0] + self.counter) & MASK32
            block[3] ^= _rotl32(self.counter, 17)
            block[12] = (block[12] + 0xD1B54A32 + self.counter * 0x9E3779B1) & MASK32
            mixed = _arx_permute(block, rounds=10)
            for i in range(16):
                mixed[i] = (mixed[i] + self.state[(i + 5) & 15] + self.counter) & MASK32
            self.state = _arx_permute(mixed, rounds=6)
            self.counter = (self.counter + 1) & MASK32
            out.extend(mixed)
        return out[:count]


def _derive_words(seed_words: Sequence[int], domain: int, count: int) -> List[int]:
    """Domain-separated ARX expansion into 32-bit words."""
    return _ARXStream(seed_words, domain).words(count)


def _mix_word_list(words: Sequence[int], extra: int, rounds: int = 8) -> List[int]:
    """Fold an arbitrary word list into 16 ARX-mixed words."""
    state = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
        0xCBBB9D5D,
        0x629A292A,
        0x9159015A,
        0x152FECD8,
        0x67332667,
        0x8EB44A87,
        0xDB0C2E0D,
        extra & MASK32,
    ]
    for idx, word in enumerate(words):
        lane = idx & 15
        state[lane] = (state[lane] + (word & MASK32) + idx * 0x9E3779B1) & MASK32
        state[(lane + 5) & 15] ^= _rotl32(word, (idx % 23) + 3)
        if lane == 15:
            state = _arx_permute(state, rounds=rounds)
    state[0] ^= len(words) & MASK32
    state[8] ^= (len(words) >> 32) & MASK32
    return _arx_permute(state, rounds=rounds + 6)


def _factor_unique(n: int) -> List[int]:
    """Return the unique prime factors of n."""
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1
    if n > 1:
        factors.append(n)
    return factors


def _primitive_root(modulus: int) -> int:
    """Find a primitive root modulo a small prime."""
    factors = _factor_unique(modulus - 1)
    for g in range(2, modulus):
        if all(pow(g, (modulus - 1) // p, modulus) != 1 for p in factors):
            return g
    raise ValueError(f"no primitive root found for modulus {modulus}")


PRIMITIVE_ROOT = _primitive_root(Q)


def _ntt(values: List[int], modulus: int, invert: bool = False) -> None:
    """
    In-place radix-2 Cooley-Tukey NTT with bit-reversal.

    NTT changes polynomial block multiplication from O(n^2) schoolbook work to
    O(n log n). This is a Kyber-style 256-point NTT over q=3329.
    """
    n = len(values)
    if n & (n - 1):
        raise ValueError("NTT length must be a power of two")
    if (modulus - 1) % n != 0:
        raise ValueError(f"modulus {modulus} does not support NTT length {n}")

    j = 0
    for i in range(1, n):
        bit = n >> 1
        while j & bit:
            j ^= bit
            bit >>= 1
        j ^= bit
        if i < j:
            values[i], values[j] = values[j], values[i]

    primitive = PRIMITIVE_ROOT if modulus == Q else _primitive_root(modulus)
    length = 2
    while length <= n:
        wlen = pow(primitive, (modulus - 1) // length, modulus)
        if invert:
            wlen = pow(wlen, -1, modulus)
        half = length >> 1
        for start in range(0, n, length):
            w = 1
            for offset in range(start, start + half):
                u = values[offset]
                v = values[offset + half] * w % modulus
                values[offset] = (u + v) % modulus
                values[offset + half] = (u - v) % modulus
                w = w * wlen % modulus
        length <<= 1

    if invert:
        inv_n = pow(n, -1, modulus)
        for i, value in enumerate(values):
            values[i] = value * inv_n % modulus


def ntt(values: Sequence[int], modulus: int = Q) -> List[int]:
    """Return the forward Kyber-style 256-point NTT of values."""
    out = [value % modulus for value in values]
    _ntt(out, modulus, invert=False)
    return out


def intt(values: Sequence[int], modulus: int = Q) -> List[int]:
    """Return the inverse Kyber-style 256-point NTT of values."""
    out = [value % modulus for value in values]
    _ntt(out, modulus, invert=True)
    return out


def _cyclic_convolution_256(a: Sequence[int], b: Sequence[int]) -> List[int]:
    """Return a 256-coefficient cyclic convolution over Z_q using the NTT."""
    if len(a) > N or len(b) > N:
        raise ValueError("cyclic NTT convolution inputs must have length <= 256")

    fa = [0] * N
    fb = [0] * N
    for i, value in enumerate(a):
        fa[i] = value % Q
    for i, value in enumerate(b):
        fb[i] = value % Q

    _ntt(fa, Q, invert=False)
    _ntt(fb, Q, invert=False)
    for i in range(N):
        fa[i] = fa[i] * fb[i] % Q
    _ntt(fa, Q, invert=True)
    return fa


def _block_convolution_128(a: Sequence[int], b: Sequence[int]) -> List[int]:
    """Exact product of two 128-coefficient blocks using the 256-point NTT."""
    if len(a) != MID or len(b) != MID:
        raise ValueError("block convolution expects two 128-coefficient blocks")
    return _cyclic_convolution_256(a, b)[: 2 * MID - 1]


class RingPoly:
    """
    Polynomial in R = Z_q[x] / (x^256 + x^128 + 1).

    Coefficients are stored in little-endian order. All coefficients are
    canonical representatives in [0, q).
    """

    __slots__ = ("coeffs",)

    def __init__(self, coeffs: Iterable[int] | None = None):
        if coeffs is None:
            self.coeffs = [0] * N
            return
        values = list(coeffs)
        if len(values) > N:
            raise ValueError(f"RingPoly expects at most {N} coefficients")
        self.coeffs = [(c % Q) for c in values] + [0] * (N - len(values))

    @classmethod
    def zero(cls) -> "RingPoly":
        return cls()

    @classmethod
    def uniform_from_words(cls, seed_words: Sequence[int], domain: int) -> "RingPoly":
        """Generate a deterministic ARX-expanded polynomial modulo q."""
        words = _derive_words(seed_words, domain, N)
        return cls(word % Q for word in words)

    @classmethod
    def small_from_words(cls, words: Sequence[int], bound: int = 32) -> "RingPoly":
        """Convert chaotic ARX words into small centered error coefficients."""
        if bound <= 0:
            raise ValueError("bound must be positive")
        width = 2 * bound + 1
        coeffs = []
        for i in range(N):
            w = words[i % len(words)]
            mixed = w ^ _rotl32(w, 7) ^ _rotl32(w, 19) ^ ((i * 0x9E3779B1) & MASK32)
            coeffs.append((mixed % width) - bound)
        return cls(coeffs)

    def __add__(self, other: "RingPoly") -> "RingPoly":
        return RingPoly((a + b) % Q for a, b in zip(self.coeffs, other.coeffs))

    def __sub__(self, other: "RingPoly") -> "RingPoly":
        return RingPoly((a - b) % Q for a, b in zip(self.coeffs, other.coeffs))

    def __neg__(self) -> "RingPoly":
        return RingPoly((-a) % Q for a in self.coeffs)

    def __mul__(self, other: "RingPoly") -> "RingPoly":
        """
        Kyber-style 256-point NTT multiplication in the custom ring.

        A 256-point cyclic NTT gives exact 128x128 block products because each
        block product has degree at most 254. Products are assembled and reduced
        with x^256 = -x^128 - 1.
        """
        a0 = self.coeffs[:MID]
        a1 = self.coeffs[MID:]
        b0 = other.coeffs[:MID]
        b1 = other.coeffs[MID:]

        p0 = _block_convolution_128(a0, b0)
        p2 = _block_convolution_128(a1, b1)
        a_sum = [(x + y) % Q for x, y in zip(a0, a1)]
        b_sum = [(x + y) % Q for x, y in zip(b0, b1)]
        p_sum = _block_convolution_128(a_sum, b_sum)
        p1 = [(p_sum[i] - p0[i] - p2[i]) % Q for i in range(len(p_sum))]

        tmp = [0] * (2 * N - 1)
        for i, value in enumerate(p0):
            tmp[i] = (tmp[i] + value) % Q
        for i, value in enumerate(p1):
            tmp[i + MID] = (tmp[i + MID] + value) % Q
        for i, value in enumerate(p2):
            tmp[i + N] = (tmp[i + N] + value) % Q

        for d in range(2 * N - 2, N - 1, -1):
            c = tmp[d]
            if c:
                tmp[d] = 0
                tmp[d - MID] = (tmp[d - MID] - c) % Q
                tmp[d - N] = (tmp[d - N] - c) % Q

        return RingPoly(tmp[:N])

    def to_words(self) -> List[int]:
        """Pack two 16-bit coefficients into each 32-bit word."""
        out = []
        for i in range(0, N, 2):
            out.append((self.coeffs[i] | (self.coeffs[i + 1] << 16)) & MASK32)
        return out

    def centered_coeffs(self) -> List[int]:
        """Return coefficients as centered representatives around zero."""
        half = Q // 2
        return [c - Q if c > half else c for c in self.coeffs]

    def __repr__(self) -> str:
        preview = ", ".join(str(c) for c in self.coeffs[:8])
        return f"RingPoly([{preview}, ...])"


def _module_mat_vec_mul(matrix: Sequence[Sequence[RingPoly]], vector: Sequence[RingPoly]) -> List[RingPoly]:
    """Multiply a k by k matrix of ring elements by a k-vector."""
    k = len(vector)
    result = []
    for row in matrix:
        acc = RingPoly.zero()
        for aij, vj in zip(row, vector):
            acc = acc + (aij * vj)
        result.append(acc)
    if len(result) != k:
        raise ValueError("matrix/vector dimension mismatch")
    return result


class PureReLWEHash:
    """
    Pure Re-LWE Hash with no external hash functions.

    The message is absorbed directly into an ARX state. That message-derived IV
    initializes module polynomials, round salt, recursive error evolution, and
    final digest folding. Ring multiplication uses a Kyber-style 256-point NTT.

    Parameters:
        k: module rank. Default is 3.
        rounds: recursive ARX/module mixing rounds. Default is 48.
        output_bits: digest size, either 256 or 512.
    """

    def __init__(self, k: int = DEFAULT_K, rounds: int = DEFAULT_ROUNDS, output_bits: int = 256):
        if k <= 0:
            raise ValueError("k must be positive")
        if rounds <= 0:
            raise ValueError("rounds must be positive")
        if output_bits not in (256, 512):
            raise ValueError("output_bits must be 256 or 512")
        self.k = k
        self.rounds = rounds
        self.output_bits = output_bits

    def _absorb_bytes(self, message: bytes) -> List[int]:
        """Absorb in-memory bytes into a 16-word message IV using only ARX."""
        sponge = _ARXSponge(self.k, self.rounds, self.output_bits)
        sponge.update(message)
        return sponge.finalize_words()

    def _initial_state(self, iv: Sequence[int]) -> List[RingPoly]:
        """Expand the message IV into the initial module state."""
        return [
            RingPoly.uniform_from_words(iv, 0x10000000 ^ (i * 0x9E3779B1))
            for i in range(self.k)
        ]

    def _initial_error(self, iv: Sequence[int]) -> List[RingPoly]:
        """Create the initial small error vector from ARX-expanded words."""
        return [
            RingPoly.small_from_words(
                _derive_words(iv, 0x20000000 ^ (i * 0x85EBCA6B), N),
                bound=32,
            )
            for i in range(self.k)
        ]

    def _state_feedback(
        self,
        state: Sequence[RingPoly],
        error: Sequence[RingPoly],
        iv: Sequence[int],
        round_index: int,
    ) -> List[int]:
        """Pure ARX compression of previous state, error, IV, and round."""
        words: List[int] = list(iv[:16])
        words.extend([round_index, self.k, self.rounds, self.output_bits, N, Q])
        for poly in state:
            words.extend(poly.to_words())
        for poly in error:
            words.extend(poly.to_words())
        return _mix_word_list(words, 0xFEE1DEAD ^ round_index, rounds=6)

    def _round_salt(self, seed: Sequence[int], feedback: Sequence[int], iv: Sequence[int], round_index: int) -> List[int]:
        """Generate deterministic round salt using only ARX."""
        material = list(iv[:16]) + list(seed[:16]) + list(feedback[:16])
        material.extend([round_index, round_index * 0x9E3779B1, self.k, Q, N])
        return _mix_word_list(material, 0x5A17C0DE ^ round_index, rounds=10)

    def _arx_error_words(
        self,
        previous_error: Sequence[RingPoly],
        seed: Sequence[int],
        salt: Sequence[int],
        previous_state: Sequence[RingPoly],
        lane_count: int,
    ) -> List[int]:
        """
        Evolve e_{i-1} into chaotic ARX words.

        This implements the recursive mechanism:

            e_i = ARX(e_{i-1}, seed_i + salt_i, b_{i-1})

        Every lane uses previous error coefficients, previous state
        coefficients, the evolving seed, the round salt, and neighboring lanes.
        """
        prev_coeffs = []
        state_coeffs = []
        for poly in previous_error:
            prev_coeffs.extend(poly.coeffs)
        for poly in previous_state:
            state_coeffs.extend(poly.coeffs)

        key = list(seed[:16]) + list(salt[:16])
        key = _mix_word_list(key, 0xA11CE000 ^ lane_count, rounds=8)
        words: List[int] = []

        for lane in range(lane_count):
            e = prev_coeffs[lane % len(prev_coeffs)]
            b = state_coeffs[(lane * 5 + 17) % len(state_coeffs)]
            k0 = key[lane & 15]
            k1 = key[(lane * 7 + 3) & 15]
            s0 = seed[(lane * 3 + 1) & 15]
            t0 = salt[(lane * 5 + 9) & 15]

            x = (e | (b << 16)) ^ k0 ^ ((lane * 0x9E3779B1) & MASK32)
            y = (k1 + ((b * 0x85EBCA6B) & MASK32) + lane + s0) & MASK32
            z = (x ^ _rotl32(y, 13) ^ t0 ^ 0xC2B2AE35) & MASK32

            for r in range(8):
                neighbor = words[-1] if words else salt[(r + lane) & 15]
                x = (x + y + seed[(r * 3 + lane) & 15]) & MASK32
                y = _rotl32(y ^ z ^ neighbor, 5 + ((r + lane) % 23))
                z = (z + _rotl32(x, 7) + salt[(r * 5 + lane) & 15]) & MASK32
                x ^= _rotl32(z, 16)
                y = (y + _rotl32(x ^ neighbor, 11)) & MASK32

            words.append((x ^ y ^ z) & MASK32)

        return words

    def _evolve_error(
        self,
        previous_error: Sequence[RingPoly],
        seed: Sequence[int],
        salt: Sequence[int],
        previous_state: Sequence[RingPoly],
    ) -> List[RingPoly]:
        """Compute the next recursive small error vector."""
        words = self._arx_error_words(previous_error, seed, salt, previous_state, self.k * N)
        return [
            RingPoly.small_from_words(words[i * N : (i + 1) * N], bound=32)
            for i in range(self.k)
        ]

    def _evolve_seed(
        self,
        seed: Sequence[int],
        salt: Sequence[int],
        state: Sequence[RingPoly],
        error: Sequence[RingPoly],
        iv: Sequence[int],
        round_index: int,
    ) -> List[int]:
        """State-coupled ARX evolution of the per-round seed."""
        words = list(iv[:16]) + list(seed[:16]) + list(salt[:16])
        words.extend([round_index, self.k, self.rounds, self.output_bits])
        for i, poly in enumerate(state):
            coeffs = poly.coeffs
            for j in range(0, N, 8):
                words.append((coeffs[j] | (coeffs[(j + 3) % N] << 16) | (i << 28)) & MASK32)
        for i, poly in enumerate(error):
            coeffs = poly.coeffs
            for j in range(1, N, 8):
                words.append((coeffs[j] | (coeffs[(j + 5) % N] << 16) | (i << 29)) & MASK32)
        return _mix_word_list(words, 0x51ED0000 ^ round_index, rounds=10)

    def _round_matrix(self, seed: Sequence[int], salt: Sequence[int], iv: Sequence[int], round_index: int) -> List[List[RingPoly]]:
        """Build deterministic k by k ring matrix A_i from ARX streams."""
        base = _mix_word_list(list(iv[:16]) + list(seed[:16]) + list(salt[:16]), 0xA7000000 ^ round_index, rounds=8)
        matrix = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                domain = 0x30000000 ^ (round_index * 0x9E3779B1) ^ (i << 8) ^ j
                row.append(RingPoly.uniform_from_words(base, domain))
            matrix.append(row)
        return matrix

    def _mix_round(
        self,
        state: Sequence[RingPoly],
        error: Sequence[RingPoly],
        seed: Sequence[int],
        iv: Sequence[int],
        round_index: int,
    ) -> tuple[List[RingPoly], List[RingPoly], List[int]]:
        """
        One pure Re-LWE round:

            feedback_i = ARX(b_{i-1}, e_{i-1}, iv, i)
            salt_i    = ARX(seed_i, feedback_i, iv, i)
            e_i       = ARX(e_{i-1}, seed_i + salt_i, b_{i-1})
            b_i       = A_i * b_{i-1} + e_i + nonlinear ring tweak
            seed_i+1  = ARX(seed_i, salt_i, b_i, e_i, iv, i)
        """
        feedback = self._state_feedback(state, error, iv, round_index)
        salt = self._round_salt(seed, feedback, iv, round_index)
        next_error = self._evolve_error(error, seed, salt, state)
        matrix = self._round_matrix(seed, salt, iv, round_index)
        mixed = _module_mat_vec_mul(matrix, state)

        next_state = []
        for i in range(self.k):
            neighbor = state[(i + 1) % self.k]
            recursive_tweak = state[i] * neighbor
            next_state.append(mixed[i] + next_error[i] + recursive_tweak)

        next_seed = self._evolve_seed(seed, salt, next_state, next_error, iv, round_index)
        return next_state, next_error, next_seed

    def _squeeze(self, seed: Sequence[int], state: Sequence[RingPoly], error: Sequence[RingPoly], iv: Sequence[int]) -> str:
        """
        Fold final module state into a digest using only ARX.

        Finalization uses coefficient permutation, state/error folding, and ARX
        stream expansion. No external hash or XOF is used.
        """
        words = list(iv[:16]) + list(seed[:16])
        words.extend([N, Q, self.k, self.rounds, self.output_bits])

        for poly_index, poly in enumerate(state):
            coeffs = poly.coeffs
            stride = 73 + 2 * poly_index
            for t in range(N):
                a = coeffs[(t * stride + 17 * poly_index) & (N - 1)]
                b = coeffs[(t * 41 + 19 + poly_index) & (N - 1)]
                words.append((a | (b << 16) | ((poly_index & 3) << 30)) & MASK32)

        for poly_index, poly in enumerate(error):
            coeffs = poly.coeffs
            stride = 89 + 2 * poly_index
            for t in range(0, N, 2):
                a = coeffs[(t * stride + 29 * poly_index) & (N - 1)]
                b = coeffs[(t * 53 + 31 + poly_index) & (N - 1)]
                words.append((a | (b << 16) | ((poly_index & 3) << 29)) & MASK32)

        folded = _mix_word_list(words, 0xF1A1F01D ^ self.output_bits, rounds=16)
        stream = _ARXStream(folded, 0xD16E5700 ^ self.output_bits)
        digest_words = stream.words(self.output_bits // 32)

        for i in range(len(digest_words)):
            digest_words[i] ^= folded[i & 15]
            digest_words[i] = _rotl32(digest_words[i], 7 + i) ^ folded[(i * 5 + 3) & 15]
            digest_words[i] &= MASK32

        return _words_to_bytes(digest_words).hex()

    def _digest_from_iv(self, iv: Sequence[int]) -> str:
        """Run all pure ARX/module rounds after absorption produces the IV."""
        state = self._initial_state(iv)
        error = self._initial_error(iv)
        seed = _mix_word_list(list(iv[:16]) + [self.k, self.rounds, self.output_bits], 0x5EED0001, rounds=12)

        for r in range(self.rounds):
            state, error, seed = self._mix_round(state, error, seed, iv, r)

        return self._squeeze(seed, state, error, iv)

    def hash(self, message: str | bytes) -> str:
        """Return a hexadecimal digest for str or bytes input."""
        return self._digest_from_iv(self._absorb_bytes(_to_bytes(message)))

    def hash_file(self, filepath: str) -> str:
        """
        Return a hexadecimal digest for a file's binary contents.

        The file is read in 1 MiB chunks. No external hash object is used; the
        streaming absorber is the local ARX sponge above.
        """
        sponge = _ARXSponge(self.k, self.rounds, self.output_bits)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                sponge.update(chunk)
        return self._digest_from_iv(sponge.finalize_words())


# Backward-compatible names for previous versions of this toy file.
ReLWEHashV2 = PureReLWEHash
EmptyTombModuleRingHash = PureReLWEHash


def _self_test() -> None:
    """Small deterministic checks for ring arithmetic and hash behavior."""
    one = RingPoly([1])
    x = RingPoly([0, 1])
    x_mid = RingPoly([0] * MID + [1])

    sample = [(i * 17 + 3) % Q for i in range(N)]
    assert intt(ntt(sample)) == sample

    def schoolbook_reference(a: Sequence[int], b: Sequence[int]) -> List[int]:
        tmp = [0] * (2 * N - 1)
        for i, ai in enumerate(a):
            if ai:
                for j, bj in enumerate(b):
                    if bj:
                        tmp[i + j] = (tmp[i + j] + ai * bj) % Q
        for d in range(2 * N - 2, N - 1, -1):
            c = tmp[d]
            if c:
                tmp[d] = 0
                tmp[d - MID] = (tmp[d - MID] - c) % Q
                tmp[d - N] = (tmp[d - N] - c) % Q
        return tmp[:N]

    a = [(i * 19 + 7) % Q for i in range(N)]
    b = [(i * i + 11) % Q for i in range(N)]
    assert (RingPoly(a) * RingPoly(b)).coeffs == schoolbook_reference(a, b)

    x2 = x * x
    x4 = x2 * x2
    x8 = x4 * x4
    x16 = x8 * x8
    x32 = x16 * x16
    x64 = x32 * x32
    x128 = x64 * x64
    x256 = x128 * x128
    assert x128.coeffs == x_mid.coeffs
    assert x256.coeffs == (-(x_mid + one)).coeffs

    h256 = PureReLWEHash(k=3, rounds=4, output_bits=256)
    a_digest = h256.hash("empty tomb")
    b_digest = h256.hash("empty tomb")
    c_digest = h256.hash("Empty tomb")
    assert a_digest == b_digest
    assert a_digest != c_digest
    assert len(a_digest) == 64

    h512 = PureReLWEHash(k=2, rounds=4, output_bits=512)
    d_digest = h512.hash(b"empty tomb")
    assert len(d_digest) == 128


def _demo() -> None:
    print(f"WARNING: {WARNING}")
    h = PureReLWEHash()
    msg = "The stone was rolled away."
    print(f"message: {msg!r}")
    print(f"pure-re-lwe digest: {h.hash(msg)}")


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"Pure Re-LWE Hash over Z_3329[x]/(x^{N}+x^{MID}+1), no external hash."
    )
    parser.add_argument(
        "text",
        nargs="?",
        help="text to hash; example: python3 emptytomb_module_ring_hash.py test",
    )
    parser.add_argument(
        "-f",
        "--file",
        metavar="PATH",
        help="hash a file's binary contents instead of the text argument",
    )
    parser.add_argument("-k", type=int, default=DEFAULT_K, help=f"module rank, default: {DEFAULT_K}")
    parser.add_argument("--rounds", type=int, default=DEFAULT_ROUNDS, help=f"rounds, default: {DEFAULT_ROUNDS}")
    parser.add_argument(
        "--output-bits",
        type=int,
        default=256,
        choices=(256, 512),
        help="digest size, default: 256",
    )
    return parser


def _main(argv: Sequence[str] | None = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        h = PureReLWEHash(k=args.k, rounds=args.rounds, output_bits=args.output_bits)
    except ValueError as exc:
        parser.error(str(exc))

    if args.file:
        try:
            print(h.hash_file(args.file))
        except FileNotFoundError:
            parser.exit(1, f"error: file not found: {args.file}\n")
        except PermissionError:
            parser.exit(1, f"error: permission denied: {args.file}\n")
        except IsADirectoryError:
            parser.exit(1, f"error: path is a directory, not a file: {args.file}\n")
        except OSError as exc:
            parser.exit(1, f"error: could not read file {args.file!r}: {exc}\n")
        return 0

    if args.text is not None:
        print(h.hash(args.text))
        return 0

    _self_test()
    _demo()
    return 0


if __name__ == "__main__":
    sys.exit(_main())
