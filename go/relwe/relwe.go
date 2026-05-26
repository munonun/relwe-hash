// Package relwe implements Pure Re-LWE Hash, a toy lattice/ARX hash.
//
// WARNING: This is a toy hash for educational/puzzle purposes only.
// Do not use for real security.
package relwe

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/bits"
	"os"
)

const (
	Q             = 3329
	N             = 256
	MID           = 128
	DefaultK      = 3
	DefaultRounds = 32
	DefaultOutput = 256
	DefaultEta    = 2
	XOFMaxOutput  = 1 << 38
	Warning       = "This is a toy hash for educational purposes only. Do not use for real security."
	mask32        = uint32(0xFFFFFFFF)
	hashDomain    = "RELWE-HASH-v1"
	xofDomain     = "RELWE-XOF-v1"
)

var primitiveRoot = primitiveRootMod(Q)
var invN = modInverse(N, Q)
var bitReverse = makeBitReverse()
var stageRoots = makeStageRoots(false)
var stageInvRoots = makeStageRoots(true)

// ReLWEHash is the main Re-LWE hash context.
type ReLWEHash struct {
	K          int
	Rounds     int
	OutputBits int
	Eta        int
}

// Config groups tunable Re-LWE parameters. Eta controls the toy
// small-error sampler; eta=2 preserves the original Go implementation's
// legacy error bound.
type Config struct {
	K          int
	Rounds     int
	OutputBits int
	Eta        int
}

// StateTraceRound exposes reduced internal state metrics for attack tooling.
// BWords/EWords/SeedWords are packed snapshots used to compute round-aligned
// deltas outside the package; they are not part of the hash output API.
type StateTraceRound struct {
	Round        int
	HWB          int
	HWE          int
	HWSeed       int
	CarryDensity float64
	Fingerprint  string
	BWords       []uint32
	EWords       []uint32
	SeedWords    []uint32
}

type digestCore struct {
	iv     []uint32
	seed   []uint32
	state  []ringPoly
	errVec []ringPoly
}

// Sum256 returns the v1.3 fixed 256-bit Re-LWE digest.
func Sum256(msg []byte) [32]byte {
	h := NewWithParams(DefaultK, DefaultRounds, DefaultOutput)
	out := h.sumBytes(msg, 32, hashDomain)
	var sum [32]byte
	copy(sum[:], out)
	return sum
}

// XOF expands msg into outLen bytes using the v1.3 Re-LWE XOF domain.
func XOF(msg []byte, outLen int) []byte {
	h := NewWithParams(DefaultK, DefaultRounds, DefaultOutput)
	return h.XOF(msg, outLen)
}

// New returns a configured pure recursive Re-LWE hash context.
func New(k, rounds, outputBits int) *ReLWEHash {
	return NewWithEta(k, rounds, outputBits, DefaultEta)
}

// NewWithEta returns a configured pure recursive Re-LWE hash context with an
// explicit toy LWE noise parameter eta.
func NewWithEta(k, rounds, outputBits, eta int) *ReLWEHash {
	return NewFromConfig(Config{
		K:          k,
		Rounds:     rounds,
		OutputBits: outputBits,
		Eta:        eta,
	})
}

// NewPureWithEta is kept as a source-compatible alias for NewWithEta.
func NewPureWithEta(k, rounds, outputBits, eta int) *ReLWEHash {
	return NewWithEta(k, rounds, outputBits, eta)
}

// NewPureWithParams is kept as a source-compatible alias for NewWithParams.
func NewPureWithParams(k, rounds, outputBits int) *ReLWEHash {
	return NewWithParams(k, rounds, outputBits)
}

func normalizeConfig(config Config) Config {
	k := config.K
	if k <= 0 {
		k = DefaultK
	}
	if k != DefaultK {
		panic("relwe: only k=3 is supported for Go/C compatible v1.3 APIs")
	}
	rounds := config.Rounds
	if rounds <= 0 {
		rounds = DefaultRounds
	}
	outputBits := config.OutputBits
	if outputBits != 256 && outputBits != 512 {
		outputBits = DefaultOutput
	}
	eta := config.Eta
	if eta <= 0 {
		eta = DefaultEta
	}
	return Config{
		K:          k,
		Rounds:     rounds,
		OutputBits: outputBits,
		Eta:        eta,
	}
}

// NewFromConfig returns a configured Re-LWE hash context.
func NewFromConfig(config Config) *ReLWEHash {
	config = normalizeConfig(config)
	return &ReLWEHash{
		K:          config.K,
		Rounds:     config.Rounds,
		OutputBits: config.OutputBits,
		Eta:        config.Eta,
	}
}

// NewWithParams returns a pure recursive Re-LWE hash using the default eta.
func NewWithParams(k, rounds, outputBits int) *ReLWEHash {
	return NewFromConfig(Config{
		K:          k,
		Rounds:     rounds,
		OutputBits: outputBits,
		Eta:        DefaultEta,
	})
}

// Hash hashes a UTF-8 Go string and returns a hex digest.
func (h *ReLWEHash) Hash(text string) string {
	return h.HashBytes([]byte(text))
}

// HashBytes hashes raw bytes and returns a hex digest.
func (h *ReLWEHash) HashBytes(message []byte) string {
	return hex.EncodeToString(h.sumBytes(message, h.OutputBits/8, hashDomain))
}

// HashFile hashes a file and returns a hex digest. It returns an empty string
// on read/stat errors; use HashFileE when the caller needs details.
func (h *ReLWEHash) HashFile(filepath string) string {
	digest, err := h.HashFileE(filepath)
	if err != nil {
		return ""
	}
	return digest
}

// HashFileE hashes a file by streaming it through the pure ARX absorber.
func (h *ReLWEHash) HashFileE(filepath string) (string, error) {
	info, err := os.Stat(filepath)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", errors.New("path is a directory")
	}

	f, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	absorber := newARXSponge(h.K, h.Rounds, h.OutputBits, h.Eta)
	absorber.update([]byte(hashDomain))
	buf := make([]byte, 1024*1024)
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			absorber.update(buf[:n])
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return "", readErr
		}
		if n == 0 {
			break
		}
	}

	return hex.EncodeToString(h.digestFromIVBytes(absorber.finalizeWords(), h.OutputBits/8, hashDomain)), nil
}

func (h *ReLWEHash) absorbBytes(message []byte) []uint32 {
	return h.absorbBytesWithDomain(message, hashDomain)
}

func (h *ReLWEHash) absorbBytesWithDomain(message []byte, domain string) []uint32 {
	absorber := newARXSponge(h.K, h.Rounds, h.OutputBits, h.Eta)
	absorber.update([]byte(domain))
	absorber.update(message)
	return absorber.finalizeWords()
}

func (h *ReLWEHash) sumBytes(message []byte, outLen int, domain string) []byte {
	return h.digestFromIVBytes(h.absorbBytesWithDomain(message, domain), outLen, domain)
}

// XOF expands raw bytes to an arbitrary-length v1.3 XOF output. The squeeze
// phase reuses the same ARX + modified Ring-LWE state as the fixed hash, with
// an independent domain tag and counter-driven ARX stream.
func (h *ReLWEHash) XOF(message []byte, outLen int) []byte {
	if outLen <= 0 {
		return []byte{}
	}
	if outLen > XOFMaxOutput {
		return nil
	}
	return h.sumBytes(message, outLen, xofDomain)
}

func (h *ReLWEHash) noiseBound() int {
	eta := h.Eta
	if eta <= 0 {
		eta = DefaultEta
	}
	// The original Pure Re-LWE Go code used bound=32 directly. Treat eta=2 as
	// that legacy point so existing hashes/tests keep their default behavior.
	return 16 * eta
}

func (h *ReLWEHash) initialState(iv []uint32) []ringPoly {
	state := make([]ringPoly, h.K)
	for i := 0; i < h.K; i++ {
		state[i] = uniformFromWords(iv, uint32(0x10000000)^uint32(i)*0x9E3779B1)
	}
	return state
}

func (h *ReLWEHash) initialError(iv []uint32) []ringPoly {
	errVec := make([]ringPoly, h.K)
	for i := 0; i < h.K; i++ {
		words := deriveWords(iv, uint32(0x20000000)^uint32(i)*0x85EBCA6B, N)
		errVec[i] = smallFromWords(words, h.noiseBound())
	}
	return errVec
}

func (h *ReLWEHash) stateFeedback(state, errVec []ringPoly, iv []uint32, round int) []uint32 {
	words := make([]uint32, 0, 16+6+(len(state)+len(errVec))*(N/2))
	words = append(words, first16(iv)...)
	words = append(words, uint32(round), uint32(h.K), uint32(h.Rounds), uint32(h.OutputBits), N, Q)
	for i := range state {
		words = append(words, state[i].toWords()...)
	}
	for i := range errVec {
		words = append(words, errVec[i].toWords()...)
	}
	return mixWordList(words, 0xFEE1DEAD^uint32(round), 6)
}

func (h *ReLWEHash) roundSalt(seed, feedback, iv []uint32, round int) []uint32 {
	material := make([]uint32, 0, 53)
	material = append(material, first16(iv)...)
	material = append(material, first16(seed)...)
	material = append(material, first16(feedback)...)
	material = append(material, uint32(round), uint32(round)*0x9E3779B1, uint32(h.K), Q, N)
	return mixWordList(material, 0x5A17C0DE^uint32(round), 10)
}

func (h *ReLWEHash) arxErrorWords(prevErr []ringPoly, seed, salt []uint32, prevState []ringPoly, laneCount int) []uint32 {
	prevCoeffs := make([]int, 0, len(prevErr)*N)
	stateCoeffs := make([]int, 0, len(prevState)*N)
	for i := range prevErr {
		prevCoeffs = append(prevCoeffs, prevErr[i].coeffs[:]...)
	}
	for i := range prevState {
		stateCoeffs = append(stateCoeffs, prevState[i].coeffs[:]...)
	}

	keyInput := make([]uint32, 0, 32)
	keyInput = append(keyInput, first16(seed)...)
	keyInput = append(keyInput, first16(salt)...)
	key := mixWordList(keyInput, 0xA11CE000^uint32(laneCount), 8)

	words := make([]uint32, laneCount)
	for lane := 0; lane < laneCount; lane++ {
		e := uint32(prevCoeffs[lane%len(prevCoeffs)])
		b := uint32(stateCoeffs[(lane*5+17)%len(stateCoeffs)])
		k0 := key[lane&15]
		k1 := key[(lane*7+3)&15]
		s0 := seed[(lane*3+1)&15]
		t0 := salt[(lane*5+9)&15]

		x := (e | (b << 16)) ^ k0 ^ (uint32(lane) * 0x9E3779B1)
		y := k1 + b*0x85EBCA6B + uint32(lane) + s0
		z := x ^ bits.RotateLeft32(y, 13) ^ t0 ^ 0xC2B2AE35

		for r := 0; r < 8; r++ {
			neighbor := salt[(r+lane)&15]
			if lane > 0 {
				neighbor = words[lane-1]
			}
			x += y + seed[(r*3+lane)&15]
			y = bits.RotateLeft32(y^z^neighbor, 5+((r+lane)%23))
			z += bits.RotateLeft32(x, 7) + salt[(r*5+lane)&15]
			x ^= bits.RotateLeft32(z, 16)
			y += bits.RotateLeft32(x^neighbor, 11)
		}
		words[lane] = x ^ y ^ z
	}
	return words
}

func (h *ReLWEHash) evolveError(prevErr []ringPoly, seed, salt []uint32, prevState []ringPoly) []ringPoly {
	words := h.arxErrorWords(prevErr, seed, salt, prevState, h.K*N)
	out := make([]ringPoly, h.K)
	for i := 0; i < h.K; i++ {
		out[i] = smallFromWords(words[i*N:(i+1)*N], h.noiseBound())
	}
	return out
}

func (h *ReLWEHash) evolveSeed(seed, salt []uint32, state, errVec []ringPoly, iv []uint32, round int) []uint32 {
	words := make([]uint32, 0, 16+16+16+4+(len(state)+len(errVec))*(N/8))
	words = append(words, first16(iv)...)
	words = append(words, first16(seed)...)
	words = append(words, first16(salt)...)
	words = append(words, uint32(round), uint32(h.K), uint32(h.Rounds), uint32(h.OutputBits))
	for i := range state {
		coeffs := state[i].coeffs
		for j := 0; j < N; j += 8 {
			words = append(words, uint32(coeffs[j])|uint32(coeffs[(j+3)%N])<<16|uint32(i)<<28)
		}
	}
	for i := range errVec {
		coeffs := errVec[i].coeffs
		for j := 1; j < N; j += 8 {
			words = append(words, uint32(coeffs[j])|uint32(coeffs[(j+5)%N])<<16|uint32(i)<<29)
		}
	}
	return mixWordList(words, 0x51ED0000^uint32(round), 10)
}

func (h *ReLWEHash) roundMatrix(seed, salt, iv []uint32, round int) [][]ringPoly {
	baseInput := make([]uint32, 0, 48)
	baseInput = append(baseInput, first16(iv)...)
	baseInput = append(baseInput, first16(seed)...)
	baseInput = append(baseInput, first16(salt)...)
	base := mixWordList(baseInput, 0xA7000000^uint32(round), 8)

	matrix := make([][]ringPoly, h.K)
	for i := 0; i < h.K; i++ {
		matrix[i] = make([]ringPoly, h.K)
		for j := 0; j < h.K; j++ {
			domain := uint32(0x30000000) ^ uint32(round)*0x9E3779B1 ^ uint32(i<<8) ^ uint32(j)
			matrix[i][j] = uniformFromWords(base, domain)
		}
	}
	return matrix
}

func (h *ReLWEHash) mixRound(state, errVec []ringPoly, seed, iv []uint32, round int) ([]ringPoly, []ringPoly, []uint32) {
	feedback := h.stateFeedback(state, errVec, iv, round)
	salt := h.roundSalt(seed, feedback, iv, round)
	nextErr := h.evolveError(errVec, seed, salt, state)
	matrix := h.roundMatrix(seed, salt, iv, round)
	scratch := newMulScratch()
	mixed := moduleMatVecMul(matrix, state, scratch)

	nextState := make([]ringPoly, h.K)
	for i := 0; i < h.K; i++ {
		tweak := state[i].mulWithScratch(state[(i+1)%h.K], scratch)
		nextState[i] = mixed[i].add(nextErr[i]).add(tweak)
	}

	nextSeed := h.evolveSeed(seed, salt, nextState, nextErr, iv, round)
	return nextState, nextErr, nextSeed
}

func (h *ReLWEHash) squeezeBytes(seed []uint32, state, errVec []ringPoly, iv []uint32, outLen int, domain string) []byte {
	if outLen <= 0 {
		return []byte{}
	}
	domainWords := bytesToWords([]byte(domain))
	words := make([]uint32, 0, len(domainWords)+16+16+5+len(state)*N+len(errVec)*(N/2))
	words = append(words, domainWords...)
	words = append(words, first16(iv)...)
	words = append(words, first16(seed)...)
	words = append(words, N, Q, uint32(h.K), uint32(h.Rounds), uint32(h.OutputBits))

	for polyIndex := range state {
		coeffs := state[polyIndex].coeffs
		stride := 73 + 2*polyIndex
		for t := 0; t < N; t++ {
			a := coeffs[(t*stride+17*polyIndex)&(N-1)]
			b := coeffs[(t*41+19+polyIndex)&(N-1)]
			words = append(words, uint32(a)|uint32(b)<<16|uint32(polyIndex&3)<<30)
		}
	}
	for polyIndex := range errVec {
		coeffs := errVec[polyIndex].coeffs
		stride := 89 + 2*polyIndex
		for t := 0; t < N; t += 2 {
			a := coeffs[(t*stride+29*polyIndex)&(N-1)]
			b := coeffs[(t*53+31+polyIndex)&(N-1)]
			words = append(words, uint32(a)|uint32(b)<<16|uint32(polyIndex&3)<<29)
		}
	}

	folded := mixWordList(words, 0xF1A1F01D^uint32(len(domain)), 16)
	stream := newARXStream(folded, 0xD16E5700^uint32(len(domain)))
	digestWords := stream.words((outLen + 3) / 4)
	for i := range digestWords {
		digestWords[i] ^= folded[i&15]
		digestWords[i] = bits.RotateLeft32(digestWords[i], 7+i) ^ folded[(i*5+3)&15]
	}
	return wordsToBytes(digestWords)[:outLen]
}

func (h *ReLWEHash) runDigestCore(iv []uint32) digestCore {
	state := h.initialState(iv)
	errVec := h.initialError(iv)
	seedInput := make([]uint32, 0, 19)
	seedInput = append(seedInput, first16(iv)...)
	seedInput = append(seedInput, uint32(h.K), uint32(h.Rounds), uint32(h.OutputBits))
	seed := mixWordList(seedInput, 0x5EED0001, 12)

	for r := 0; r < h.Rounds; r++ {
		state, errVec, seed = h.mixRound(state, errVec, seed, iv, r)
	}
	return digestCore{
		iv:     append([]uint32(nil), iv...),
		seed:   seed,
		state:  state,
		errVec: errVec,
	}
}

func (h *ReLWEHash) digestFromIVBytes(iv []uint32, outLen int, domain string) []byte {
	core := h.runDigestCore(iv)
	return h.squeezeBytes(core.seed, core.state, core.errVec, core.iv, outLen, domain)
}

func (h *ReLWEHash) digestFromIV(iv []uint32) string {
	return hex.EncodeToString(h.digestFromIVBytes(iv, h.OutputBits/8, hashDomain))
}

// TraceFingerprints returns one compact ARX fingerprint for the initial state
// and each subsequent round state. It is intended for attack experiments and
// cycle detection, not for production use.
func (h *ReLWEHash) TraceFingerprints(message []byte, maxRounds int) []string {
	if maxRounds < 0 {
		maxRounds = 0
	}
	iv := h.absorbBytes(message)
	state := h.initialState(iv)
	errVec := h.initialError(iv)
	seedInput := make([]uint32, 0, 19)
	seedInput = append(seedInput, first16(iv)...)
	seedInput = append(seedInput, uint32(h.K), uint32(h.Rounds), uint32(h.OutputBits))
	seed := mixWordList(seedInput, 0x5EED0001, 12)

	out := make([]string, 0, maxRounds+1)
	out = append(out, fingerprintState(iv, seed, state, errVec, 0))
	for r := 0; r < maxRounds; r++ {
		state, errVec, seed = h.mixRound(state, errVec, seed, iv, r)
		out = append(out, fingerprintState(iv, seed, state, errVec, r+1))
	}
	return out
}

// TraceStateMetrics returns round-by-round internal metrics for cryptanalysis
// harnesses. It includes round 0 before the first mix round.
func (h *ReLWEHash) TraceStateMetrics(message []byte, maxRounds int) []StateTraceRound {
	if maxRounds < 0 {
		maxRounds = 0
	}
	iv := h.absorbBytes(message)
	state := h.initialState(iv)
	errVec := h.initialError(iv)
	seedInput := make([]uint32, 0, 19)
	seedInput = append(seedInput, first16(iv)...)
	seedInput = append(seedInput, uint32(h.K), uint32(h.Rounds), uint32(h.OutputBits))
	seed := mixWordList(seedInput, 0x5EED0001, 12)

	out := make([]StateTraceRound, 0, maxRounds+1)
	out = append(out, h.stateTraceRound(iv, seed, state, errVec, 0))
	for r := 0; r < maxRounds; r++ {
		state, errVec, seed = h.mixRound(state, errVec, seed, iv, r)
		out = append(out, h.stateTraceRound(iv, seed, state, errVec, r+1))
	}
	return out
}

func (h *ReLWEHash) stateTraceRound(iv, seed []uint32, state, errVec []ringPoly, round int) StateTraceRound {
	bWords := packPolys(state)
	eWords := packPolys(errVec)
	seedWords := append([]uint32(nil), first16(seed)...)
	return StateTraceRound{
		Round:        round,
		HWB:          hammingWords(bWords),
		HWE:          hammingWords(eWords),
		HWSeed:       hammingWords(seedWords),
		CarryDensity: estimatedCarryDensity(seedWords, bWords, eWords, uint32(round), uint32(h.Eta)),
		Fingerprint:  sha256StateFingerprint(iv, seedWords, bWords, eWords, round, h.Eta),
		BWords:       bWords,
		EWords:       eWords,
		SeedWords:    seedWords,
	}
}

func packPolys(polys []ringPoly) []uint32 {
	words := make([]uint32, 0, len(polys)*(N/2))
	for i := range polys {
		words = append(words, polys[i].toWords()...)
	}
	return words
}

func hammingWords(words []uint32) int {
	total := 0
	for _, word := range words {
		total += bits.OnesCount32(word)
	}
	return total
}

func sha256StateFingerprint(iv, seedWords, bWords, eWords []uint32, round, eta int) string {
	d := sha256.New()
	var buf [4]byte
	writeWord := func(word uint32) {
		binary.LittleEndian.PutUint32(buf[:], word)
		_, _ = d.Write(buf[:])
	}
	writeWord(uint32(round))
	writeWord(uint32(eta))
	for _, word := range first16(iv) {
		writeWord(word)
	}
	for _, word := range seedWords {
		writeWord(word)
	}
	for _, word := range bWords {
		writeWord(word)
	}
	for _, word := range eWords {
		writeWord(word)
	}
	return hex.EncodeToString(d.Sum(nil))[:24]
}

func estimatedCarryDensity(seedWords, bWords, eWords []uint32, round, eta uint32) float64 {
	material := make([]uint32, 0, 2+len(seedWords)+min(32, len(bWords))+min(32, len(eWords)))
	material = append(material, round, eta)
	material = append(material, seedWords...)
	material = append(material, bWords[:min(32, len(bWords))]...)
	material = append(material, eWords[:min(32, len(eWords))]...)
	if len(material) < 2 {
		return 0
	}
	carries, positions := 0, 0
	for i := 0; i+1 < len(material); i++ {
		carries += carryCount32(material[i], material[i+1])
		positions += 32
	}
	if positions == 0 {
		return 0
	}
	// TODO: replace this estimator with direct instrumentation of every ARX ADD
	// once the round function exposes carry counters without perturbing speed.
	return float64(carries) / float64(positions)
}

func carryCount32(a, b uint32) int {
	count := 0
	carry := uint32(0)
	for bit := 0; bit < 32; bit++ {
		ai := (a >> bit) & 1
		bi := (b >> bit) & 1
		next := (ai & bi) | (carry & (ai ^ bi))
		if next != 0 {
			count++
		}
		carry = next
	}
	return count
}

func fingerprintState(iv, seed []uint32, state, errVec []ringPoly, round int) string {
	words := make([]uint32, 0, 16+16+1+(len(state)+len(errVec))*(N/2))
	words = append(words, first16(iv)...)
	words = append(words, first16(seed)...)
	words = append(words, uint32(round))
	for i := range state {
		words = append(words, state[i].toWords()...)
	}
	for i := range errVec {
		words = append(words, errVec[i].toWords()...)
	}
	folded := mixWordList(words, 0xC1C1E000^uint32(round), 10)
	return hex.EncodeToString(wordsToBytes(folded[:2]))
}

type arxSponge struct {
	state  [16]uint32
	length uint64
	buffer []byte
}

func newARXSponge(k, rounds, outputBits, eta int) *arxSponge {
	if eta <= 0 {
		eta = DefaultEta
	}
	etaDelta := uint32(eta - DefaultEta)
	return &arxSponge{
		state: [16]uint32{
			0x70757265,
			0x72656C77,
			0x65486173,
			0x68327632,
			N,
			Q,
			uint32(k),
			uint32(rounds),
			uint32(outputBits),
			0x243F6A88 ^ etaDelta*0x45D9F3B,
			0x85A308D3,
			0x13198A2E,
			0x03707344,
			0xA4093822,
			0x299F31D0,
			0x082EFA98,
		},
		buffer: make([]byte, 0, 64),
	}
}

func (s *arxSponge) update(data []byte) {
	if len(data) == 0 {
		return
	}
	s.length += uint64(len(data))
	s.buffer = append(s.buffer, data...)
	for len(s.buffer) >= 64 {
		block := make([]byte, 64)
		copy(block, s.buffer[:64])
		s.buffer = s.buffer[64:]
		s.absorbBlock(block, true)
	}
}

func (s *arxSponge) absorbBlock(block []byte, full bool) {
	words := bytesToWords(block)
	for len(words) < 16 {
		words = append(words, 0)
	}
	for i := 0; i < 16; i++ {
		lane := (i*5 + 3) & 15
		s.state[lane] ^= words[i]
		s.state[(lane+7)&15] += bits.RotateLeft32(words[i]^uint32(i), 3+(i&15))
	}
	if full {
		s.state[0] ^= uint32(len(block))
	} else {
		s.state[0] ^= 0x80000000 | uint32(len(block))
	}
	s.state[9] += uint32(s.length)
	s.state[13] ^= uint32(s.length >> 32)
	perm := arxPermute(s.state[:], 8)
	copy(s.state[:], perm)
}

func (s *arxSponge) finalizeWords() []uint32 {
	pad := make([]byte, len(s.buffer)+1)
	copy(pad, s.buffer)
	pad[len(pad)-1] = 0x80
	s.buffer = s.buffer[:0]
	s.absorbBlock(pad, false)
	s.state[1] ^= uint32(s.length)
	s.state[2] ^= uint32(s.length >> 32)
	s.state[14] ^= 0xFFFFFFFF
	perm := arxPermute(s.state[:], 16)
	copy(s.state[:], perm)
	return append([]uint32(nil), s.state[:]...)
}

type arxStream struct {
	state   []uint32
	counter uint32
}

func newARXStream(seedWords []uint32, domain uint32) *arxStream {
	base := first16(seedWords)
	base[0] ^= domain
	base[1] += domain * 0x9E3779B1
	base[7] ^= bits.RotateLeft32(domain, 13)
	return &arxStream{state: arxPermute(base, 12)}
}

func (s *arxStream) words(count int) []uint32 {
	out := make([]uint32, 0, count)
	for len(out) < count {
		block := append([]uint32(nil), s.state...)
		block[0] += s.counter
		block[3] ^= bits.RotateLeft32(s.counter, 17)
		block[12] += 0xD1B54A32 + s.counter*0x9E3779B1
		mixed := arxPermute(block, 10)
		for i := 0; i < 16; i++ {
			mixed[i] += s.state[(i+5)&15] + s.counter
		}
		s.state = arxPermute(mixed, 6)
		s.counter++
		out = append(out, mixed...)
	}
	return out[:count]
}

func deriveWords(seedWords []uint32, domain uint32, count int) []uint32 {
	return newARXStream(seedWords, domain).words(count)
}

func arxPermute(words []uint32, rounds int) []uint32 {
	state := first16(words)
	for r := 0; r < rounds; r++ {
		state[0] += 0x9E3779B9 + uint32(r)
		state[5] ^= bits.RotateLeft32(state[0], 3+(r&15))
		state[10] += bits.RotateLeft32(state[15], 11)
		state[15] ^= 0xA5A5A5A5 + 0x01010101*uint32(r)

		quarterRound(state, 0, 4, 8, 12)
		quarterRound(state, 1, 5, 9, 13)
		quarterRound(state, 2, 6, 10, 14)
		quarterRound(state, 3, 7, 11, 15)
		quarterRound(state, 0, 5, 10, 15)
		quarterRound(state, 1, 6, 11, 12)
		quarterRound(state, 2, 7, 8, 13)
		quarterRound(state, 3, 4, 9, 14)
	}
	return state
}

func quarterRound(state []uint32, a, b, c, d int) {
	state[a] += state[b]
	state[d] = bits.RotateLeft32(state[d]^state[a], 16)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], 12)
	state[a] += state[b]
	state[d] = bits.RotateLeft32(state[d]^state[a], 8)
	state[c] += state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], 7)
}

func mixWordList(words []uint32, extra uint32, rounds int) []uint32 {
	state := []uint32{
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
		extra,
	}
	for idx, word := range words {
		lane := idx & 15
		state[lane] += word + uint32(idx)*0x9E3779B1
		state[(lane+5)&15] ^= bits.RotateLeft32(word, (idx%23)+3)
		if lane == 15 {
			state = arxPermute(state, rounds)
		}
	}
	state[0] ^= uint32(len(words))
	state[8] ^= uint32(uint64(len(words)) >> 32)
	return arxPermute(state, rounds+6)
}

func first16(words []uint32) []uint32 {
	out := make([]uint32, 16)
	copy(out, words)
	if len(words) < 16 {
		for i := len(words); i < 16; i++ {
			out[i] = 0x9E3779B9 ^ uint32(i)*0x85EBCA6B
		}
	}
	return out
}

func bytesToWords(data []byte) []uint32 {
	if len(data) == 0 {
		return []uint32{0}
	}
	out := make([]uint32, 0, (len(data)+3)/4)
	for i := 0; i < len(data); i += 4 {
		var value uint32
		for j := 0; j < 4 && i+j < len(data); j++ {
			value |= uint32(data[i+j]) << (8 * j)
		}
		out = append(out, value)
	}
	return out
}

func wordsToBytes(words []uint32) []byte {
	out := make([]byte, 0, len(words)*4)
	for _, w := range words {
		out = append(out, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
	}
	return out
}

type ringPoly struct {
	coeffs [N]int
}

func zeroPoly() ringPoly { return ringPoly{} }

func uniformFromWords(seedWords []uint32, domain uint32) ringPoly {
	words := deriveWords(seedWords, domain, N)
	var p ringPoly
	for i := 0; i < N; i++ {
		p.coeffs[i] = int(words[i] % Q)
	}
	return p
}

func smallFromWords(words []uint32, bound int) ringPoly {
	width := 2*bound + 1
	var p ringPoly
	for i := 0; i < N; i++ {
		w := words[i%len(words)]
		mixed := int(w ^ bits.RotateLeft32(w, 7) ^ bits.RotateLeft32(w, 19) ^ (uint32(i) * 0x9E3779B1))
		p.coeffs[i] = modQ((mixed % width) - bound)
	}
	return p
}

func (p ringPoly) add(q ringPoly) ringPoly {
	var out ringPoly
	for i := 0; i < N; i++ {
		v := p.coeffs[i] + q.coeffs[i]
		if v >= Q {
			v -= Q
		}
		out.coeffs[i] = v
	}
	return out
}

func (p ringPoly) neg() ringPoly {
	var out ringPoly
	for i := 0; i < N; i++ {
		if p.coeffs[i] != 0 {
			out.coeffs[i] = Q - p.coeffs[i]
		}
	}
	return out
}

func (p ringPoly) mul(q ringPoly) ringPoly {
	return p.mulWithScratch(q, newMulScratch())
}

func (p ringPoly) toWords() []uint32 {
	out := make([]uint32, 0, N/2)
	for i := 0; i < N; i += 2 {
		out = append(out, uint32(p.coeffs[i])|uint32(p.coeffs[i+1])<<16)
	}
	return out
}

type mulScratch struct {
	fa   [N]int
	fb   [N]int
	p0   [2*MID - 1]int
	p2   [2*MID - 1]int
	psum [2*MID - 1]int
	aSum [MID]int
	bSum [MID]int
	tmp  [2*N - 1]int
}

func newMulScratch() *mulScratch {
	return &mulScratch{}
}

func (p ringPoly) mulWithScratch(q ringPoly, scratch *mulScratch) ringPoly {
	a0 := p.coeffs[:MID]
	a1 := p.coeffs[MID:]
	b0 := q.coeffs[:MID]
	b1 := q.coeffs[MID:]

	for i := 0; i < MID; i++ {
		v := a0[i] + a1[i]
		if v >= Q {
			v -= Q
		}
		scratch.aSum[i] = v
		v = b0[i] + b1[i]
		if v >= Q {
			v -= Q
		}
		scratch.bSum[i] = v
	}

	blockConvolution128Into(&scratch.p0, a0, b0, scratch)
	blockConvolution128Into(&scratch.p2, a1, b1, scratch)
	blockConvolution128Into(&scratch.psum, scratch.aSum[:], scratch.bSum[:], scratch)

	for i := 0; i < len(scratch.tmp); i++ {
		scratch.tmp[i] = 0
	}

	for i, v := range scratch.p0 {
		scratch.tmp[i] = v
	}
	for i := range scratch.psum {
		v := scratch.psum[i] - scratch.p0[i] - scratch.p2[i]
		scratch.tmp[i+MID] = addMod(scratch.tmp[i+MID], modQ(v))
	}
	for i, v := range scratch.p2 {
		scratch.tmp[i+N] = addMod(scratch.tmp[i+N], v)
	}
	for d := 2*N - 2; d >= N; d-- {
		c := scratch.tmp[d]
		if c != 0 {
			scratch.tmp[d] = 0
			scratch.tmp[d-MID] = subMod(scratch.tmp[d-MID], c)
			scratch.tmp[d-N] = subMod(scratch.tmp[d-N], c)
		}
	}

	var out ringPoly
	copy(out.coeffs[:], scratch.tmp[:N])
	return out
}

func moduleMatVecMul(matrix [][]ringPoly, vector []ringPoly, scratch *mulScratch) []ringPoly {
	out := make([]ringPoly, len(vector))
	for i := range vector {
		acc := zeroPoly()
		for j := range vector {
			acc = acc.add(matrix[i][j].mulWithScratch(vector[j], scratch))
		}
		out[i] = acc
	}
	return out
}

// NTT returns the forward Kyber-style 256-point NTT over Z_3329.
func NTT(values []int) []int {
	out := make([]int, len(values))
	for i, v := range values {
		out[i] = modQ(v)
	}
	nttInPlace(out, false)
	return out
}

// INTT returns the inverse Kyber-style NTT over Z_3329.
func INTT(values []int) []int {
	out := make([]int, len(values))
	for i, v := range values {
		out[i] = modQ(v)
	}
	nttInPlace(out, true)
	return out
}

func nttInPlace(values []int, invert bool) {
	if len(values) != N {
		panic("invalid NTT length")
	}

	for i := 1; i < N; i++ {
		j := bitReverse[i]
		if i < j {
			values[i], values[j] = values[j], values[i]
		}
	}

	stage := 0
	for length := 2; length <= N; length <<= 1 {
		wlen := stageRoots[stage]
		if invert {
			wlen = stageInvRoots[stage]
		}
		half := length >> 1
		for start := 0; start < N; start += length {
			w := 1
			for off := start; off < start+half; off++ {
				u := values[off]
				v := values[off+half] * w % Q
				sum := u + v
				if sum >= Q {
					sum -= Q
				}
				diff := u - v
				if diff < 0 {
					diff += Q
				}
				values[off] = sum
				values[off+half] = diff
				w = w * wlen % Q
			}
		}
		stage++
	}

	if invert {
		for i := range values {
			values[i] = values[i] * invN % Q
		}
	}
}

func cyclicConvolution256(a, b []int) []int {
	fa := make([]int, N)
	fb := make([]int, N)
	for i, v := range a {
		fa[i] = modQ(v)
	}
	for i, v := range b {
		fb[i] = modQ(v)
	}
	nttInPlace(fa, false)
	nttInPlace(fb, false)
	for i := 0; i < N; i++ {
		fa[i] = fa[i] * fb[i] % Q
	}
	nttInPlace(fa, true)
	return fa
}

func blockConvolution128(a, b []int) []int {
	if len(a) != MID || len(b) != MID {
		panic("block convolution expects 128 coefficient blocks")
	}
	return cyclicConvolution256(a, b)[:2*MID-1]
}

func blockConvolution128Into(out *[2*MID - 1]int, a, b []int, scratch *mulScratch) {
	for i := 0; i < N; i++ {
		scratch.fa[i] = 0
		scratch.fb[i] = 0
	}
	copy(scratch.fa[:MID], a)
	copy(scratch.fb[:MID], b)
	nttInPlace(scratch.fa[:], false)
	nttInPlace(scratch.fb[:], false)
	for i := 0; i < N; i++ {
		scratch.fa[i] = scratch.fa[i] * scratch.fb[i] % Q
	}
	nttInPlace(scratch.fa[:], true)
	copy(out[:], scratch.fa[:2*MID-1])
}

func primitiveRootMod(modulus int) int {
	factors := uniqueFactors(modulus - 1)
	for g := 2; g < modulus; g++ {
		ok := true
		for _, p := range factors {
			if modPow(g, (modulus-1)/p, modulus) == 1 {
				ok = false
				break
			}
		}
		if ok {
			return g
		}
	}
	panic("no primitive root")
}

func uniqueFactors(n int) []int {
	var factors []int
	for d := 2; d*d <= n; d++ {
		if n%d == 0 {
			factors = append(factors, d)
			for n%d == 0 {
				n /= d
			}
		}
	}
	if n > 1 {
		factors = append(factors, n)
	}
	return factors
}

func modPow(base, exp, mod int) int {
	result := 1
	base %= mod
	for exp > 0 {
		if exp&1 == 1 {
			result = result * base % mod
		}
		base = base * base % mod
		exp >>= 1
	}
	return result
}

func modInverse(x, mod int) int {
	return modPow(x, mod-2, mod)
}

func addMod(a, b int) int {
	v := a + b
	if v >= Q {
		v -= Q
	}
	return v
}

func subMod(a, b int) int {
	v := a - b
	if v < 0 {
		v += Q
	}
	return v
}

func modQ(x int) int {
	x %= Q
	if x < 0 {
		x += Q
	}
	return x
}

func makeBitReverse() [N]int {
	var out [N]int
	for i := 0; i < N; i++ {
		x := i
		rev := 0
		for bit := N >> 1; bit > 0; bit >>= 1 {
			rev = (rev << 1) | (x & 1)
			x >>= 1
		}
		out[i] = rev
	}
	return out
}

func makeStageRoots(invert bool) [8]int {
	var roots [8]int
	stage := 0
	for length := 2; length <= N; length <<= 1 {
		root := modPow(primitiveRoot, (Q-1)/length, Q)
		if invert {
			root = modInverse(root, Q)
		}
		roots[stage] = root
		stage++
	}
	return roots
}
