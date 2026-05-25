package main

import (
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"math"
	"math/bits"
	mrand "math/rand"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cryptography/relwe"
)

type collisionResult struct {
	attempts      int
	key           string
	digestA       string
	digestB       string
	msgA          []byte
	msgB          []byte
	fullCollision bool
}

type seenEntry struct {
	msg    []byte
	digest string
}

type workerRow struct {
	key    string
	msg    []byte
	digest string
}

var cliEta = relwe.DefaultEta

func newAttackHash(k, rounds, outputBits int) *relwe.ReLWEHash {
	return relwe.NewPureWithEta(k, rounds, outputBits, cliEta)
}

func main() {
	attacks := flag.String("attacks", "reduced,birthday,differential,random", "comma-separated attacks: reduced,birthday,differential,random,avalanche/stat-avalanche,linear,rotational,cycle,low-entropy,targeted-conditional,state-trace,state-evolution,state-rank,higher-order-state,degree-growth,walsh-bias,mutual-info,sat-smt,milp,algebraic,impossible,groebner")
	reducedRoundsText := flag.String("reduced-rounds", "4,8,12,16,24,32", "comma-separated reduced rounds")
	reducedAttempts := flag.Int("reduced-attempts", 100000, "birthday-style random attempts per reduced round")
	birthdayRoundsText := flag.String("birthday-rounds", "48", "comma-separated round counts for birthday attack, e.g. 24,48")
	birthdayAttempts := flag.Int("birthday-attempts", 200000, "birthday attack attempts per round count")
	randomRoundsText := flag.String("random-rounds", "8", "comma-separated round counts for random test, e.g. 12,16,20,24")
	randomAttempts := flag.Int("random-attempts", 1024, "random attempts")
	threads := flag.Int("threads", runtime.NumCPU(), "worker goroutines for parallel attacks")
	prefixBits := flag.Int("prefix-bits", 36, "digest prefix bits to compare")
	diffRoundsText := flag.String("differential-rounds", "4,8,12,16,24,32,48", "comma-separated round counts for differential search")
	diffTrials := flag.Int("differential-trials", 64, "trials per differential characteristic candidate")
	diffFlipsText := flag.String("differential-flips", "1,2,4,8", "comma-separated input bit flip counts")
	diffSearches := flag.Int("differential-searches", 128, "candidate characteristics to test per round/flip count")
	statAvalancheTrials := flag.Int("stat-avalanche-trials", 5000, "statistical avalanche trials")
	statAvalancheRounds := flag.Int("stat-avalanche-rounds", relwe.DefaultRounds, "rounds for statistical avalanche test")
	statAvalancheMinLen := flag.Int("stat-avalanche-min-len", 1, "minimum random message length")
	statAvalancheMaxLen := flag.Int("stat-avalanche-max-len", 96, "maximum random message length")
	statInputBits := flag.Int("stat-input-bits", 256, "input bit positions tracked for conditional avalanche statistics")
	histogramBinWidth := flag.Int("histogram-bin-width", 4, "Hamming-distance histogram bin width")
	linearRounds := flag.Int("linear-rounds", relwe.DefaultRounds, "rounds for linear approximation test")
	linearTrials := flag.Int("linear-trials", 5000, "messages per linear approximation test")
	linearMasks := flag.Int("linear-masks", 64, "random linear approximations to test")
	linearMessageLen := flag.Int("linear-message-len", 64, "message length for linear approximation test")
	rotationalTrials := flag.Int("rotational-trials", 2000, "random messages per rotational symmetry shift")
	rotationalRounds := flag.Int("rotational-rounds", relwe.DefaultRounds, "rounds for rotational symmetry test")
	rotationalShiftsText := flag.String("rotational-shifts", "1,7,13,31", "comma-separated bit rotations for rotational test")
	cycleMaxRounds := flag.Int("cycle-max-rounds", 512, "maximum rounds for state fingerprint cycle detection")
	lowEntropyRounds := flag.Int("low-entropy-rounds", relwe.DefaultRounds, "rounds for low-entropy input tests")
	targetedRounds := flag.Int("targeted-rounds", relwe.DefaultRounds, "rounds for targeted conditional avalanche")
	targetedSearches := flag.Int("targeted-searches", 512, "input/output bit pairs to search")
	targetedTrials := flag.Int("targeted-trials", 128, "trials per targeted input/output bit pair")
	satRounds := flag.Int("sat-rounds", 1, "rounds for SAT/SMT mini-core export")
	satMessageBits := flag.Int("sat-message-bits", 16, "symbolic message bits for SAT/SMT export")
	satOutputBits := flag.Int("sat-output-bits", 16, "truncated output bits for SAT/SMT export")
	satMode := flag.String("sat-mode", "preimage", "SAT/SMT mode: preimage, collision, differential")
	satTimeoutSec := flag.Int("sat-timeout-sec", 30, "solver timeout suggestion in seconds")
	satMiniCore := flag.Bool("sat-mini-core", true, "export reduced ARX mini-core constraints instead of full ring constraints")
	milpRoundsText := flag.String("milp-rounds", "1,2,4,8,12,16", "comma-separated mini-core rounds for MILP-style differential propagation")
	milpMessageBits := flag.Int("milp-message-bits", 16, "symbolic message bits for MILP-style mini-core")
	milpOutputBits := flag.Int("milp-output-bits", 16, "truncated output bits for MILP-style mini-core")
	milpTimeoutSec := flag.Int("milp-timeout-sec", 30, "solver timeout suggestion in seconds for exported/derived MILP cases")
	algebraicRoundsText := flag.String("algebraic-rounds", "1,2,4,8,12,16", "comma-separated mini-core rounds for algebraic degree propagation")
	algebraicMessageBits := flag.Int("algebraic-message-bits", 16, "symbolic message bits for algebraic mini-core")
	algebraicOutputBits := flag.Int("algebraic-output-bits", 16, "truncated output bits for algebraic mini-core")
	algebraicTimeoutSec := flag.Int("algebraic-timeout-sec", 30, "reserved timeout hint for future algebraic solvers")
	impossibleRoundsText := flag.String("impossible-rounds", "1,2,4", "comma-separated mini-core rounds for impossible differential SMT export")
	impossibleMessageBits := flag.Int("impossible-message-bits", 16, "symbolic message bits for impossible differential SMT export")
	impossibleOutputBits := flag.Int("impossible-output-bits", 16, "truncated output bits for impossible differential SMT export")
	impossibleTimeoutSec := flag.Int("impossible-timeout-sec", 30, "solver timeout suggestion in seconds for impossible differential cases")
	impossibleCandidates := flag.Int("impossible-candidates", 8, "low-weight/random differential candidates to export per round")
	groebnerRoundsText := flag.String("groebner-rounds", "1,2", "comma-separated tiny mini-core rounds for Sage/Groebner export")
	groebnerMessageBits := flag.Int("groebner-message-bits", 8, "symbolic message bits for Sage/Groebner mini-core")
	groebnerOutputBits := flag.Int("groebner-output-bits", 8, "truncated output bits constrained in Sage/Groebner export")
	groebnerTimeoutSec := flag.Int("groebner-timeout-sec", 30, "solver timeout hint printed in Sage/Groebner export")
	stateTraceRounds := flag.Int("state-trace-rounds", relwe.DefaultRounds, "rounds for internal state trace")
	stateTraceSamples := flag.Int("state-trace-samples", 256, "random samples for internal state trace")
	stateTraceMessageBits := flag.Int("state-trace-message-bits", 512, "random message bits for internal state trace")
	stateTraceOutput := flag.String("state-trace-output", "", "CSV output path for state trace; default out/state_trace/state_trace_eta<eta>.csv")
	stateTraceLowEntropy := flag.Bool("state-trace-low-entropy", true, "include low-entropy messages in state trace")
	stateEvolutionInput := flag.String("state-evolution-input", "", "state-trace CSV input; default out/state_trace/state_trace_eta<eta>.csv")
	stateEvolutionOutputDir := flag.String("state-evolution-output-dir", filepath.Join("out", "state_evolution"), "output directory for state evolution CSV/plots")
	stateEvolutionCompare := flag.String("state-evolution-compare", "", "comma-separated state-trace CSVs for eta overlay comparison")
	stateRankInput := flag.String("state-rank-input", "", "state-trace CSV input; default out/state_trace/state_trace_eta<eta>.csv")
	stateRankOutput := flag.String("state-rank-output", "", "state rank CSV output; default out/state_rank/state_rank_eta<eta>.csv")
	stateRankTarget := flag.String("state-rank-target", "all", "state rank target: all,b,e,seed,be,bseed,eseed")
	stateRankMaxRows := flag.Int("state-rank-max-rows", 4096, "maximum state rows per round for rank; 0 means all")
	stateRankCompare := flag.String("state-rank-compare", "", "comma-separated state-trace CSVs for rank comparison")
	hoOrder := flag.Int("ho-order", 2, "higher-order derivative order")
	hoRounds := flag.Int("ho-rounds", relwe.DefaultRounds, "rounds for higher-order state derivative")
	hoSamples := flag.Int("ho-samples", 128, "samples for higher-order state derivative")
	hoMessageBits := flag.Int("ho-message-bits", 512, "message bits for higher-order state derivative")
	hoTarget := flag.String("ho-target", "all", "higher-order state target: all,b,e,seed")
	hoCompare := flag.String("ho-compare", "", "comma-separated higher-order CSVs for eta comparison")
	degreeRounds := flag.Int("degree-rounds", 12, "rounds for degree growth estimate")
	degreeStateBits := flag.Int("degree-state-bits", 16, "mini-core state/input bits for degree growth")
	degreeSamples := flag.Int("degree-samples", 64, "reserved sample hint for degree growth")
	degreeCompare := flag.String("degree-compare", "", "comma-separated degree CSVs for eta comparison")
	walshRounds := flag.Int("walsh-rounds", relwe.DefaultRounds, "rounds for Walsh/Fourier bias search")
	walshSamples := flag.Int("walsh-samples", 100000, "samples for Walsh/Fourier bias search")
	walshOutputBits := flag.Int("walsh-output-bits", 8, "selected digest output bits for Walsh/Fourier bias search")
	walshMaxMaskWeight := flag.Int("walsh-max-mask-weight", 4, "maximum input mask weight for Walsh/Fourier bias search")
	walshFocusMasks := flag.String("walsh-focus-masks", "", "comma-separated focus masks, e.g. \"w3:[92,354,448],w1:[93]\"")
	walshProgress := flag.Bool("walsh-progress", false, "print progress while running focused Walsh verification")
	walshCompare := flag.String("walsh-compare", "", "comma-separated Walsh CSVs for eta comparison")
	miRounds := flag.Int("mi-rounds", relwe.DefaultRounds, "rounds for mutual information tracking")
	miSamples := flag.Int("mi-samples", 20000, "samples for mutual information tracking")
	miTarget := flag.String("mi-target", "seed", "mutual information target: all,b,e,seed,output")
	miCompare := flag.String("mi-compare", "", "comma-separated mutual information CSVs for eta comparison")
	messageLen := flag.Int("message-len", 32, "message length for differential test")
	k := flag.Int("k", relwe.DefaultK, "module rank")
	outputBits := flag.Int("output-bits", relwe.DefaultOutput, "digest size: 256 or 512")
	eta := flag.Int("eta", relwe.DefaultEta, "toy LWE noise parameter eta")
	flag.Parse()

	if *eta <= 0 {
		fmt.Fprintln(os.Stderr, "error: eta must be positive")
		os.Exit(2)
	}
	if *eta > 8 {
		fmt.Fprintf(os.Stderr, "warning: eta=%d is unusually large for this toy construction\n", *eta)
	}
	cliEta = *eta

	reducedRounds, err := parseRounds(*reducedRoundsText)
	must(err)
	birthdayRounds, err := parseRounds(*birthdayRoundsText)
	must(err)
	randomRounds, err := parseRounds(*randomRoundsText)
	must(err)
	diffRounds, err := parseRounds(*diffRoundsText)
	must(err)
	diffFlips, err := parseRounds(*diffFlipsText)
	must(err)
	rotationalShifts, err := parseRounds(*rotationalShiftsText)
	must(err)
	milpRounds, err := parseRounds(*milpRoundsText)
	must(err)
	algebraicRounds, err := parseRounds(*algebraicRoundsText)
	must(err)
	impossibleRounds, err := parseRounds(*impossibleRoundsText)
	must(err)
	groebnerRounds, err := parseRounds(*groebnerRoundsText)
	must(err)

	selected := parseAttackSet(*attacks)
	if *threads > 0 {
		runtime.GOMAXPROCS(*threads)
	}
	fmt.Println("Pure Re-LWE Hash Go attack experiments")
	fmt.Printf("k=%d, output_bits=%d, prefix_bits=%d, eta=%d\n", *k, *outputBits, *prefixBits, cliEta)
	fmt.Println("Note: prefix collisions are truncated-digest experiments, not full hash breaks.")

	if selected["reduced"] {
		reducedRoundCollisionSearch(reducedRounds, *reducedAttempts, *prefixBits, *threads, *k, *outputBits)
	}
	if selected["birthday"] {
		for _, r := range birthdayRounds {
			birthdayAttack(r, *birthdayAttempts, *prefixBits, *threads, *k, *outputBits)
		}
	}
	if selected["differential"] {
		differentialAvalancheTest(diffRounds, *diffTrials, diffFlips, *diffSearches, *threads, *k, *outputBits, *messageLen)
	}
	if selected["random"] {
		for _, r := range randomRounds {
			randomMessageTest(r, *randomAttempts, *threads, *prefixBits, *k, *outputBits)
		}
	}
	if selected["stat-avalanche"] {
		statisticalAvalancheTest(
			*statAvalancheTrials,
			*statAvalancheRounds,
			*k,
			*outputBits,
			*statAvalancheMinLen,
			*statAvalancheMaxLen,
			*histogramBinWidth,
			*statInputBits,
			*threads,
		)
	}
	if selected["linear"] {
		linearApproximationTest(*linearTrials, *linearRounds, *linearMasks, *linearMessageLen, *threads, *k, *outputBits)
	}
	if selected["rotational"] {
		rotationalSymmetryTest(*rotationalTrials, *rotationalRounds, rotationalShifts, *messageLen, *threads, *k, *outputBits)
	}
	if selected["cycle"] {
		cycleDetectionTest(*cycleMaxRounds, *threads, *k, *outputBits)
	}
	if selected["low-entropy"] {
		lowEntropyInputTest(*lowEntropyRounds, *threads, *k, *outputBits)
	}
	if selected["targeted-conditional"] {
		targetedConditionalAvalancheTest(*targetedRounds, *targetedSearches, *targetedTrials, *messageLen, *threads, *k, *outputBits)
	}
	if selected["state-trace"] {
		outPath := *stateTraceOutput
		if outPath == "" {
			outPath = filepath.Join("out", "state_trace", fmt.Sprintf("state_trace_eta%d.csv", cliEta))
		}
		stateTraceAttack(*stateTraceRounds, *stateTraceSamples, *stateTraceMessageBits, outPath, *stateTraceLowEntropy, *k, *outputBits)
	}
	if selected["state-evolution"] {
		inputPath := *stateEvolutionInput
		if inputPath == "" {
			inputPath = filepath.Join("out", "state_trace", fmt.Sprintf("state_trace_eta%d.csv", cliEta))
		}
		compareText := *stateEvolutionCompare
		if compareText == "" && flag.NArg() > 0 {
			compareText = flag.Arg(0)
		}
		stateEvolutionAttack(inputPath, *stateEvolutionOutputDir, compareText)
	}
	if selected["state-rank"] {
		inputPath := *stateRankInput
		if inputPath == "" {
			inputPath = filepath.Join("out", "state_trace", fmt.Sprintf("state_trace_eta%d.csv", cliEta))
		}
		outputPath := *stateRankOutput
		if outputPath == "" {
			outputPath = filepath.Join("out", "state_rank", fmt.Sprintf("state_rank_eta%d.csv", cliEta))
		}
		compareText := *stateRankCompare
		if compareText == "" && flag.NArg() > 0 {
			compareText = flag.Arg(0)
		}
		stateRankAttack(inputPath, outputPath, *stateRankTarget, *stateRankMaxRows, compareText)
	}
	if selected["higher-order-state"] {
		higherOrderStateAttack(*hoOrder, *hoRounds, *hoSamples, *hoMessageBits, *hoTarget, *hoCompare, *k, *outputBits)
	}
	if selected["degree-growth"] {
		degreeGrowthAttack(*degreeRounds, *degreeStateBits, *degreeSamples, *degreeCompare)
	}
	if selected["walsh-bias"] {
		walshBiasAttack(*walshRounds, *walshSamples, *walshOutputBits, *walshMaxMaskWeight, *walshFocusMasks, *walshCompare, *walshProgress, *threads, *k, *outputBits)
	}
	if selected["mutual-info"] {
		mutualInfoAttack(*miRounds, *miSamples, *miTarget, *miCompare, *threads, *k, *outputBits)
	}
	if selected["sat-smt"] {
		satSMTExport(*satRounds, *satMessageBits, *satOutputBits, *satMode, *satTimeoutSec, *satMiniCore)
	}
	if selected["milp"] {
		milpDifferentialHarness(milpRounds, *milpMessageBits, *milpOutputBits, *milpTimeoutSec)
	}
	if selected["algebraic"] {
		algebraicDegreeHarness(algebraicRounds, *algebraicMessageBits, *algebraicOutputBits, *algebraicTimeoutSec)
	}
	if selected["impossible"] {
		impossibleDifferentialExport(impossibleRounds, *impossibleMessageBits, *impossibleOutputBits, *impossibleTimeoutSec, *impossibleCandidates)
	}
	if selected["groebner"] {
		groebnerExport(groebnerRounds, *groebnerMessageBits, *groebnerOutputBits, *groebnerTimeoutSec)
	}
}

func reducedRoundCollisionSearch(rounds []int, attempts, prefixBits, threads, k, outputBits int) {
	fmt.Printf("\n== Strong reduced-round birthday collision search (eta=%d) ==\n", cliEta)
	for _, r := range rounds {
		prefixBirthdayAttack("reduced", r, attempts, prefixBits, threads, k, outputBits)
	}
}

func birthdayAttack(rounds, attempts, prefixBits, threads, k, outputBits int) {
	fmt.Printf("\n== Proper birthday attack on random messages (eta=%d) ==\n", cliEta)
	prefixBirthdayAttack("birthday", rounds, attempts, prefixBits, threads, k, outputBits)
}

func prefixBirthdayAttack(label string, rounds, attempts, prefixBits, threads, k, outputBits int) {
	if attempts <= 0 {
		fmt.Fprintf(os.Stderr, "error: %s attempts must be positive\n", label)
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}

	fmt.Printf("[%s rounds=%d] workers=%d, attempts=%d, prefix_bits=%d\n", label, rounds, threads, attempts, prefixBits)
	start := time.Now()

	var seen sync.Map
	var issued atomic.Int64
	var stop atomic.Bool
	resultCh := make(chan collisionResult, 1)
	doneCh := make(chan struct{})

	var wg sync.WaitGroup
	for workerID := 0; workerID < threads; workerID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			prefixBirthdayWorker(label, workerID, rounds, attempts, prefixBits, k, outputBits, &seen, &issued, &stop, resultCh)
		}(workerID)
	}

	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case result := <-resultCh:
		stop.Store(true)
		<-doneCh
		printCollision(result, fmt.Sprintf("%s rounds=%d", label, rounds), prefixBits)
		fmt.Printf("  elapsed:  %s\n", time.Since(start).Round(time.Millisecond))
	case <-doneCh:
		select {
		case result := <-resultCh:
			printCollision(result, fmt.Sprintf("%s rounds=%d", label, rounds), prefixBits)
			fmt.Printf("  elapsed:  %s\n", time.Since(start).Round(time.Millisecond))
		default:
			completed := int(issued.Load())
			if completed > attempts {
				completed = attempts
			}
			if label == "reduced" {
				fmt.Printf("No collision in %d attempts for rounds=%d (%s)\n", completed, rounds, time.Since(start).Round(time.Millisecond))
			} else {
				fmt.Printf("[%s rounds=%d] No collision in %d attempts (%s)\n", label, rounds, completed, time.Since(start).Round(time.Millisecond))
			}
		}
	}
}

func prefixBirthdayWorker(label string, workerID, rounds, attempts, prefixBits, k, outputBits int, seen *sync.Map, issued *atomic.Int64, stop *atomic.Bool, resultCh chan<- collisionResult) {
	h := newAttackHash(k, rounds, outputBits)
	labelMix := uint64(0)
	for i := 0; i < len(label); i++ {
		labelMix = labelMix*131 + uint64(label[i])
	}
	seed := int64(uint64(time.Now().UnixNano()) ^ (uint64(workerID+1) * 0x9E3779B97F4A7C15) ^ (uint64(rounds) * 0xD1B54A32D192ED03) ^ labelMix)
	rng := mrand.New(mrand.NewSource(seed))

	for !stop.Load() {
		attempt := issued.Add(1)
		if attempt > int64(attempts) {
			return
		}

		msg := randomBirthdayMessageFrom(rng)
		digest := h.HashBytes(msg)
		key := digestKey(digest, prefixBits)
		current := seenEntry{msg: msg, digest: digest}

		if previousAny, loaded := seen.LoadOrStore(key, current); loaded {
			previous := previousAny.(seenEntry)
			if bytes.Equal(previous.msg, msg) {
				continue
			}
			if stop.CompareAndSwap(false, true) {
				resultCh <- collisionResult{
					attempts:      int(attempt),
					key:           key,
					digestA:       previous.digest,
					digestB:       digest,
					msgA:          previous.msg,
					msgB:          msg,
					fullCollision: previous.digest == digest,
				}
			}
			return
		}
	}
}

func differentialAvalancheTest(rounds []int, trials int, flipCounts []int, searches, threads, k, outputBits, messageLen int) {
	fmt.Printf("\n== Reduced-round differential characteristic search (eta=%d) ==\n", cliEta)
	if trials <= 0 || messageLen <= 0 {
		fmt.Fprintln(os.Stderr, "error: differential-trials and message-len must be positive")
		os.Exit(2)
	}
	if searches <= 0 {
		fmt.Fprintln(os.Stderr, "error: differential-searches must be positive")
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	fmt.Printf("rounds=%s, flips=%s, candidates=%d per round/flip, trials=%d per candidate, workers=%d\n",
		formatInts(rounds), formatInts(flipCounts), searches, trials, threads)
	characteristicSearch(rounds, trials, flipCounts, searches, threads, k, outputBits, messageLen)
}

type characteristicResult struct {
	rounds    int
	flips     int
	positions []int
	mean      float64
	min       int
	max       int
}

func characteristicSearch(rounds []int, trials int, flipCounts []int, searches, threads, k, outputBits, messageLen int) {
	fmt.Println("\nBest low-weight differential characteristics:")
	if threads <= 0 {
		threads = 1
	}

	jobList := make([]characteristicResult, 0)
	jobRng := mrand.New(mrand.NewSource(0x43484152414354))
	for _, r := range rounds {
		for _, flipCount := range flipCounts {
			if flipCount <= 0 || flipCount > messageLen*8 {
				continue
			}
			for s := 0; s < searches; s++ {
				jobList = append(jobList, characteristicResult{
					rounds:    r,
					flips:     flipCount,
					positions: randomDistinctBits(jobRng, messageLen*8, flipCount),
				})
			}
		}
	}

	jobs := make(chan characteristicResult, threads)
	results := make(chan characteristicResult, threads)
	var wg sync.WaitGroup
	for workerID := 0; workerID < threads; workerID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			rng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ int64(workerID*0xA5A5A5A5)))
			for job := range jobs {
				h := newAttackHash(k, job.rounds, outputBits)
				minFlip, maxFlip, sum := outputBits, 0, 0
				for i := 0; i < trials; i++ {
					base := make([]byte, messageLen)
					rng.Read(base)
					modified := flipBits(base, job.positions)
					dist := hammingHex(h.HashBytes(base), h.HashBytes(modified))
					if dist < minFlip {
						minFlip = dist
					}
					if dist > maxFlip {
						maxFlip = dist
					}
					sum += dist
				}
				job.mean = float64(sum) / float64(trials)
				job.min = minFlip
				job.max = maxFlip
				results <- job
			}
		}(workerID)
	}

	go func() {
		for _, job := range jobList {
			jobs <- job
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	bestByKey := make(map[string]characteristicResult)
	for result := range results {
		key := fmt.Sprintf("%d/%d", result.rounds, result.flips)
		best, ok := bestByKey[key]
		if !ok || result.mean < best.mean {
			bestByKey[key] = result
		}
	}

	keys := make([]string, 0, len(bestByKey))
	for key := range bestByKey {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a := bestByKey[keys[i]]
		b := bestByKey[keys[j]]
		if a.rounds != b.rounds {
			return a.rounds < b.rounds
		}
		return a.flips < b.flips
	})

	fmt.Printf("tested characteristics: %d\n", len(jobList))
	fmt.Println("rounds | flips | candidates | trials | best mean | min | max | positions")
	fmt.Println("-------+-------+------------+--------+-----------+-----+-----+----------")
	for _, key := range keys {
		result := bestByKey[key]
		fmt.Printf("%6d | %5d | %10d | %6d | %9.2f | %3d | %3d | %s\n",
			result.rounds, result.flips, searches, trials, result.mean, result.min, result.max, formatPositions(result.positions, 10))
		if result.mean < 110.0 {
			fmt.Println("  Potential weak differential characteristic found")
		}
	}
}

type statAvalanchePartial struct {
	distances        []int
	outputFlipCounts []int
	inputTrials      []int
	inputOutputFlips []int
}

type rankedBitBias struct {
	index int
	prob  float64
	dev   float64
}

type rankedPairBias struct {
	inputBit  int
	outputBit int
	trials    int
	prob      float64
	z         float64
}

func statisticalAvalancheTest(trials, rounds, k, outputBits, minMessageLen, maxMessageLen, histogramBinWidth, trackedInputBits, threads int) {
	fmt.Printf("\n== Statistical avalanche test (eta=%d) ==\n", cliEta)
	if trials <= 0 {
		fmt.Fprintln(os.Stderr, "error: stat-avalanche-trials must be positive")
		os.Exit(2)
	}
	if outputBits != 256 && outputBits != 512 {
		fmt.Fprintln(os.Stderr, "error: stat-avalanche expects 256-bit or 512-bit output")
		os.Exit(2)
	}
	if minMessageLen <= 0 || maxMessageLen < minMessageLen {
		fmt.Fprintln(os.Stderr, "error: invalid stat-avalanche message length range")
		os.Exit(2)
	}
	if histogramBinWidth <= 0 {
		fmt.Fprintln(os.Stderr, "error: histogram-bin-width must be positive")
		os.Exit(2)
	}
	if trackedInputBits <= 0 {
		trackedInputBits = minMessageLen * 8
	}
	if trackedInputBits > maxMessageLen*8 {
		trackedInputBits = maxMessageLen * 8
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}

	distances := make([]int, 0, trials)
	outputFlipCounts := make([]int, outputBits)
	inputTrials := make([]int, trackedInputBits)
	inputOutputFlips := make([]int, trackedInputBits*outputBits)
	start := time.Now()

	perWorker := splitWork(trials, threads)
	partials := make(chan statAvalanchePartial, threads)
	var wg sync.WaitGroup
	for workerID, count := range perWorker {
		if count == 0 {
			continue
		}
		wg.Add(1)
		go func(workerID, count int) {
			defer wg.Done()
			partials <- statAvalancheWorker(workerID, count, rounds, k, outputBits, minMessageLen, maxMessageLen, trackedInputBits)
		}(workerID, count)
	}

	go func() {
		wg.Wait()
		close(partials)
	}()

	for partial := range partials {
		distances = append(distances, partial.distances...)
		for i, v := range partial.outputFlipCounts {
			outputFlipCounts[i] += v
		}
		for i, v := range partial.inputTrials {
			inputTrials[i] += v
		}
		for i, v := range partial.inputOutputFlips {
			inputOutputFlips[i] += v
		}
	}

	mean, stdev, minDist, maxDist := distanceStats(distances)
	lo := int(float64(outputBits) * 0.45)
	hi := int(float64(outputBits) * 0.55)
	inBand := 0
	for _, d := range distances {
		if lo <= d && d <= hi {
			inBand++
		}
	}
	inBandRatio := float64(inBand) / float64(trials)
	meanPct := 100.0 * mean / float64(outputBits)
	quality := avalancheQuality(meanPct, stdev, inBandRatio)

	fmt.Printf("rounds: %d, k: %d, trials: %d, output_bits: %d\n", rounds, k, trials, outputBits)
	fmt.Printf("mean: %.3f bits (%.3f%%)\n", mean, meanPct)
	fmt.Printf("stddev: %.3f bits\n", stdev)
	fmt.Printf("min: %d bits\n", minDist)
	fmt.Printf("max: %d bits\n", maxDist)
	fmt.Printf("45~55%% range: %d..%d changed bits\n", lo, hi)
	fmt.Printf("45~55%% ratio: %.2f%%\n", inBandRatio*100)
	fmt.Printf("Avalanche quality: %s\n", quality)
	fmt.Printf("elapsed: %s\n", time.Since(start).Round(time.Millisecond))
	fmt.Println("\nDistribution histogram:")
	printHistogram(distances, histogramBinWidth, 48)
	printBitIndependenceStats(outputFlipCounts, len(distances))
	printInputOutputDependenceStats(inputTrials, inputOutputFlips, outputBits)
}

func statAvalancheWorker(workerID, trials, rounds, k, outputBits, minMessageLen, maxMessageLen, trackedInputBits int) statAvalanchePartial {
	h := newAttackHash(k, rounds, outputBits)
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ int64(workerID*0x53544154+0x4156)))
	partial := statAvalanchePartial{
		distances:        make([]int, 0, trials),
		outputFlipCounts: make([]int, outputBits),
		inputTrials:      make([]int, trackedInputBits),
		inputOutputFlips: make([]int, trackedInputBits*outputBits),
	}

	for i := 0; i < trials; i++ {
		msgLen := minMessageLen + rng.Intn(maxMessageLen-minMessageLen+1)
		minLenForTracking := (trackedInputBits + 7) / 8
		if msgLen < minLenForTracking {
			msgLen = minLenForTracking
		}
		if msgLen > maxMessageLen {
			msgLen = maxMessageLen
		}
		message := make([]byte, msgLen)
		rng.Read(message)
		effectiveInputBits := min(trackedInputBits, msgLen*8)
		bitIndex := rng.Intn(effectiveInputBits)
		modified := flipOneBit(message, bitIndex)

		digestA, _ := hex.DecodeString(h.HashBytes(message))
		digestB, _ := hex.DecodeString(h.HashBytes(modified))
		dist := 0
		partial.inputTrials[bitIndex]++
		for outBit := 0; outBit < outputBits; outBit++ {
			byteIndex := outBit / 8
			mask := byte(1 << (outBit % 8))
			flipped := (digestA[byteIndex] ^ digestB[byteIndex]) & mask
			if flipped != 0 {
				dist++
				partial.outputFlipCounts[outBit]++
				partial.inputOutputFlips[bitIndex*outputBits+outBit]++
			}
		}
		partial.distances = append(partial.distances, dist)
	}
	return partial
}

func printBitIndependenceStats(outputFlipCounts []int, trials int) {
	fmt.Println("\nBit independence test:")
	if trials == 0 {
		return
	}
	ranked := make([]rankedBitBias, 0, len(outputFlipCounts))
	sumDev := 0.0
	maxDev := 0.0
	minProb, maxProb := 1.0, 0.0
	for bitIndex, count := range outputFlipCounts {
		prob := float64(count) / float64(trials)
		dev := math.Abs(prob - 0.5)
		sumDev += dev
		if dev > maxDev {
			maxDev = dev
		}
		if prob < minProb {
			minProb = prob
		}
		if prob > maxProb {
			maxProb = prob
		}
		ranked = append(ranked, rankedBitBias{index: bitIndex, prob: prob, dev: dev})
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].dev > ranked[j].dev })
	fmt.Printf("output flip probability range: %.4f..%.4f\n", minProb, maxProb)
	fmt.Printf("mean absolute bias from 0.5: %.4f\n", sumDev/float64(len(outputFlipCounts)))
	fmt.Printf("max absolute bias from 0.5: %.4f\n", maxDev)
	fmt.Println("worst output bits:")
	for i := 0; i < min(8, len(ranked)); i++ {
		fmt.Printf("  out_bit=%3d flip_prob=%.4f bias=%+.4f\n", ranked[i].index, ranked[i].prob, ranked[i].prob-0.5)
	}
	if maxDev > 0.05 {
		fmt.Println("Potential weakness warning: output bit flip probability deviates from 50% by more than 5 percentage points")
	}
}

func printInputOutputDependenceStats(inputTrials, inputOutputFlips []int, outputBits int) {
	fmt.Println("\nInput/output bit dependence test:")
	ranked := make([]rankedPairBias, 0)
	for inBit, n := range inputTrials {
		if n < 16 {
			continue
		}
		sigma := math.Sqrt(0.25 / float64(n))
		for outBit := 0; outBit < outputBits; outBit++ {
			prob := float64(inputOutputFlips[inBit*outputBits+outBit]) / float64(n)
			z := math.Abs(prob-0.5) / sigma
			ranked = append(ranked, rankedPairBias{inputBit: inBit, outputBit: outBit, trials: n, prob: prob, z: z})
		}
	}
	if len(ranked) == 0 {
		fmt.Println("not enough per-input-bit samples; increase --stat-avalanche-trials or reduce --stat-input-bits")
		return
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].z > ranked[j].z })
	fmt.Println("highest conditional deviations P(output bit flips | input bit flipped):")
	for i := 0; i < min(10, len(ranked)); i++ {
		row := ranked[i]
		fmt.Printf("  in_bit=%3d out_bit=%3d n=%4d prob=%.4f z=%.2f\n", row.inputBit, row.outputBit, row.trials, row.prob, row.z)
	}
	if ranked[0].z > 6.0 {
		fmt.Println("Potential weakness warning: strong input/output conditional avalanche bias candidate")
	}
}

type linearMask struct {
	inputBits  []int
	outputBits []int
}

type linearResult struct {
	index int
	mask  linearMask
	ones  int
	bias  float64
}

func linearApproximationTest(trials, rounds, maskCount, messageLen, threads, k, outputBits int) {
	fmt.Printf("\n== Linear approximation bias test (eta=%d) ==\n", cliEta)
	if trials <= 0 || maskCount <= 0 || messageLen <= 0 {
		fmt.Fprintln(os.Stderr, "error: linear-trials, linear-masks, and linear-message-len must be positive")
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	masks := makeLinearMasks(maskCount, messageLen*8, outputBits)
	perWorker := splitWork(trials, threads)
	countsCh := make(chan []int, threads)
	var wg sync.WaitGroup
	start := time.Now()

	for workerID, count := range perWorker {
		if count == 0 {
			continue
		}
		wg.Add(1)
		go func(workerID, count int) {
			defer wg.Done()
			countsCh <- linearWorker(workerID, count, rounds, k, outputBits, messageLen, masks)
		}(workerID, count)
	}
	go func() {
		wg.Wait()
		close(countsCh)
	}()

	ones := make([]int, len(masks))
	for partial := range countsCh {
		for i, v := range partial {
			ones[i] += v
		}
	}

	results := make([]linearResult, len(masks))
	meanBias := 0.0
	for i, count := range ones {
		p := float64(count) / float64(trials)
		bias := math.Abs(p - 0.5)
		meanBias += bias
		results[i] = linearResult{index: i, mask: masks[i], ones: count, bias: bias}
	}
	meanBias /= float64(len(results))
	sort.Slice(results, func(i, j int) bool { return results[i].bias > results[j].bias })

	expectedSigma := math.Sqrt(0.25 / float64(trials))
	fmt.Printf("rounds=%d, k=%d, trials=%d, masks=%d, message_bits=%d, output_bits=%d\n", rounds, k, trials, maskCount, messageLen*8, outputBits)
	fmt.Printf("mean absolute linear bias: %.5f\n", meanBias)
	fmt.Printf("max absolute linear bias: %.5f (%.2f sigma)\n", results[0].bias, results[0].bias/expectedSigma)
	fmt.Println("top biased approximations:")
	for i := 0; i < min(10, len(results)); i++ {
		result := results[i]
		p := float64(result.ones) / float64(trials)
		fmt.Printf("  mask=%3d prob=%.5f bias=%+.5f input=%s output=%s\n",
			result.index, p, p-0.5, formatPositions(result.mask.inputBits, 8), formatPositions(result.mask.outputBits, 8))
	}
	if results[0].bias/expectedSigma > 6.0 {
		fmt.Println("Potential weakness warning: high-sigma linear approximation bias candidate")
	}
	fmt.Printf("elapsed: %s\n", time.Since(start).Round(time.Millisecond))
}

func makeLinearMasks(maskCount, inputBits, outputBits int) []linearMask {
	rng := mrand.New(mrand.NewSource(0x4C494E454152))
	masks := make([]linearMask, maskCount)
	for i := 0; i < maskCount; i++ {
		inputWeight := 1 + rng.Intn(4)
		outputWeight := 1 + rng.Intn(4)
		masks[i] = linearMask{
			inputBits:  randomDistinctBits(rng, inputBits, inputWeight),
			outputBits: randomDistinctBits(rng, outputBits, outputWeight),
		}
	}
	return masks
}

func linearWorker(workerID, trials, rounds, k, outputBits, messageLen int, masks []linearMask) []int {
	h := newAttackHash(k, rounds, outputBits)
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ int64(workerID*0x1F123BB5)))
	ones := make([]int, len(masks))
	for i := 0; i < trials; i++ {
		message := make([]byte, messageLen)
		rng.Read(message)
		digest, _ := hex.DecodeString(h.HashBytes(message))
		for maskIndex, mask := range masks {
			v := parityAtPositions(message, mask.inputBits) ^ parityAtPositions(digest, mask.outputBits)
			if v == 1 {
				ones[maskIndex]++
			}
		}
	}
	return ones
}

type rotationalPartial struct {
	shift       int
	count       int
	relationSum int
	directSum   int
	minRelation int
	maxRelation int
}

func rotationalSymmetryTest(trials, rounds int, shifts []int, messageLen, threads, k, outputBits int) {
	fmt.Printf("\n== Rotational symmetry test (eta=%d) ==\n", cliEta)
	if trials <= 0 || messageLen <= 0 {
		fmt.Fprintln(os.Stderr, "error: rotational-trials and message-len must be positive")
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	fmt.Println("shift | trials | mean relation dist | min | max | mean direct dist | warning")
	fmt.Println("------+--------+--------------------+-----+-----+------------------+--------")
	for _, shift := range shifts {
		perWorker := splitWork(trials, threads)
		ch := make(chan rotationalPartial, threads)
		var wg sync.WaitGroup
		for workerID, count := range perWorker {
			if count == 0 {
				continue
			}
			wg.Add(1)
			go func(workerID, count int) {
				defer wg.Done()
				ch <- rotationalWorker(workerID, count, rounds, shift, messageLen, k, outputBits)
			}(workerID, count)
		}
		go func() {
			wg.Wait()
			close(ch)
		}()

		total := rotationalPartial{shift: shift, minRelation: outputBits}
		for part := range ch {
			total.count += part.count
			total.relationSum += part.relationSum
			total.directSum += part.directSum
			if part.minRelation < total.minRelation {
				total.minRelation = part.minRelation
			}
			if part.maxRelation > total.maxRelation {
				total.maxRelation = part.maxRelation
			}
		}
		meanRelation := float64(total.relationSum) / float64(total.count)
		meanDirect := float64(total.directSum) / float64(total.count)
		warning := ""
		if meanRelation < float64(outputBits)*0.43 {
			warning = "Potential rotational relation"
		}
		fmt.Printf("%5d | %6d | %18.2f | %3d | %3d | %16.2f | %s\n",
			shift, total.count, meanRelation, total.minRelation, total.maxRelation, meanDirect, warning)
	}
}

func rotationalWorker(workerID, trials, rounds, shift, messageLen, k, outputBits int) rotationalPartial {
	h := newAttackHash(k, rounds, outputBits)
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ int64(workerID*0x52544C)))
	out := rotationalPartial{shift: shift, count: trials, minRelation: outputBits}
	for i := 0; i < trials; i++ {
		msg := make([]byte, messageLen)
		rng.Read(msg)
		rotMsg := rotateBits(msg, shift)
		digestA, _ := hex.DecodeString(h.HashBytes(msg))
		digestB, _ := hex.DecodeString(h.HashBytes(rotMsg))
		rotDigestA := rotateBits(digestA, shift)
		relation := hammingBytes(rotDigestA, digestB)
		direct := hammingBytes(digestA, digestB)
		out.relationSum += relation
		out.directSum += direct
		if relation < out.minRelation {
			out.minRelation = relation
		}
		if relation > out.maxRelation {
			out.maxRelation = relation
		}
	}
	return out
}

type cycleResult struct {
	msg     []byte
	found   bool
	first   int
	second  int
	fp      string
	checked int
}

func cycleDetectionTest(maxRounds, threads, k, outputBits int) {
	fmt.Printf("\n== Full-state fingerprint cycle detection (eta=%d) ==\n", cliEta)
	if maxRounds <= 0 {
		fmt.Fprintln(os.Stderr, "error: cycle-max-rounds must be positive")
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	messages := lowEntropyMessages()
	jobs := make(chan []byte, len(messages))
	results := make(chan cycleResult, len(messages))
	var wg sync.WaitGroup
	for workerID := 0; workerID < min(threads, len(messages)); workerID++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for msg := range jobs {
				results <- cycleWorker(msg, maxRounds, k, outputBits)
			}
		}()
	}
	for _, msg := range messages {
		jobs <- msg
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	foundAny := false
	for result := range results {
		if result.found {
			foundAny = true
			fmt.Printf("Potential cycle found: msg=%s first_round=%d repeat_round=%d fp=%s\n",
				hex.EncodeToString(result.msg), result.first, result.second, result.fp)
		} else {
			fmt.Printf("No cycle in %d fingerprints for msg=%s\n", result.checked, hex.EncodeToString(result.msg))
		}
	}
	if !foundAny {
		fmt.Println("No repeated full-state fingerprints detected.")
	}
}

func cycleWorker(msg []byte, maxRounds, k, outputBits int) cycleResult {
	h := newAttackHash(k, maxRounds, outputBits)
	fps := h.TraceFingerprints(msg, maxRounds)
	seen := make(map[string]int, len(fps))
	for round, fp := range fps {
		if first, ok := seen[fp]; ok {
			return cycleResult{msg: msg, found: true, first: first, second: round, fp: fp, checked: len(fps)}
		}
		seen[fp] = round
	}
	return cycleResult{msg: msg, checked: len(fps)}
}

type lowEntropyResult struct {
	name       string
	message    []byte
	digest     string
	onesRatio  float64
	longestRun int
	chiSquare  float64
}

func lowEntropyInputTest(rounds, threads, k, outputBits int) {
	fmt.Printf("\n== Low-entropy input structure test (eta=%d) ==\n", cliEta)
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	cases := namedLowEntropyMessages()
	jobs := make(chan lowEntropyResult, len(cases))
	results := make(chan lowEntropyResult, len(cases))
	var wg sync.WaitGroup
	for workerID := 0; workerID < min(threads, len(cases)); workerID++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h := newAttackHash(k, rounds, outputBits)
			for job := range jobs {
				digest := h.HashBytes(job.message)
				digestBytes, _ := hex.DecodeString(digest)
				job.digest = digest
				job.onesRatio = bitOnesRatio(digestBytes)
				job.longestRun = longestBitRun(digestBytes)
				job.chiSquare = byteChiSquare(digestBytes)
				results <- job
			}
		}()
	}
	for _, c := range cases {
		jobs <- c
	}
	close(jobs)
	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Println("case | len | ones ratio | longest run | byte chi2 | digest prefix | warning")
	fmt.Println("-----+-----+------------+-------------+-----------+---------------+--------")
	for result := range results {
		warning := ""
		if result.onesRatio < 0.42 || result.onesRatio > 0.58 || result.longestRun > 32 || result.chiSquare > 420 {
			warning = "Potential structured output"
		}
		fmt.Printf("%s | %3d | %.4f | %11d | %9.2f | %s | %s\n",
			result.name, len(result.message), result.onesRatio, result.longestRun, result.chiSquare, result.digest[:min(16, len(result.digest))], warning)
	}
}

type targetedJob struct {
	inputBit  int
	outputBit int
}

type targetedResult struct {
	inputBit  int
	outputBit int
	trials    int
	prob      float64
	z         float64
}

func targetedConditionalAvalancheTest(rounds, searches, trials, messageLen, threads, k, outputBits int) {
	fmt.Printf("\n== Targeted conditional avalanche search (eta=%d) ==\n", cliEta)
	if searches <= 0 || trials <= 0 || messageLen <= 0 {
		fmt.Fprintln(os.Stderr, "error: targeted-searches, targeted-trials, and message-len must be positive")
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}

	rng := mrand.New(mrand.NewSource(0x544152474554))
	jobs := make(chan targetedJob, threads)
	results := make(chan targetedResult, threads)
	var wg sync.WaitGroup
	for workerID := 0; workerID < threads; workerID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			h := newAttackHash(k, rounds, outputBits)
			localRng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ int64(workerID*0x5443)))
			for job := range jobs {
				results <- targetedWorker(h, localRng, job, trials, messageLen)
			}
		}(workerID)
	}
	go func() {
		for i := 0; i < searches; i++ {
			jobs <- targetedJob{
				inputBit:  rng.Intn(messageLen * 8),
				outputBit: rng.Intn(outputBits),
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	var ranked []targetedResult
	for result := range results {
		ranked = append(ranked, result)
	}
	sort.Slice(ranked, func(i, j int) bool { return ranked[i].z > ranked[j].z })

	fmt.Printf("rounds=%d searches=%d trials=%d message_bits=%d output_bits=%d\n", rounds, searches, trials, messageLen*8, outputBits)
	fmt.Println("input bit | output bit | flip prob | z-score | warning")
	fmt.Println("----------+------------+-----------+---------+--------")
	for i := 0; i < min(12, len(ranked)); i++ {
		result := ranked[i]
		warning := ""
		if result.z > 6.0 || (result.trials >= 64 && (result.prob < 0.30 || result.prob > 0.70)) {
			warning = "Potential conditional weakness"
		}
		fmt.Printf("%9d | %10d | %.4f | %7.2f | %s\n",
			result.inputBit, result.outputBit, result.prob, result.z, warning)
	}
}

func targetedWorker(h *relwe.ReLWEHash, rng *mrand.Rand, job targetedJob, trials, messageLen int) targetedResult {
	flips := 0
	for i := 0; i < trials; i++ {
		msg := make([]byte, messageLen)
		rng.Read(msg)
		modified := flipOneBit(msg, job.inputBit)
		digestA, _ := hex.DecodeString(h.HashBytes(msg))
		digestB, _ := hex.DecodeString(h.HashBytes(modified))
		mask := byte(1 << (job.outputBit % 8))
		if ((digestA[job.outputBit/8] ^ digestB[job.outputBit/8]) & mask) != 0 {
			flips++
		}
	}
	prob := float64(flips) / float64(trials)
	sigma := math.Sqrt(0.25 / float64(trials))
	return targetedResult{
		inputBit:  job.inputBit,
		outputBit: job.outputBit,
		trials:    trials,
		prob:      prob,
		z:         math.Abs(prob-0.5) / sigma,
	}
}

type stateTraceSample struct {
	name    string
	message []byte
	flipBit int
}

type stateTraceSummary struct {
	totalRows            int
	finalCount           int
	finalDeltaBSum       int
	finalDeltaESum       int
	finalDeltaSeedSum    int
	finalDeltaBMin       int
	finalDeltaBMax       int
	finalDeltaEMin       int
	finalDeltaEMax       int
	finalDeltaSeedMin    int
	finalDeltaSeedMax    int
	carrySum             float64
	carryCount           int
	repeatedFingerprints int
	fingerprintSeen      map[string]int
}

func stateTraceAttack(rounds, samples, messageBits int, outputPath string, includeLowEntropy bool, k, outputBits int) {
	fmt.Printf("\n== Round state trace attack (eta=%d) ==\n", cliEta)
	if rounds <= 0 || samples < 0 || messageBits <= 0 {
		fmt.Fprintln(os.Stderr, "error: state-trace-rounds and state-trace-message-bits must be positive; samples must be non-negative")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create state trace directory: %v\n", err)
		os.Exit(1)
	}
	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outputPath, err)
		os.Exit(1)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	header := []string{
		"sample_id",
		"round",
		"eta",
		"message_type",
		"flip_bit",
		"hw_b",
		"hw_e",
		"hw_seed",
		"delta_hw_b",
		"delta_hw_e",
		"delta_hw_seed",
		"carry_density",
		"state_fingerprint",
		"state_b_hex",
		"state_e_hex",
		"state_seed_hex",
	}
	if err := writer.Write(header); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write CSV header: %v\n", err)
		os.Exit(1)
	}

	traceSamples := makeStateTraceSamples(samples, messageBits, includeLowEntropy)
	h := newAttackHash(k, rounds, outputBits)
	summary := stateTraceSummary{
		finalDeltaBMin:    int(^uint(0) >> 1),
		finalDeltaEMin:    int(^uint(0) >> 1),
		finalDeltaSeedMin: int(^uint(0) >> 1),
		fingerprintSeen:   make(map[string]int),
	}

	for sampleID, sample := range traceSamples {
		flipped := flipBitExtending(sample.message, sample.flipBit)
		baseTrace := h.TraceStateMetrics(sample.message, rounds)
		flipTrace := h.TraceStateMetrics(flipped, rounds)
		limit := min(len(baseTrace), len(flipTrace))
		for i := 0; i < limit; i++ {
			db := hammingWordDelta(baseTrace[i].BWords, flipTrace[i].BWords)
			de := hammingWordDelta(baseTrace[i].EWords, flipTrace[i].EWords)
			ds := hammingWordDelta(baseTrace[i].SeedWords, flipTrace[i].SeedWords)
			writeStateTraceRow(writer, &summary, sampleID, sample.name+":base", sample.flipBit, baseTrace[i], db, de, ds)
			writeStateTraceRow(writer, &summary, sampleID, sample.name+":flipped", sample.flipBit, flipTrace[i], db, de, ds)
			if i == limit-1 {
				summary.finalCount++
				summary.finalDeltaBSum += db
				summary.finalDeltaESum += de
				summary.finalDeltaSeedSum += ds
				summary.finalDeltaBMin = min(summary.finalDeltaBMin, db)
				summary.finalDeltaBMax = max(summary.finalDeltaBMax, db)
				summary.finalDeltaEMin = min(summary.finalDeltaEMin, de)
				summary.finalDeltaEMax = max(summary.finalDeltaEMax, de)
				summary.finalDeltaSeedMin = min(summary.finalDeltaSeedMin, ds)
				summary.finalDeltaSeedMax = max(summary.finalDeltaSeedMax, ds)
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not flush %s: %v\n", outputPath, err)
		os.Exit(1)
	}

	fmt.Printf("wrote: %s\n", outputPath)
	printStateTraceSummary(summary, rounds, len(traceSamples), k)
}

func makeStateTraceSamples(samples, messageBits int, includeLowEntropy bool) []stateTraceSample {
	byteLen := (messageBits + 7) / 8
	if byteLen <= 0 {
		byteLen = 1
	}
	out := make([]stateTraceSample, 0, samples+9)
	if includeLowEntropy {
		out = append(out,
			stateTraceSample{name: "empty", message: []byte{}, flipBit: 0},
			stateTraceSample{name: "all-zero", message: bytes.Repeat([]byte{0x00}, byteLen), flipBit: min(messageBits-1, 0)},
			stateTraceSample{name: "all-ff", message: bytes.Repeat([]byte{0xFF}, byteLen), flipBit: min(messageBits-1, 1)},
			stateTraceSample{name: "repeat-55", message: bytes.Repeat([]byte{0x55}, byteLen), flipBit: min(messageBits-1, 2)},
			stateTraceSample{name: "repeat-aa", message: bytes.Repeat([]byte{0xAA}, byteLen), flipBit: min(messageBits-1, 3)},
			stateTraceSample{name: "incrementing", message: incrementingBytes(byteLen), flipBit: min(messageBits-1, 5)},
			stateTraceSample{name: "test", message: []byte("test"), flipBit: min(31, max(0, messageBits-1))},
			stateTraceSample{name: "a", message: []byte("a"), flipBit: min(7, max(0, messageBits-1))},
			stateTraceSample{name: "repeat-ab", message: bytes.Repeat([]byte("ab"), max(1, byteLen/2)), flipBit: min(messageBits-1, 11)},
		)
	}
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ 0x571A7E))
	for i := 0; i < samples; i++ {
		msg := make([]byte, byteLen)
		rng.Read(msg)
		out = append(out, stateTraceSample{
			name:    "random",
			message: msg,
			flipBit: rng.Intn(max(1, messageBits)),
		})
	}
	return out
}

func writeStateTraceRow(writer *csv.Writer, summary *stateTraceSummary, sampleID int, messageType string, flipBit int, row relwe.StateTraceRound, deltaB, deltaE, deltaSeed int) {
	record := []string{
		strconv.Itoa(sampleID),
		strconv.Itoa(row.Round),
		strconv.Itoa(cliEta),
		messageType,
		strconv.Itoa(flipBit),
		strconv.Itoa(row.HWB),
		strconv.Itoa(row.HWE),
		strconv.Itoa(row.HWSeed),
		strconv.Itoa(deltaB),
		strconv.Itoa(deltaE),
		strconv.Itoa(deltaSeed),
		fmt.Sprintf("%.6f", row.CarryDensity),
		row.Fingerprint,
		hexFromWords(row.BWords),
		hexFromWords(row.EWords),
		hexFromWords(row.SeedWords),
	}
	if err := writer.Write(record); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write state trace row: %v\n", err)
		os.Exit(1)
	}
	summary.totalRows++
	summary.carrySum += row.CarryDensity
	summary.carryCount++
	summary.fingerprintSeen[row.Fingerprint]++
	if summary.fingerprintSeen[row.Fingerprint] == 2 {
		summary.repeatedFingerprints++
	}
}

func printStateTraceSummary(summary stateTraceSummary, rounds, sampleCount, k int) {
	avgCarry := 0.0
	if summary.carryCount > 0 {
		avgCarry = summary.carrySum / float64(summary.carryCount)
	}
	if summary.finalCount == 0 {
		fmt.Printf("total rows: %d\n", summary.totalRows)
		fmt.Println("no final rows available")
		return
	}
	avgB := float64(summary.finalDeltaBSum) / float64(summary.finalCount)
	avgE := float64(summary.finalDeltaESum) / float64(summary.finalCount)
	avgSeed := float64(summary.finalDeltaSeedSum) / float64(summary.finalCount)
	fmt.Printf("samples: %d, rounds traced: 0..%d\n", sampleCount, rounds)
	fmt.Printf("total rows: %d\n", summary.totalRows)
	fmt.Printf("average final delta_hw_b: %.2f (min=%d max=%d)\n", avgB, summary.finalDeltaBMin, summary.finalDeltaBMax)
	fmt.Printf("average final delta_hw_e: %.2f (min=%d max=%d)\n", avgE, summary.finalDeltaEMin, summary.finalDeltaEMax)
	fmt.Printf("average final delta_hw_seed: %.2f (min=%d max=%d)\n", avgSeed, summary.finalDeltaSeedMin, summary.finalDeltaSeedMax)
	fmt.Printf("average carry_density: %.6f\n", avgCarry)
	fmt.Printf("repeated state_fingerprint count: %d\n", summary.repeatedFingerprints)

	stateBits := float64(k * relwe.N * 16)
	seedBits := 512.0
	if avgB < stateBits*0.25 || avgE < stateBits*0.25 || avgSeed < seedBits*0.25 {
		fmt.Println("Potential weakness warning: final state delta appears collapsed below 25% diffusion")
	}
	if summary.repeatedFingerprints > 0 {
		fmt.Println("Potential weakness warning: repeated state fingerprints detected")
	}
}

func hammingWordDelta(a, b []uint32) int {
	n := min(len(a), len(b))
	total := 0
	for i := 0; i < n; i++ {
		total += bits.OnesCount32(a[i] ^ b[i])
	}
	for i := n; i < len(a); i++ {
		total += bits.OnesCount32(a[i])
	}
	for i := n; i < len(b); i++ {
		total += bits.OnesCount32(b[i])
	}
	return total
}

func hexFromWords(words []uint32) string {
	data := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(data[i*4:], word)
	}
	return hex.EncodeToString(data)
}

func flipBitExtending(data []byte, bitIndex int) []byte {
	if bitIndex < 0 {
		bitIndex = 0
	}
	out := append([]byte{}, data...)
	needLen := bitIndex/8 + 1
	for len(out) < needLen {
		out = append(out, 0)
	}
	out[bitIndex/8] ^= byte(1 << (bitIndex % 8))
	return out
}

type stateEvolutionRound struct {
	round                     int
	count                     int
	avgDeltaB                 float64
	avgDeltaE                 float64
	avgDeltaSeed              float64
	stdDeltaB                 float64
	stdDeltaE                 float64
	stdDeltaSeed              float64
	avgCarry                  float64
	stdCarry                  float64
	fingerprintCollisionCount int
}

type stateEvolutionAccum struct {
	deltaB       []float64
	deltaE       []float64
	deltaSeed    []float64
	carry        []float64
	fingerprints map[string]int
}

func stateEvolutionAttack(inputPath, outputDir, compareText string) {
	fmt.Printf("\n== State evolution analysis (eta=%d) ==\n", cliEta)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outputDir, err)
		os.Exit(1)
	}
	rounds, err := readStateEvolutionCSV(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not read state evolution input %s: %v\n", inputPath, err)
		os.Exit(1)
	}
	outCSV := filepath.Join(outputDir, fmt.Sprintf("round_evolution_eta%d.csv", cliEta))
	if err := writeStateEvolutionCSV(outCSV, rounds); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write %s: %v\n", outCSV, err)
		os.Exit(1)
	}
	if err := writeStateEvolutionPlots(outputDir, cliEta, rounds); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write state evolution plots: %v\n", err)
	}
	fmt.Printf("input: %s\n", inputPath)
	fmt.Printf("wrote: %s\n", outCSV)
	fmt.Printf("plots: %s\n", outputDir)
	printStateEvolutionSummary(rounds)

	if strings.TrimSpace(compareText) != "" {
		paths := splitCSVList(compareText)
		if len(paths) > 0 {
			stateEvolutionCompare(outputDir, paths)
		}
	}
}

func readStateEvolutionCSV(path string) ([]stateEvolutionRound, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV has no data rows")
	}
	header := make(map[string]int)
	for i, name := range rows[0] {
		header[strings.TrimSpace(name)] = i
	}
	required := []string{"round", "delta_hw_b", "delta_hw_e", "delta_hw_seed", "carry_density", "state_fingerprint"}
	for _, name := range required {
		if _, ok := header[name]; !ok {
			return nil, fmt.Errorf("missing required column %q", name)
		}
	}

	accByRound := map[int]*stateEvolutionAccum{}
	for rowIndex, row := range rows[1:] {
		round, err := atoiCSV(row, header["round"])
		if err != nil {
			return nil, fmt.Errorf("row %d round: %w", rowIndex+2, err)
		}
		db, err := atofCSV(row, header["delta_hw_b"])
		if err != nil {
			return nil, fmt.Errorf("row %d delta_hw_b: %w", rowIndex+2, err)
		}
		de, err := atofCSV(row, header["delta_hw_e"])
		if err != nil {
			return nil, fmt.Errorf("row %d delta_hw_e: %w", rowIndex+2, err)
		}
		ds, err := atofCSV(row, header["delta_hw_seed"])
		if err != nil {
			return nil, fmt.Errorf("row %d delta_hw_seed: %w", rowIndex+2, err)
		}
		carry, err := atofCSV(row, header["carry_density"])
		if err != nil {
			return nil, fmt.Errorf("row %d carry_density: %w", rowIndex+2, err)
		}
		fp := strings.TrimSpace(row[header["state_fingerprint"]])
		acc := accByRound[round]
		if acc == nil {
			acc = &stateEvolutionAccum{fingerprints: map[string]int{}}
			accByRound[round] = acc
		}
		acc.deltaB = append(acc.deltaB, db)
		acc.deltaE = append(acc.deltaE, de)
		acc.deltaSeed = append(acc.deltaSeed, ds)
		acc.carry = append(acc.carry, carry)
		acc.fingerprints[fp]++
	}

	roundKeys := make([]int, 0, len(accByRound))
	for round := range accByRound {
		roundKeys = append(roundKeys, round)
	}
	sort.Ints(roundKeys)
	out := make([]stateEvolutionRound, 0, len(roundKeys))
	for _, round := range roundKeys {
		acc := accByRound[round]
		avgB, stdB := meanStd(acc.deltaB)
		avgE, stdE := meanStd(acc.deltaE)
		avgSeed, stdSeed := meanStd(acc.deltaSeed)
		avgCarry, stdCarry := meanStd(acc.carry)
		collisions := 0
		for _, count := range acc.fingerprints {
			if count > 1 {
				collisions += count - 1
			}
		}
		out = append(out, stateEvolutionRound{
			round:                     round,
			count:                     len(acc.deltaB),
			avgDeltaB:                 avgB,
			avgDeltaE:                 avgE,
			avgDeltaSeed:              avgSeed,
			stdDeltaB:                 stdB,
			stdDeltaE:                 stdE,
			stdDeltaSeed:              stdSeed,
			avgCarry:                  avgCarry,
			stdCarry:                  stdCarry,
			fingerprintCollisionCount: collisions,
		})
	}
	return out, nil
}

func writeStateEvolutionCSV(path string, rounds []stateEvolutionRound) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	header := []string{
		"round",
		"avg_delta_hw_b",
		"avg_delta_hw_e",
		"avg_delta_hw_seed",
		"stddev_delta_hw_b",
		"stddev_delta_hw_e",
		"stddev_delta_hw_seed",
		"avg_carry_density",
		"stddev_carry_density",
		"fingerprint_collision_count",
	}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, row := range rounds {
		record := []string{
			strconv.Itoa(row.round),
			fmt.Sprintf("%.6f", row.avgDeltaB),
			fmt.Sprintf("%.6f", row.avgDeltaE),
			fmt.Sprintf("%.6f", row.avgDeltaSeed),
			fmt.Sprintf("%.6f", row.stdDeltaB),
			fmt.Sprintf("%.6f", row.stdDeltaE),
			fmt.Sprintf("%.6f", row.stdDeltaSeed),
			fmt.Sprintf("%.8f", row.avgCarry),
			fmt.Sprintf("%.8f", row.stdCarry),
			strconv.Itoa(row.fingerprintCollisionCount),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func printStateEvolutionSummary(rounds []stateEvolutionRound) {
	fmt.Printf("rounds analyzed: %d\n", len(rounds))
	if len(rounds) == 0 {
		return
	}
	saturationRound := firstSaturationRound(rounds)
	maxGrowthRound, maxGrowth := maxDeltaGrowthRound(rounds)
	carryStableRound := carryStabilizationRound(rounds)
	fmt.Printf("first saturation round: %s\n", formatRoundMaybe(saturationRound))
	fmt.Printf("max delta growth round: %d (growth=%.3f)\n", maxGrowthRound, maxGrowth)
	fmt.Printf("carry stabilization round: %s\n", formatRoundMaybe(carryStableRound))

	accelStart, accelEnd := diffusionAccelerationPhase(rounds)
	satStart := saturationRound
	if satStart < 0 {
		satStart = rounds[len(rounds)-1].round
	}
	fmt.Printf("diffusion acceleration phase: rounds %d..%d\n", accelStart, accelEnd)
	fmt.Printf("diffusion saturation phase: rounds %d..%d\n", satStart, rounds[len(rounds)-1].round)
	fmt.Printf("oscillation detection: %s\n", boolLabel(detectOscillation(rounds)))
	fmt.Printf("sudden collapse detection: %s\n", boolLabel(detectSuddenCollapse(rounds)))

	totalCollisions := 0
	for _, row := range rounds {
		totalCollisions += row.fingerprintCollisionCount
	}
	if detectPlateauCollapse(rounds) {
		fmt.Println("Potential weakness warning: plateau/collapse detected in state delta evolution")
	}
	if totalCollisions > 0 {
		fmt.Printf("Potential weakness warning: fingerprint collisions appeared (%d total repeated fingerprints)\n", totalCollisions)
	}
}

func firstSaturationRound(rounds []stateEvolutionRound) int {
	if len(rounds) < 4 {
		return -1
	}
	maxCombined := 0.0
	for _, row := range rounds {
		maxCombined = math.Max(maxCombined, combinedDelta(row))
	}
	epsilon := math.Max(8.0, maxCombined*0.005)
	streak := 0
	for i := 1; i < len(rounds); i++ {
		if math.Abs(combinedDelta(rounds[i])-combinedDelta(rounds[i-1])) < epsilon {
			streak++
			if streak >= 3 {
				return rounds[i-2].round
			}
		} else {
			streak = 0
		}
	}
	return -1
}

func maxDeltaGrowthRound(rounds []stateEvolutionRound) (int, float64) {
	if len(rounds) < 2 {
		return rounds[0].round, 0
	}
	bestRound := rounds[1].round
	bestGrowth := combinedDelta(rounds[1]) - combinedDelta(rounds[0])
	for i := 2; i < len(rounds); i++ {
		growth := combinedDelta(rounds[i]) - combinedDelta(rounds[i-1])
		if growth > bestGrowth {
			bestGrowth = growth
			bestRound = rounds[i].round
		}
	}
	return bestRound, bestGrowth
}

func carryStabilizationRound(rounds []stateEvolutionRound) int {
	if len(rounds) < 4 {
		return -1
	}
	streak := 0
	for i := 1; i < len(rounds); i++ {
		if math.Abs(rounds[i].avgCarry-rounds[i-1].avgCarry) < 0.0025 {
			streak++
			if streak >= 3 {
				return rounds[i-2].round
			}
		} else {
			streak = 0
		}
	}
	return -1
}

func diffusionAccelerationPhase(rounds []stateEvolutionRound) (int, int) {
	if len(rounds) < 2 {
		return rounds[0].round, rounds[0].round
	}
	bestRound, _ := maxDeltaGrowthRound(rounds)
	return rounds[0].round, bestRound
}

func detectOscillation(rounds []stateEvolutionRound) bool {
	if len(rounds) < 6 {
		return false
	}
	changes := 0
	lastSign := 0
	for i := 1; i < len(rounds); i++ {
		delta := combinedDelta(rounds[i]) - combinedDelta(rounds[i-1])
		sign := 0
		if delta > 0 {
			sign = 1
		} else if delta < 0 {
			sign = -1
		}
		if sign != 0 && lastSign != 0 && sign != lastSign {
			changes++
		}
		if sign != 0 {
			lastSign = sign
		}
	}
	return changes >= len(rounds)/3
}

func detectSuddenCollapse(rounds []stateEvolutionRound) bool {
	if len(rounds) < 2 {
		return false
	}
	maxSeen := combinedDelta(rounds[0])
	for i := 1; i < len(rounds); i++ {
		cur := combinedDelta(rounds[i])
		if maxSeen > 0 && cur < maxSeen*0.70 {
			return true
		}
		if cur > maxSeen {
			maxSeen = cur
		}
	}
	return false
}

func detectPlateauCollapse(rounds []stateEvolutionRound) bool {
	saturation := firstSaturationRound(rounds) >= 0
	collapse := detectSuddenCollapse(rounds)
	if collapse {
		return true
	}
	if !saturation || len(rounds) < 8 {
		return false
	}
	final := combinedDelta(rounds[len(rounds)-1])
	peak := 0.0
	for _, row := range rounds {
		peak = math.Max(peak, combinedDelta(row))
	}
	return peak > 0 && final < peak*0.85
}

func combinedDelta(row stateEvolutionRound) float64 {
	return row.avgDeltaB + row.avgDeltaE + row.avgDeltaSeed
}

func formatRoundMaybe(round int) string {
	if round < 0 {
		return "not detected"
	}
	return strconv.Itoa(round)
}

func boolLabel(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func writeStateEvolutionPlots(outputDir string, eta int, rounds []stateEvolutionRound) error {
	if len(rounds) == 0 {
		return nil
	}
	xs := roundXs(rounds)
	if err := writeLinePlot(
		filepath.Join(outputDir, fmt.Sprintf("delta_evolution_eta%d.png", eta)),
		xs,
		[]plotSeries{
			{name: "delta_hw_b", values: mapRoundValues(rounds, func(r stateEvolutionRound) float64 { return r.avgDeltaB }), color: color.RGBA{220, 60, 60, 255}},
			{name: "delta_hw_e", values: mapRoundValues(rounds, func(r stateEvolutionRound) float64 { return r.avgDeltaE }), color: color.RGBA{40, 130, 220, 255}},
			{name: "delta_hw_seed", values: mapRoundValues(rounds, func(r stateEvolutionRound) float64 { return r.avgDeltaSeed }), color: color.RGBA{40, 170, 90, 255}},
		},
	); err != nil {
		return err
	}
	if err := writeLinePlot(
		filepath.Join(outputDir, fmt.Sprintf("carry_density_eta%d.png", eta)),
		xs,
		[]plotSeries{{name: "carry_density", values: mapRoundValues(rounds, func(r stateEvolutionRound) float64 { return r.avgCarry }), color: color.RGBA{180, 80, 220, 255}}},
	); err != nil {
		return err
	}
	return writeLinePlot(
		filepath.Join(outputDir, fmt.Sprintf("fingerprint_collisions_eta%d.png", eta)),
		xs,
		[]plotSeries{{name: "fingerprint_collision_count", values: mapRoundValues(rounds, func(r stateEvolutionRound) float64 { return float64(r.fingerprintCollisionCount) }), color: color.RGBA{230, 150, 30, 255}}},
	)
}

func stateEvolutionCompare(outputDir string, paths []string) {
	series := make([]plotSeries, 0, len(paths))
	xSeen := map[int]bool{}
	labels := make([]string, 0, len(paths))
	palette := []color.RGBA{
		{220, 60, 60, 255},
		{40, 130, 220, 255},
		{40, 170, 90, 255},
		{180, 80, 220, 255},
		{230, 150, 30, 255},
	}
	for i, path := range paths {
		rounds, err := readStateEvolutionCSV(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: compare input skipped %s: %v\n", path, err)
			continue
		}
		label := etaLabelFromPath(path)
		labels = append(labels, label)
		for _, x := range roundXs(rounds) {
			xSeen[x] = true
		}
		values := mapRoundValues(rounds, combinedDelta)
		series = append(series, plotSeries{name: label, values: values, color: palette[i%len(palette)]})
	}
	if len(series) == 0 {
		return
	}
	xs := make([]int, 0, len(xSeen))
	for x := range xSeen {
		xs = append(xs, x)
	}
	sort.Ints(xs)
	outPath := filepath.Join(outputDir, "comparison_"+strings.Join(labels, "_vs_")+".png")
	outPath = strings.ReplaceAll(outPath, string(os.PathSeparator)+"comparison_", string(os.PathSeparator)+"comparison_")
	if err := writeLinePlot(outPath, xs, series); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write comparison plot: %v\n", err)
		return
	}
	fmt.Printf("comparison plot: %s\n", outPath)
}

type plotSeries struct {
	name   string
	values map[int]float64
	color  color.RGBA
}

func writeLinePlot(path string, xs []int, series []plotSeries) error {
	const width = 1000
	const height = 620
	const left = 70
	const right = 30
	const top = 30
	const bottom = 70
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{color.RGBA{250, 250, 250, 255}}, image.Point{}, draw.Src)
	axis := color.RGBA{50, 50, 50, 255}
	grid := color.RGBA{225, 225, 225, 255}
	for i := 0; i <= 5; i++ {
		y := top + i*(height-top-bottom)/5
		drawLine(img, left, y, width-right, y, grid)
	}
	drawLine(img, left, top, left, height-bottom, axis)
	drawLine(img, left, height-bottom, width-right, height-bottom, axis)

	if len(xs) == 0 || len(series) == 0 {
		return savePNG(path, img)
	}
	minX, maxX := xs[0], xs[len(xs)-1]
	if minX == maxX {
		maxX = minX + 1
	}
	minY, maxY := math.MaxFloat64, -math.MaxFloat64
	for _, s := range series {
		for _, x := range xs {
			if y, ok := s.values[x]; ok {
				minY = math.Min(minY, y)
				maxY = math.Max(maxY, y)
			}
		}
	}
	if minY == math.MaxFloat64 {
		minY, maxY = 0, 1
	}
	if minY > 0 {
		minY = 0
	}
	if maxY <= minY {
		maxY = minY + 1
	}
	project := func(x int, y float64) (int, int) {
		px := left + int(math.Round(float64(x-minX)*float64(width-left-right)/float64(maxX-minX)))
		py := height - bottom - int(math.Round((y-minY)*float64(height-top-bottom)/(maxY-minY)))
		return px, py
	}
	for _, s := range series {
		hasPrev := false
		prevX, prevY := 0, 0
		for _, x := range xs {
			y, ok := s.values[x]
			if !ok {
				hasPrev = false
				continue
			}
			px, py := project(x, y)
			fillRect(img, px-2, py-2, 5, 5, s.color)
			if hasPrev {
				drawLine(img, prevX, prevY, px, py, s.color)
			}
			prevX, prevY, hasPrev = px, py, true
		}
	}
	return savePNG(path, img)
}

func savePNG(path string, img image.Image) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return png.Encode(file, img)
}

func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx := absInt(x1 - x0)
	dy := -absInt(y1 - y0)
	sx, sy := -1, -1
	if x0 < x1 {
		sx = 1
	}
	if y0 < y1 {
		sy = 1
	}
	err := dx + dy
	for {
		if image.Pt(x0, y0).In(img.Bounds()) {
			img.SetRGBA(x0, y0, c)
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func fillRect(img *image.RGBA, x, y, w, h int, c color.RGBA) {
	for yy := y; yy < y+h; yy++ {
		for xx := x; xx < x+w; xx++ {
			if image.Pt(xx, yy).In(img.Bounds()) {
				img.SetRGBA(xx, yy, c)
			}
		}
	}
}

func roundXs(rounds []stateEvolutionRound) []int {
	xs := make([]int, len(rounds))
	for i, row := range rounds {
		xs[i] = row.round
	}
	return xs
}

func mapRoundValues(rounds []stateEvolutionRound, fn func(stateEvolutionRound) float64) map[int]float64 {
	out := make(map[int]float64, len(rounds))
	for _, row := range rounds {
		out[row.round] = fn(row)
	}
	return out
}

func meanStd(values []float64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, value := range values {
		sum += value
	}
	mean := sum / float64(len(values))
	var variance float64
	for _, value := range values {
		delta := value - mean
		variance += delta * delta
	}
	return mean, math.Sqrt(variance / float64(len(values)))
}

func atoiCSV(row []string, index int) (int, error) {
	if index < 0 || index >= len(row) {
		return 0, fmt.Errorf("column index out of range")
	}
	return strconv.Atoi(strings.TrimSpace(row[index]))
}

func atofCSV(row []string, index int) (float64, error) {
	if index < 0 || index >= len(row) {
		return 0, fmt.Errorf("column index out of range")
	}
	return strconv.ParseFloat(strings.TrimSpace(row[index]), 64)
}

func splitCSVList(text string) []string {
	var out []string
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

func etaLabelFromPath(path string) string {
	base := filepath.Base(path)
	for eta := 1; eta <= 64; eta++ {
		token := fmt.Sprintf("eta%d", eta)
		if strings.Contains(base, token) {
			return token
		}
	}
	clean := strings.TrimSuffix(base, filepath.Ext(base))
	clean = strings.NewReplacer(" ", "_", ".", "_", "-", "_").Replace(clean)
	return clean
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

type stateRankResult struct {
	round            int
	eta              int
	target           string
	rows             int
	cols             int
	rank             int
	rankRatio        float64
	deficiency       int
	uniqueVectors    int
	duplicateVectors int
}

type stateRankRoundData struct {
	rows       [][]uint64
	unique     map[string]struct{}
	duplicates int
	cols       int
	eta        int
}

func stateRankAttack(inputPath, outputPath, target string, maxRows int, compareText string) {
	fmt.Printf("\n== State rank analysis over GF(2) (eta=%d) ==\n", cliEta)
	target = strings.ToLower(strings.TrimSpace(target))
	if !validStateRankTarget(target) {
		fmt.Fprintln(os.Stderr, "error: state-rank-target must be one of: all,b,e,seed,be,bseed,eseed")
		os.Exit(2)
	}
	if maxRows < 0 {
		fmt.Fprintln(os.Stderr, "error: state-rank-max-rows must be >= 0")
		os.Exit(2)
	}

	results, err := computeStateRank(inputPath, target, maxRows)
	if err != nil {
		if strings.TrimSpace(compareText) == "" {
			fmt.Fprintf(os.Stderr, "error: state-rank failed for %s: %v\n", inputPath, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "warning: primary state-rank input skipped %s: %v\n", inputPath, err)
	} else {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: could not create state-rank directory: %v\n", err)
			os.Exit(1)
		}
		if err := writeStateRankCSV(outputPath, results); err != nil {
			fmt.Fprintf(os.Stderr, "error: could not write %s: %v\n", outputPath, err)
			os.Exit(1)
		}
		fmt.Printf("input: %s\n", inputPath)
		fmt.Printf("wrote: %s\n", outputPath)
		printStateRankSummary(results, target)
	}

	if strings.TrimSpace(compareText) != "" {
		paths := splitCSVList(compareText)
		if len(paths) > 0 {
			stateRankCompare(paths, filepath.Join("out", "state_rank", "state_rank_compare.csv"), target, maxRows)
		}
	}
}

func computeStateRank(path, target string, maxRows int) ([]stateRankResult, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	headerRow, err := reader.Read()
	if err != nil {
		return nil, err
	}
	header := make(map[string]int)
	for i, name := range headerRow {
		header[strings.TrimSpace(name)] = i
	}
	required := []string{"round", "eta", "state_b_hex", "state_e_hex", "state_seed_hex"}
	for _, name := range required {
		if _, ok := header[name]; !ok {
			return nil, fmt.Errorf("missing %q; regenerate state-trace CSV with the current build so raw state hex columns are present", name)
		}
	}

	roundData := map[int]*stateRankRoundData{}
	for {
		row, err := reader.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		round, err := atoiCSV(row, header["round"])
		if err != nil {
			return nil, err
		}
		eta, err := atoiCSV(row, header["eta"])
		if err != nil {
			return nil, err
		}
		data, err := stateRankTargetBytes(row, header, target)
		if err != nil {
			return nil, err
		}
		acc := roundData[round]
		if acc == nil {
			acc = &stateRankRoundData{unique: map[string]struct{}{}, cols: len(data) * 8, eta: eta}
			roundData[round] = acc
		}
		if maxRows > 0 && len(acc.rows) >= maxRows {
			continue
		}
		key := string(data)
		if _, ok := acc.unique[key]; ok {
			acc.duplicates++
		} else {
			acc.unique[key] = struct{}{}
		}
		acc.rows = append(acc.rows, bytesToBitset(data))
	}

	rounds := make([]int, 0, len(roundData))
	for round := range roundData {
		rounds = append(rounds, round)
	}
	sort.Ints(rounds)
	results := make([]stateRankResult, 0, len(rounds))
	for _, round := range rounds {
		acc := roundData[round]
		rank := gf2Rank(acc.rows, acc.cols)
		limit := min(len(acc.rows), acc.cols)
		deficiency := limit - rank
		ratio := 1.0
		if limit > 0 {
			ratio = float64(rank) / float64(limit)
		}
		results = append(results, stateRankResult{
			round:            round,
			eta:              acc.eta,
			target:           target,
			rows:             len(acc.rows),
			cols:             acc.cols,
			rank:             rank,
			rankRatio:        ratio,
			deficiency:       deficiency,
			uniqueVectors:    len(acc.unique),
			duplicateVectors: acc.duplicates,
		})
	}
	return results, nil
}

func stateRankTargetBytes(row []string, header map[string]int, target string) ([]byte, error) {
	readHex := func(name string) ([]byte, error) {
		index := header[name]
		if index < 0 || index >= len(row) {
			return nil, fmt.Errorf("column %s out of range", name)
		}
		return hex.DecodeString(strings.TrimSpace(row[index]))
	}
	b, err := readHex("state_b_hex")
	if err != nil {
		return nil, fmt.Errorf("state_b_hex: %w", err)
	}
	e, err := readHex("state_e_hex")
	if err != nil {
		return nil, fmt.Errorf("state_e_hex: %w", err)
	}
	seed, err := readHex("state_seed_hex")
	if err != nil {
		return nil, fmt.Errorf("state_seed_hex: %w", err)
	}
	switch target {
	case "all":
		return append(append(append([]byte{}, b...), e...), seed...), nil
	case "b":
		return b, nil
	case "e":
		return e, nil
	case "seed":
		return seed, nil
	case "be":
		return append(append([]byte{}, b...), e...), nil
	case "bseed":
		return append(append([]byte{}, b...), seed...), nil
	case "eseed":
		return append(append([]byte{}, e...), seed...), nil
	default:
		return nil, fmt.Errorf("invalid state-rank target %q", target)
	}
}

func writeStateRankCSV(path string, results []stateRankResult) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	header := []string{"round", "eta", "target", "rows", "cols", "rank", "rank_ratio", "deficiency", "unique_vectors", "duplicate_vectors"}
	if err := writer.Write(header); err != nil {
		return err
	}
	for _, row := range results {
		if err := writer.Write(stateRankRecord(row)); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func stateRankRecord(row stateRankResult) []string {
	return []string{
		strconv.Itoa(row.round),
		strconv.Itoa(row.eta),
		row.target,
		strconv.Itoa(row.rows),
		strconv.Itoa(row.cols),
		strconv.Itoa(row.rank),
		fmt.Sprintf("%.8f", row.rankRatio),
		strconv.Itoa(row.deficiency),
		strconv.Itoa(row.uniqueVectors),
		strconv.Itoa(row.duplicateVectors),
	}
}

func printStateRankSummary(results []stateRankResult, target string) {
	fmt.Printf("rounds analyzed: %d\n", len(results))
	fmt.Printf("target: %s\n", target)
	if len(results) == 0 {
		return
	}
	minRatio := 1.0
	maxDef := 0
	firstDefRound := -1
	duplicateTotal := 0
	deficientRounds := 0
	for _, row := range results {
		if row.rankRatio < minRatio {
			minRatio = row.rankRatio
		}
		if row.deficiency > maxDef {
			maxDef = row.deficiency
		}
		if row.deficiency > 0 {
			deficientRounds++
			if firstDefRound < 0 {
				firstDefRound = row.round
			}
		}
		duplicateTotal += row.duplicateVectors
	}
	fmt.Printf("min rank_ratio: %.6f\n", minRatio)
	fmt.Printf("max deficiency: %d\n", maxDef)
	fmt.Printf("first round with deficiency > 0: %s\n", formatRoundMaybe(firstDefRound))
	fmt.Printf("duplicate vector count: %d\n", duplicateTotal)
	if minRatio < 0.98 || duplicateTotal > 0 || deficientRounds >= 3 || (target == "seed" && maxDef > 0) {
		fmt.Println("Potential weakness warning: low-rank behavior detected")
	}
}

func stateRankCompare(paths []string, outputPath, target string, maxRows int) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create state-rank compare directory: %v\n", err)
		return
	}
	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not create %s: %v\n", outputPath, err)
		return
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	header := []string{"source", "round", "eta", "target", "rows", "cols", "rank", "rank_ratio", "deficiency", "unique_vectors", "duplicate_vectors"}
	if err := writer.Write(header); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write compare CSV: %v\n", err)
		return
	}
	for _, path := range paths {
		results, err := computeStateRank(path, target, maxRows)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: state-rank compare skipped %s: %v\n", path, err)
			continue
		}
		source := etaLabelFromPath(path)
		for _, result := range results {
			record := append([]string{source}, stateRankRecord(result)...)
			if err := writer.Write(record); err != nil {
				fmt.Fprintf(os.Stderr, "warning: could not write compare row: %v\n", err)
				return
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not flush compare CSV: %v\n", err)
		return
	}
	fmt.Printf("compare CSV: %s\n", outputPath)
}

func bytesToBitset(data []byte) []uint64 {
	words := make([]uint64, (len(data)*8+63)/64)
	for i, b := range data {
		words[i/8] |= uint64(b) << (8 * (i % 8))
	}
	return words
}

func gf2Rank(rows [][]uint64, cols int) int {
	pivots := make(map[int][]uint64)
	rank := 0
	for _, original := range rows {
		row := append([]uint64(nil), original...)
		for {
			pivotCol := leadingBit(row)
			if pivotCol < 0 || pivotCol >= cols {
				break
			}
			pivot, ok := pivots[pivotCol]
			if !ok {
				pivots[pivotCol] = row
				rank++
				break
			}
			xorBitsets(row, pivot)
		}
	}
	return rank
}

func leadingBit(row []uint64) int {
	for wordIndex := len(row) - 1; wordIndex >= 0; wordIndex-- {
		word := row[wordIndex]
		if word != 0 {
			return wordIndex*64 + bits.Len64(word) - 1
		}
	}
	return -1
}

func xorBitsets(dst, src []uint64) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

func validStateRankTarget(target string) bool {
	switch target {
	case "all", "b", "e", "seed", "be", "bseed", "eseed":
		return true
	default:
		return false
	}
}

type hoRoundAccum struct {
	hws        []float64
	zeros      int
	duplicates int
	seen       map[string]struct{}
	ones       int
	bits       int
}

func higherOrderStateAttack(order, rounds, samples, messageBits int, target, compareText string, k, outputBits int) {
	fmt.Printf("\n== Higher-order differential state attack (eta=%d) ==\n", cliEta)
	target = strings.ToLower(strings.TrimSpace(target))
	if order <= 0 || order > 6 || rounds <= 0 || samples <= 0 || messageBits <= 0 {
		fmt.Fprintln(os.Stderr, "error: ho-order must be 1..6 and ho-rounds/ho-samples/ho-message-bits must be positive")
		os.Exit(2)
	}
	if !validHOTarget(target) {
		fmt.Fprintln(os.Stderr, "error: ho-target must be one of: all,b,e,seed")
		os.Exit(2)
	}
	outDir := filepath.Join("out", "higher_order")
	must(os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, fmt.Sprintf("ho_eta%d_order%d.csv", cliEta, order))
	acc := make([]hoRoundAccum, rounds+1)
	for i := range acc {
		acc[i].seen = map[string]struct{}{}
	}
	h := newAttackHash(k, rounds, outputBits)
	byteLen := (messageBits + 7) / 8
	rng := mrand.New(mrand.NewSource(0x484F0000 ^ int64(cliEta)*0x10001 ^ int64(order)))
	evals := 1 << order
	for sample := 0; sample < samples; sample++ {
		base := make([]byte, byteLen)
		rng.Read(base)
		diffs := randomDistinctBits(rng, messageBits, order)
		derivatives := make([][]byte, rounds+1)
		for subset := 0; subset < evals; subset++ {
			msg := append([]byte{}, base...)
			for bit := 0; bit < order; bit++ {
				if ((subset >> bit) & 1) == 1 {
					msg = flipBitExtending(msg, diffs[bit])
				}
			}
			trace := h.TraceStateMetrics(msg, rounds)
			for r := 0; r <= rounds && r < len(trace); r++ {
				vec := stateMetricTargetBytes(trace[r], target)
				if derivatives[r] == nil {
					derivatives[r] = make([]byte, len(vec))
				}
				xorBytesInPlace(derivatives[r], vec)
			}
		}
		for r, vec := range derivatives {
			if vec == nil {
				continue
			}
			hw := hammingByteSlice(vec)
			acc[r].hws = append(acc[r].hws, float64(hw))
			acc[r].ones += hw
			acc[r].bits += len(vec) * 8
			if hw == 0 {
				acc[r].zeros++
			}
			key := string(vec)
			if _, ok := acc[r].seen[key]; ok {
				acc[r].duplicates++
			} else {
				acc[r].seen[key] = struct{}{}
			}
		}
	}
	if err := writeHigherOrderCSV(outPath, order, target, acc); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write %s: %v\n", outPath, err)
		os.Exit(1)
	}
	if err := plotSimpleCSV(outPath, outDir, fmt.Sprintf("comparison_ho_eta%d_order%d.png", cliEta, order), "round", "avg_hw"); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write higher-order plot: %v\n", err)
	}
	fmt.Printf("wrote: %s\n", outPath)
	printHigherOrderSummary(acc, order, target)
	if compareText != "" {
		compareMetricCSVs(splitCSVList(compareText), filepath.Join(outDir, comparisonName("comparison_ho", compareText)), "round", "avg_hw")
	}
}

func writeHigherOrderCSV(path string, order int, target string, acc []hoRoundAccum) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"round", "order", "target", "avg_hw", "stddev_hw", "zero_ratio", "duplicate_ratio", "entropy_estimate"}); err != nil {
		return err
	}
	for round, row := range acc {
		avg, std := meanStd(row.hws)
		count := max(1, len(row.hws))
		entropy := bitEntropy(row.ones, row.bits)
		record := []string{
			strconv.Itoa(round),
			strconv.Itoa(order),
			target,
			fmt.Sprintf("%.6f", avg),
			fmt.Sprintf("%.6f", std),
			fmt.Sprintf("%.8f", float64(row.zeros)/float64(count)),
			fmt.Sprintf("%.8f", float64(row.duplicates)/float64(count)),
			fmt.Sprintf("%.8f", entropy),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

func printHigherOrderSummary(acc []hoRoundAccum, order int, target string) {
	minAvg := math.MaxFloat64
	zeroSpike, dupSpike := false, false
	for _, row := range acc {
		avg, _ := meanStd(row.hws)
		minAvg = math.Min(minAvg, avg)
		count := max(1, len(row.hws))
		if float64(row.zeros)/float64(count) > 0.05 {
			zeroSpike = true
		}
		if float64(row.duplicates)/float64(count) > 0.05 {
			dupSpike = true
		}
	}
	fmt.Printf("order=%d target=%s rounds=%d\n", order, target, len(acc)-1)
	fmt.Printf("minimum avg derivative HW: %.2f\n", minAvg)
	if zeroSpike || dupSpike || minAvg < 64 {
		fmt.Println("Potential weakness warning: higher-order derivative collapse/duplication candidate")
	}
}

func degreeGrowthAttack(rounds, stateBits, samples int, compareText string) {
	fmt.Printf("\n== Algebraic degree growth estimate (eta=%d) ==\n", cliEta)
	if rounds <= 0 || stateBits <= 0 || samples <= 0 {
		fmt.Fprintln(os.Stderr, "error: degree-rounds, degree-state-bits, and degree-samples must be positive")
		os.Exit(2)
	}
	outDir := filepath.Join("out", "degree")
	must(os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, fmt.Sprintf("degree_growth_eta%d.csv", cliEta))
	file, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outPath, err)
		os.Exit(1)
	}
	writer := csv.NewWriter(file)
	must(writer.Write([]string{"round", "estimated_degree", "degree_growth_rate", "degree_saturation"}))
	prev := 1
	stagnant := 0
	for r := 0; r <= rounds; r++ {
		degrees := estimateMiniCoreDegrees(r, min(stateBits, 64), min(stateBits, 32))
		maxDegree := 0
		for _, d := range degrees {
			maxDegree = max(maxDegree, d)
		}
		if maxDegree > stateBits {
			maxDegree = stateBits
		}
		growth := maxDegree - prev
		saturation := float64(maxDegree) / float64(stateBits)
		if r > 0 && growth <= 0 {
			stagnant++
		}
		must(writer.Write([]string{strconv.Itoa(r), strconv.Itoa(maxDegree), strconv.Itoa(growth), fmt.Sprintf("%.8f", saturation)}))
		prev = maxDegree
	}
	writer.Flush()
	must(writer.Error())
	must(file.Close())
	_ = plotSimpleCSV(outPath, outDir, fmt.Sprintf("comparison_degree_eta%d.png", cliEta), "round", "estimated_degree")
	fmt.Printf("wrote: %s\n", outPath)
	if stagnant >= 3 || prev < min(stateBits, 8) {
		fmt.Println("Potential weakness warning: algebraic degree stagnation / low-degree candidate")
	}
	if compareText != "" {
		compareMetricCSVs(splitCSVList(compareText), filepath.Join(outDir, comparisonName("comparison_degree", compareText)), "round", "estimated_degree")
	}
}

type walshMask struct {
	name string
	bits []int
}

type walshPartial struct {
	counts [][]int
	calls  int64
}

func walshBiasAttack(rounds, samples, outputBitCount, maxMaskWeight int, focusMasksText, compareText string, progress bool, threads, k, outputBits int) {
	fmt.Printf("\n== Walsh/Fourier spectral bias search (eta=%d) ==\n", cliEta)
	if rounds <= 0 || samples <= 0 || outputBitCount <= 0 || maxMaskWeight <= 0 {
		fmt.Fprintln(os.Stderr, "error: walsh-rounds, walsh-samples, walsh-output-bits, and walsh-max-mask-weight must be positive")
		os.Exit(2)
	}
	outputBitCount = min(outputBitCount, outputBits)
	focusMode := strings.TrimSpace(focusMasksText) != ""
	masks := makeWalshMasks(512, maxMaskWeight, 64)
	if focusMode {
		var err error
		masks, err = parseWalshFocusMasks(focusMasksText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid walsh-focus-masks: %v\n", err)
			os.Exit(2)
		}
		outputBitCount = min(8, outputBits)
		fmt.Printf("focus mode: masks=%d, output_bits=0..%d\n", len(masks), outputBitCount-1)
	}
	var counts [][]int
	hashCalls := int64(samples)
	var elapsed time.Duration
	if focusMode {
		counts, hashCalls, elapsed = walshFocusFastPath(rounds, samples, masks, outputBitCount, progress, threads, k, outputBits)
		fmt.Printf("focus transform calls: %d (samples=%d)\n", hashCalls, samples)
		if hashCalls != int64(samples) {
			fmt.Println("Potential implementation warning: focused Walsh transform calls differ from sample count")
		}
		fmt.Printf("focus elapsed: %s\n", elapsed.Round(time.Millisecond))
	} else {
		counts, hashCalls, elapsed = walshFocusFastPath(rounds, samples, masks, outputBitCount, progress, threads, k, outputBits)
		_ = hashCalls
		_ = elapsed
	}
	outDir := filepath.Join("out", "walsh")
	must(os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, fmt.Sprintf("walsh_eta%d.csv", cliEta))
	file, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outPath, err)
		os.Exit(1)
	}
	writer := csv.NewWriter(file)
	must(writer.Write([]string{"mask", "round", "bias", "correlation", "max_abs_bias"}))
	maxBias := 0.0
	for mi, mask := range masks {
		maskBias := make([]float64, outputBitCount)
		maskMax := 0.0
		for outBit := 0; outBit < outputBitCount; outBit++ {
			p := float64(counts[mi][outBit]) / float64(samples)
			bias := p - 0.5
			maskBias[outBit] = bias
			maskMax = math.Max(maskMax, math.Abs(bias))
		}
		maxBias = math.Max(maxBias, maskMax)
		for outBit, bias := range maskBias {
			must(writer.Write([]string{fmt.Sprintf("%s->out%d", mask.name, outBit), strconv.Itoa(rounds), fmt.Sprintf("%.8f", bias), fmt.Sprintf("%.8f", 2*bias), fmt.Sprintf("%.8f", maskMax)}))
		}
	}
	writer.Flush()
	must(writer.Error())
	must(file.Close())
	_ = plotSimpleCSV(outPath, outDir, fmt.Sprintf("comparison_walsh_eta%d.png", cliEta), "round", "max_abs_bias")
	fmt.Printf("wrote: %s\n", outPath)
	if focusMode {
		fmt.Printf("focus masks checked: %s\n", formatWalshMaskNames(masks))
	}
	fmt.Printf("max_abs_bias: %.8f\n", maxBias)
	if maxBias > math.Max(0.01, 6*math.Sqrt(0.25/float64(samples))) {
		fmt.Println("Potential weakness warning: persistent low-weight spectral bias candidate")
	}
	if compareText != "" {
		compareMetricCSVs(splitCSVList(compareText), filepath.Join(outDir, comparisonName("comparison_walsh", compareText)), "round", "max_abs_bias")
	}
}

func walshFocusFastPath(rounds, samples int, masks []walshMask, outputBitCount int, progress bool, threads, k, outputBits int) ([][]int, int64, time.Duration) {
	start := time.Now()
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	perWorker := splitWork(samples, threads)
	partials := make(chan walshPartial, threads)
	var wg sync.WaitGroup
	var processed atomic.Int64
	stopProgress := startProgressReporter("walsh", int64(samples), &processed, progress)

	startIndex := 0
	for workerID, count := range perWorker {
		if count == 0 {
			continue
		}
		workerStart := startIndex
		startIndex += count
		wg.Add(1)
		go func(workerID, first, count int) {
			defer wg.Done()
			partials <- walshWorker(workerID, first, count, rounds, masks, outputBitCount, k, outputBits, &processed)
		}(workerID, workerStart, count)
	}
	go func() {
		wg.Wait()
		close(partials)
	}()

	counts := newCountMatrix(len(masks), outputBitCount)
	var calls int64
	for partial := range partials {
		mergeCountMatrix(counts, partial.counts)
		calls += partial.calls
	}
	stopProgress()
	return counts, calls, time.Since(start)
}

func walshWorker(workerID, first, samples, rounds int, masks []walshMask, outputBitCount, k, outputBits int, processed *atomic.Int64) walshPartial {
	h := newAttackHash(k, rounds, outputBits)
	rng := mrand.New(mrand.NewSource(0x57414C5348 ^ int64(cliEta)*0x1000003 ^ int64(first) ^ int64(workerID)*0x9E3779B1))
	counts := newCountMatrix(len(masks), outputBitCount)
	for i := 0; i < samples; i++ {
		msg := make([]byte, 64)
		rng.Read(msg)
		digest, _ := hex.DecodeString(h.HashBytes(msg))
		outputBitsSet := make([]int, outputBitCount)
		for outBit := 0; outBit < outputBitCount; outBit++ {
			outputBitsSet[outBit] = int(bitAt(digest, outBit))
		}
		for mi, mask := range masks {
			inParity := parityAtPositions(msg, mask.bits)
			for outBit, outValue := range outputBitsSet {
				if inParity^outValue == 1 {
					counts[mi][outBit]++
				}
			}
		}
		processed.Add(1)
	}
	return walshPartial{counts: counts, calls: int64(samples)}
}

func newCountMatrix(rows, cols int) [][]int {
	counts := make([][]int, rows)
	for i := range counts {
		counts[i] = make([]int, cols)
	}
	return counts
}

func mergeCountMatrix(dst, src [][]int) {
	for i := range dst {
		for j, v := range src[i] {
			dst[i][j] += v
		}
	}
}

func startProgressReporter(label string, total int64, processed *atomic.Int64, enabled bool) func() {
	if !enabled || total <= 0 {
		return func() {}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				doneCount := processed.Load()
				pct := 100 * float64(doneCount) / float64(total)
				fmt.Fprintf(os.Stderr, "%s progress: %d/%d (%.1f%%, %s)\n", label, doneCount, total, pct, time.Since(start).Round(time.Second))
			case <-stop:
				doneCount := processed.Load()
				pct := 100 * float64(doneCount) / float64(total)
				fmt.Fprintf(os.Stderr, "%s progress: %d/%d (%.1f%%, %s)\n", label, doneCount, total, pct, time.Since(start).Round(time.Second))
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

type miPartial struct {
	acc        []miAccum
	carryAcc   []miAccum
	outputAcc  []miAccum
	traceCalls int64
	hashCalls  int64
}

type miAccum struct {
	counts []int
}

func mutualInfoAttack(rounds, samples int, target, compareText string, threads, k, outputBits int) {
	fmt.Printf("\n== Mutual information tracking (eta=%d) ==\n", cliEta)
	target = strings.ToLower(strings.TrimSpace(target))
	if rounds <= 0 || samples <= 0 || !validMITarget(target) {
		fmt.Fprintln(os.Stderr, "error: mi-rounds/mi-samples must be positive and mi-target must be all,b,e,seed,output")
		os.Exit(2)
	}
	if threads <= 0 {
		threads = runtime.NumCPU()
	}
	trackedInputs := 16
	trackedTargets := 64
	acc, carryAcc, outputAcc := newMIAccumulators(rounds, trackedInputs, trackedTargets)
	start := time.Now()
	perWorker := splitWork(samples, threads)
	partials := make(chan miPartial, threads)
	var wg sync.WaitGroup
	var processed atomic.Int64
	stopProgress := startProgressReporter("mutual-info", int64(samples), &processed, samples >= 50000)

	startIndex := 0
	for workerID, count := range perWorker {
		if count == 0 {
			continue
		}
		workerStart := startIndex
		startIndex += count
		wg.Add(1)
		go func(workerID, first, count int) {
			defer wg.Done()
			partials <- mutualInfoWorker(workerID, first, count, rounds, target, trackedInputs, trackedTargets, k, outputBits, &processed)
		}(workerID, workerStart, count)
	}
	go func() {
		wg.Wait()
		close(partials)
	}()

	var traceCalls, hashCalls int64
	for partial := range partials {
		mergeMIAccumulators(acc, partial.acc)
		mergeMIAccumulators(carryAcc, partial.carryAcc)
		mergeMIAccumulators(outputAcc, partial.outputAcc)
		traceCalls += partial.traceCalls
		hashCalls += partial.hashCalls
	}
	stopProgress()
	outDir := filepath.Join("out", "mutual_info")
	must(os.MkdirAll(outDir, 0o755))
	outPath := filepath.Join(outDir, fmt.Sprintf("mi_eta%d.csv", cliEta))
	file, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outPath, err)
		os.Exit(1)
	}
	writer := csv.NewWriter(file)
	must(writer.Write([]string{"round", "target", "avg_mutual_information", "max_mutual_information", "min_mutual_information"}))
	globalMax := 0.0
	for r := 0; r <= rounds; r++ {
		avg, maxMI, minMI := summarizeMI(acc[r].counts, trackedInputs, trackedTargets)
		globalMax = math.Max(globalMax, maxMI)
		must(writer.Write([]string{strconv.Itoa(r), target, fmt.Sprintf("%.10f", avg), fmt.Sprintf("%.10f", maxMI), fmt.Sprintf("%.10f", minMI)}))
		avg, maxMI, minMI = summarizeMI(carryAcc[r].counts, trackedInputs, 1)
		globalMax = math.Max(globalMax, maxMI)
		must(writer.Write([]string{strconv.Itoa(r), "carry_density", fmt.Sprintf("%.10f", avg), fmt.Sprintf("%.10f", maxMI), fmt.Sprintf("%.10f", minMI)}))
		avg, maxMI, minMI = summarizeMI(outputAcc[r].counts, trackedInputs, trackedTargets)
		globalMax = math.Max(globalMax, maxMI)
		must(writer.Write([]string{strconv.Itoa(r), "output", fmt.Sprintf("%.10f", avg), fmt.Sprintf("%.10f", maxMI), fmt.Sprintf("%.10f", minMI)}))
	}
	writer.Flush()
	must(writer.Error())
	must(file.Close())
	_ = plotSimpleCSV(outPath, outDir, fmt.Sprintf("comparison_mi_eta%d.png", cliEta), "round", "max_mutual_information")
	fmt.Printf("wrote: %s\n", outPath)
	fmt.Fprintf(os.Stderr, "mutual-info evaluation calls: traces=%d hashes=%d samples=%d elapsed=%s\n", traceCalls, hashCalls, samples, time.Since(start).Round(time.Millisecond))
	fmt.Printf("max_mutual_information: %.10f bits\n", globalMax)
	if globalMax > 0.02 {
		fmt.Println("Potential weakness warning: persistent input/state dependency candidate")
	}
	if compareText != "" {
		compareMetricCSVs(splitCSVList(compareText), filepath.Join(outDir, comparisonName("comparison_mi", compareText)), "round", "max_mutual_information")
	}
}

func newMIAccumulators(rounds, trackedInputs, trackedTargets int) ([]miAccum, []miAccum, []miAccum) {
	acc := make([]miAccum, rounds+1)
	carryAcc := make([]miAccum, rounds+1)
	outputAcc := make([]miAccum, rounds+1)
	for i := range acc {
		acc[i].counts = make([]int, trackedInputs*trackedTargets*4)
		carryAcc[i].counts = make([]int, trackedInputs*1*4)
		outputAcc[i].counts = make([]int, trackedInputs*trackedTargets*4)
	}
	return acc, carryAcc, outputAcc
}

func mutualInfoWorker(workerID, first, samples, rounds int, target string, trackedInputs, trackedTargets, k, outputBits int, processed *atomic.Int64) miPartial {
	acc, carryAcc, outputAcc := newMIAccumulators(rounds, trackedInputs, trackedTargets)
	h := newAttackHash(k, rounds, outputBits)
	rng := mrand.New(mrand.NewSource(0x4D493000 ^ int64(cliEta)*0x1000003 ^ int64(first) ^ int64(workerID)*0x85EBCA6B))
	for s := 0; s < samples; s++ {
		msg := make([]byte, 64)
		rng.Read(msg)
		trace := h.TraceStateMetrics(msg, rounds)
		digest, _ := hex.DecodeString(h.HashBytes(msg))
		for r := 0; r <= rounds && r < len(trace); r++ {
			vec := miTargetBytesFromDigest(trace[r], target, digest)
			updateMICounts(acc[r].counts, msg, vec, trackedInputs, min(trackedTargets, len(vec)*8))
			carryBit := byte(0)
			if trace[r].CarryDensity >= 0.3125 {
				carryBit = 1
			}
			updateMICounts(carryAcc[r].counts, msg, []byte{carryBit}, trackedInputs, 1)
			updateMICounts(outputAcc[r].counts, msg, digest, trackedInputs, min(trackedTargets, len(digest)*8))
		}
		processed.Add(1)
	}
	return miPartial{
		acc:        acc,
		carryAcc:   carryAcc,
		outputAcc:  outputAcc,
		traceCalls: int64(samples),
		hashCalls:  int64(samples),
	}
}

func mergeMIAccumulators(dst, src []miAccum) {
	for i := range dst {
		for j, v := range src[i].counts {
			dst[i].counts[j] += v
		}
	}
}

func validHOTarget(target string) bool {
	switch target {
	case "all", "b", "e", "seed":
		return true
	default:
		return false
	}
}

func stateMetricTargetBytes(row relwe.StateTraceRound, target string) []byte {
	switch target {
	case "b":
		return wordsToBytesLocal(row.BWords)
	case "e":
		return wordsToBytesLocal(row.EWords)
	case "seed":
		return wordsToBytesLocal(row.SeedWords)
	default:
		out := wordsToBytesLocal(row.BWords)
		out = append(out, wordsToBytesLocal(row.EWords)...)
		out = append(out, wordsToBytesLocal(row.SeedWords)...)
		return out
	}
}

func wordsToBytesLocal(words []uint32) []byte {
	out := make([]byte, len(words)*4)
	for i, word := range words {
		binary.LittleEndian.PutUint32(out[i*4:], word)
	}
	return out
}

func xorBytesInPlace(dst, src []byte) {
	for i := 0; i < min(len(dst), len(src)); i++ {
		dst[i] ^= src[i]
	}
}

func hammingByteSlice(data []byte) int {
	total := 0
	for _, b := range data {
		total += bits.OnesCount8(b)
	}
	return total
}

func bitEntropy(ones, totalBits int) float64 {
	if totalBits <= 0 {
		return 0
	}
	p := float64(ones) / float64(totalBits)
	if p <= 0 || p >= 1 {
		return 0
	}
	return -p*math.Log2(p) - (1-p)*math.Log2(1-p)
}

func makeWalshMasks(inputBits, maxWeight, limit int) []walshMask {
	rng := mrand.New(mrand.NewSource(0x574D41534B))
	masks := make([]walshMask, 0, limit)
	for weight := 1; weight <= maxWeight && len(masks) < limit; weight++ {
		for i := 0; i < max(8, limit/maxWeight) && len(masks) < limit; i++ {
			bits := randomDistinctBits(rng, inputBits, weight)
			masks = append(masks, walshMask{name: "w" + strconv.Itoa(weight) + ":" + formatPositions(bits, 6), bits: bits})
		}
	}
	return masks
}

func parseWalshFocusMasks(text string) ([]walshMask, error) {
	items := splitMaskSpecs(text)
	if len(items) == 0 {
		return nil, fmt.Errorf("no masks provided")
	}
	masks := make([]walshMask, 0, len(items))
	for _, item := range items {
		name, bits, err := parseWalshMaskSpec(item)
		if err != nil {
			return nil, err
		}
		masks = append(masks, walshMask{name: name, bits: bits})
	}
	return masks, nil
}

func splitMaskSpecs(text string) []string {
	var out []string
	start := 0
	depth := 0
	for i, r := range text {
		switch r {
		case '[':
			depth++
		case ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(text[start:i])
				if part != "" {
					out = append(out, part)
				}
				start = i + 1
			}
		}
	}
	part := strings.TrimSpace(text[start:])
	if part != "" {
		out = append(out, part)
	}
	return out
}

func parseWalshMaskSpec(spec string) (string, []int, error) {
	spec = strings.TrimSpace(spec)
	open := strings.IndexByte(spec, '[')
	close := strings.LastIndexByte(spec, ']')
	if open < 0 || close < open {
		return "", nil, fmt.Errorf("mask %q must look like w3:[1,2,3]", spec)
	}
	prefix := strings.TrimSpace(strings.TrimSuffix(spec[:open], ":"))
	body := strings.TrimSpace(spec[open+1 : close])
	if prefix == "" {
		prefix = "w?"
	}
	var bitsOut []int
	if body != "" {
		for _, part := range strings.Split(body, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			v, err := strconv.Atoi(part)
			if err != nil || v < 0 {
				return "", nil, fmt.Errorf("invalid bit index %q in %q", part, spec)
			}
			bitsOut = append(bitsOut, v)
		}
	}
	if len(bitsOut) == 0 {
		return "", nil, fmt.Errorf("mask %q has no bit positions", spec)
	}
	sort.Ints(bitsOut)
	expectedWeight := -1
	if strings.HasPrefix(prefix, "w") {
		if w, err := strconv.Atoi(strings.TrimPrefix(prefix, "w")); err == nil {
			expectedWeight = w
		}
	}
	if expectedWeight >= 0 && expectedWeight != len(bitsOut) {
		return "", nil, fmt.Errorf("mask %q declares weight %d but has %d positions", spec, expectedWeight, len(bitsOut))
	}
	name := fmt.Sprintf("%s:%s", prefix, formatPositions(bitsOut, len(bitsOut)))
	return name, bitsOut, nil
}

func formatWalshMaskNames(masks []walshMask) string {
	parts := make([]string, len(masks))
	for i, mask := range masks {
		parts[i] = mask.name
	}
	return strings.Join(parts, ",")
}

func validMITarget(target string) bool {
	switch target {
	case "all", "b", "e", "seed", "output":
		return true
	default:
		return false
	}
}

func miTargetBytes(h *relwe.ReLWEHash, msg []byte, row relwe.StateTraceRound, target string) []byte {
	if target == "output" {
		digest, _ := hex.DecodeString(h.HashBytes(msg))
		return digest
	}
	return stateMetricTargetBytes(row, target)
}

func miTargetBytesFromDigest(row relwe.StateTraceRound, target string, digest []byte) []byte {
	if target == "output" {
		return digest
	}
	return stateMetricTargetBytes(row, target)
}

func updateMICounts(counts []int, msg, target []byte, inputBits, targetBits int) {
	for inBit := 0; inBit < inputBits; inBit++ {
		x := int(bitAt(msg, inBit))
		for outBit := 0; outBit < targetBits; outBit++ {
			y := int(bitAt(target, outBit))
			counts[((inBit*targetBits+outBit)*4)+(x*2+y)]++
		}
	}
}

func summarizeMI(counts []int, inputBits, targetBits int) (float64, float64, float64) {
	sum := 0.0
	maxMI := 0.0
	minMI := math.MaxFloat64
	n := 0
	for inBit := 0; inBit < inputBits; inBit++ {
		for outBit := 0; outBit < targetBits; outBit++ {
			base := (inBit*targetBits + outBit) * 4
			mi := mutualInformation2x2(counts[base], counts[base+1], counts[base+2], counts[base+3])
			sum += mi
			maxMI = math.Max(maxMI, mi)
			minMI = math.Min(minMI, mi)
			n++
		}
	}
	if n == 0 {
		return 0, 0, 0
	}
	return sum / float64(n), maxMI, minMI
}

func mutualInformation2x2(c00, c01, c10, c11 int) float64 {
	counts := [2][2]float64{{float64(c00), float64(c01)}, {float64(c10), float64(c11)}}
	total := counts[0][0] + counts[0][1] + counts[1][0] + counts[1][1]
	if total == 0 {
		return 0
	}
	px := [2]float64{counts[0][0] + counts[0][1], counts[1][0] + counts[1][1]}
	py := [2]float64{counts[0][0] + counts[1][0], counts[0][1] + counts[1][1]}
	mi := 0.0
	for x := 0; x < 2; x++ {
		for y := 0; y < 2; y++ {
			pxy := counts[x][y] / total
			if pxy == 0 {
				continue
			}
			mi += pxy * math.Log2(pxy/(px[x]/total)/(py[y]/total))
		}
	}
	return mi
}

func plotSimpleCSV(csvPath, outDir, pngName, xColumn, yColumn string) error {
	rows, err := readMetricCSV(csvPath, xColumn, yColumn)
	if err != nil {
		return err
	}
	xs := make([]int, 0, len(rows))
	values := make(map[int]float64, len(rows))
	for x, y := range rows {
		xs = append(xs, x)
		values[x] = y
	}
	sort.Ints(xs)
	return writeLinePlot(filepath.Join(outDir, pngName), xs, []plotSeries{{name: yColumn, values: values, color: color.RGBA{40, 130, 220, 255}}})
}

func compareMetricCSVs(paths []string, outPath, xColumn, yColumn string) {
	palette := []color.RGBA{{220, 60, 60, 255}, {40, 130, 220, 255}, {40, 170, 90, 255}, {180, 80, 220, 255}}
	xSeen := map[int]bool{}
	var series []plotSeries
	csvRows := [][]string{{"source", xColumn, yColumn}}
	for i, path := range paths {
		rows, err := readMetricCSV(path, xColumn, yColumn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: compare skipped %s: %v\n", path, err)
			continue
		}
		values := map[int]float64{}
		source := etaLabelFromPath(path)
		for x, y := range rows {
			xSeen[x] = true
			values[x] = y
			csvRows = append(csvRows, []string{source, strconv.Itoa(x), fmt.Sprintf("%.10f", y)})
		}
		series = append(series, plotSeries{name: source, values: values, color: palette[i%len(palette)]})
	}
	if len(series) == 0 {
		return
	}
	xs := make([]int, 0, len(xSeen))
	for x := range xSeen {
		xs = append(xs, x)
	}
	sort.Ints(xs)
	if err := writeLinePlot(outPath, xs, series); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write comparison plot: %v\n", err)
		return
	}
	fmt.Printf("comparison plot: %s\n", outPath)
	csvPath := strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".csv"
	if err := writeRowsCSV(csvPath, csvRows); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not write comparison CSV: %v\n", err)
		return
	}
	fmt.Printf("comparison CSV: %s\n", csvPath)
}

func readMetricCSV(path, xColumn, yColumn string) (map[int]float64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("no data rows")
	}
	header := map[string]int{}
	for i, name := range rows[0] {
		header[name] = i
	}
	xi, ok := header[xColumn]
	if !ok {
		return nil, fmt.Errorf("missing %s", xColumn)
	}
	yi, ok := header[yColumn]
	if !ok {
		return nil, fmt.Errorf("missing %s", yColumn)
	}
	out := map[int]float64{}
	for _, row := range rows[1:] {
		x, err := atoiCSV(row, xi)
		if err != nil {
			continue
		}
		y, err := atofCSV(row, yi)
		if err != nil {
			continue
		}
		if existing, ok := out[x]; !ok || y > existing {
			out[x] = y
		}
	}
	return out, nil
}

func comparisonName(prefix, compareText string) string {
	parts := splitCSVList(compareText)
	labels := make([]string, 0, len(parts))
	for _, path := range parts {
		labels = append(labels, etaLabelFromPath(path))
	}
	if len(labels) == 0 {
		labels = append(labels, fmt.Sprintf("eta%d", cliEta))
	}
	return prefix + "_" + strings.Join(labels, "_vs_") + ".png"
}

func writeRowsCSV(path string, rows [][]string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	for _, row := range rows {
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	writer.Flush()
	return writer.Error()
}

type smtBuilder struct {
	lines       []string
	variables   int
	constraints int
	defs        int
}

func (b *smtBuilder) line(format string, args ...any) {
	b.lines = append(b.lines, fmt.Sprintf(format, args...))
}

func (b *smtBuilder) declare(name string, width int) {
	b.line("(declare-fun %s () (_ BitVec %d))", name, width)
	b.variables++
}

func (b *smtBuilder) define(name string, width int, expr string) {
	b.line("(define-fun %s () (_ BitVec %d) %s)", name, width, expr)
	b.defs++
}

func (b *smtBuilder) assert(expr string) {
	b.line("(assert %s)", expr)
	b.constraints++
}

func satSMTExport(rounds, messageBits, outputBits int, mode string, timeoutSec int, miniCore bool) {
	fmt.Printf("\n== SAT/SMT structural attack export (eta=%d) ==\n", cliEta)
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != "preimage" && mode != "collision" && mode != "differential" {
		fmt.Fprintln(os.Stderr, "error: sat-mode must be one of: preimage, collision, differential")
		os.Exit(2)
	}
	if rounds <= 0 || messageBits <= 0 || outputBits <= 0 || timeoutSec <= 0 {
		fmt.Fprintln(os.Stderr, "error: sat-rounds, sat-message-bits, sat-output-bits, and sat-timeout-sec must be positive")
		os.Exit(2)
	}
	if !miniCore {
		fmt.Println("full ring SAT/SMT model is intentionally not emitted yet; using mini-core exporter")
	}
	if outputBits > 32 {
		fmt.Printf("sat mini-core supports at most 32 output bits; truncating requested %d to 32\n", outputBits)
		outputBits = 32
	}
	if messageBits > 64 {
		fmt.Printf("sat mini-core is intended for tiny messages; truncating requested %d to 64\n", messageBits)
		messageBits = 64
	}

	builder := buildSatMiniCore(rounds, messageBits, outputBits, mode)
	outDir := filepath.Join("out", "smt")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outDir, err)
		os.Exit(1)
	}
	outPath := filepath.Join(outDir, fmt.Sprintf("case_%s_r%d_m%d_o%d.smt2", mode, rounds, messageBits, outputBits))
	if err := os.WriteFile(outPath, []byte(strings.Join(builder.lines, "\n")+"\n"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not write %s: %v\n", outPath, err)
		os.Exit(1)
	}

	fmt.Printf("mode: %s\n", mode)
	fmt.Printf("core: mini ARX feedback core, QF_BV\n")
	fmt.Printf("rounds: %d, message_bits: %d, output_bits: %d, eta: %d\n", rounds, messageBits, outputBits, cliEta)
	fmt.Printf("variables: %d\n", builder.variables)
	fmt.Printf("definitions: %d\n", builder.defs)
	fmt.Printf("constraints: %d\n", builder.constraints)
	fmt.Printf("wrote: %s\n", outPath)
	fmt.Printf("solver suggestion: z3 -T:%d %s\n", timeoutSec, outPath)
	fmt.Println("solver status: UNKNOWN (export only; run the suggested solver command)")
}

func buildSatMiniCore(rounds, messageBits, outputBits int, mode string) smtBuilder {
	var b smtBuilder
	b.line("(set-logic QF_BV)")
	b.line("(set-option :produce-models true)")
	b.line("; Pure Re-LWE reduced SAT/SMT harness")
	b.line("; Mini-core model: symbolic message bits -> ARX state -> feedback rounds -> truncated output")
	b.line("; This intentionally models a tiny structural core, not the full polynomial ring.")
	b.line("; eta = %d", cliEta)

	switch mode {
	case "preimage":
		b.declare("m", messageBits)
		out := defineMiniCoreHash(&b, "h", "m", messageBits, rounds)
		trunc := bvLow(out, 32, outputBits)
		b.assert(fmt.Sprintf("(= %s %s)", trunc, bvConst(patternTarget(outputBits), outputBits)))
	case "collision":
		b.declare("m1", messageBits)
		b.declare("m2", messageBits)
		out1 := defineMiniCoreHash(&b, "h1", "m1", messageBits, rounds)
		out2 := defineMiniCoreHash(&b, "h2", "m2", messageBits, rounds)
		b.assert("(not (= m1 m2))")
		b.assert(fmt.Sprintf("(= %s %s)", bvLow(out1, 32, outputBits), bvLow(out2, 32, outputBits)))
	case "differential":
		b.declare("m1", messageBits)
		diff := uint64(1)
		b.define("m2", messageBits, fmt.Sprintf("(bvxor m1 %s)", bvConst(diff, messageBits)))
		out1 := defineMiniCoreHash(&b, "h1", "m1", messageBits, rounds)
		out2 := defineMiniCoreHash(&b, "h2", "m2", messageBits, rounds)
		b.define("outdiff", outputBits, fmt.Sprintf("(bvxor %s %s)", bvLow(out1, 32, outputBits), bvLow(out2, 32, outputBits)))
		threshold := max(1, outputBits/4)
		b.assert(fmt.Sprintf("(bvule %s %s)", popCountBV("outdiff", outputBits, 8), bvConst(uint64(threshold), 8)))
	}
	b.line("(check-sat)")
	b.line("(get-model)")
	return b
}

func defineMiniCoreHash(b *smtBuilder, prefix, msg string, messageBits, rounds int) string {
	w := 8
	msg8 := msgToWord(msg, messageBits, w)
	b.define(prefix+"_s0_0", w, fmt.Sprintf("(bvxor %s %s)", msg8, miniConstBV(0x65)))
	b.define(prefix+"_s0_1", w, fmt.Sprintf("(bvadd %s %s)", rotlBV(msg8, w, 1), miniConstBV(0x9b)))
	b.define(prefix+"_s0_2", w, fmt.Sprintf("(bvxor %s %s)", rotlBV(msg8, w, 3), miniConstBV(0xa7)))
	b.define(prefix+"_s0_3", w, fmt.Sprintf("(bvadd %s %s)", msg8, miniConstBV(0x3d)))

	a, c, d, e := prefix+"_s0_0", prefix+"_s0_1", prefix+"_s0_2", prefix+"_s0_3"
	for r := 0; r < rounds; r++ {
		fb := fmt.Sprintf("%s_fb_%d", prefix, r)
		b.define(fb, w, bvNary("bvxor", a, c, d, e, miniConstBV((r*0x31+0x57)&0xff)))
		na := fmt.Sprintf("%s_r%d_a", prefix, r+1)
		nb := fmt.Sprintf("%s_r%d_b", prefix, r+1)
		nc := fmt.Sprintf("%s_r%d_c", prefix, r+1)
		nd := fmt.Sprintf("%s_r%d_d", prefix, r+1)
		b.define(na, w, bvNary("bvadd", a, c, fb))
		b.define(nd, w, rotlBV(fmt.Sprintf("(bvxor %s %s)", e, na), w, 4))
		b.define(nc, w, bvNary("bvadd", d, nd, miniConstBV((r*17+11)&0xff)))
		b.define(nb, w, rotlBV(bvNary("bvxor", c, nc, fb), w, 3))
		a, c, d, e = na, nb, nc, nd
	}
	out := prefix + "_out"
	b.define(out, 32, fmt.Sprintf("(concat %s %s %s %s)", e, d, c, a))
	return out
}

func msgToWord(msg string, msgBits, wordBits int) string {
	if msgBits == wordBits {
		return msg
	}
	if msgBits < wordBits {
		return fmt.Sprintf("((_ zero_extend %d) %s)", wordBits-msgBits, msg)
	}
	return fmt.Sprintf("((_ extract %d 0) %s)", wordBits-1, msg)
}

func bvLow(expr string, exprBits, outBits int) string {
	if outBits == exprBits {
		return expr
	}
	return fmt.Sprintf("((_ extract %d 0) %s)", outBits-1, expr)
}

func rotlBV(expr string, width, shift int) string {
	shift %= width
	if shift == 0 {
		return expr
	}
	return fmt.Sprintf("((_ rotate_left %d) %s)", shift, expr)
}

func miniConstBV(base int) string {
	return fmt.Sprintf("#x%02x", miniConstByte(base))
}

func miniConstByte(base int) byte {
	etaDelta := cliEta - relwe.DefaultEta
	return byte((base ^ ((etaDelta * 0x1f) & 0xff)) & 0xff)
}

func bvNary(op string, terms ...string) string {
	if len(terms) == 0 {
		return ""
	}
	if len(terms) == 1 {
		return terms[0]
	}
	acc := fmt.Sprintf("(%s %s %s)", op, terms[0], terms[1])
	for i := 2; i < len(terms); i++ {
		acc = fmt.Sprintf("(%s %s %s)", op, acc, terms[i])
	}
	return acc
}

func bvConst(value uint64, bits int) string {
	if bits <= 0 {
		return "#b0"
	}
	var sb strings.Builder
	sb.WriteString("#b")
	for i := bits - 1; i >= 0; i-- {
		if i < 64 && ((value>>i)&1) == 1 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	return sb.String()
}

func patternTarget(bits int) uint64 {
	var v uint64
	for i := 0; i < bits && i < 64; i++ {
		if i%3 == 0 || i%5 == 0 {
			v |= 1 << i
		}
	}
	return v
}

func popCountBV(expr string, width, sumWidth int) string {
	terms := make([]string, 0, width)
	for i := 0; i < width; i++ {
		bit := fmt.Sprintf("((_ extract %d %d) %s)", i, i, expr)
		terms = append(terms, fmt.Sprintf("((_ zero_extend %d) %s)", sumWidth-1, bit))
	}
	if len(terms) == 0 {
		return bvConst(0, sumWidth)
	}
	acc := terms[0]
	for i := 1; i < len(terms); i++ {
		acc = fmt.Sprintf("(bvadd %s %s)", acc, terms[i])
	}
	return acc
}

type activeWord [8]bool

func milpDifferentialHarness(rounds []int, messageBits, outputBits, timeoutSec int) {
	fmt.Printf("\n== MILP-style active-bit differential propagation (eta=%d) ==\n", cliEta)
	messageBits, outputBits = clampMiniCoreBits("milp", messageBits, outputBits)
	if timeoutSec <= 0 {
		fmt.Fprintln(os.Stderr, "error: milp-timeout-sec must be positive")
		os.Exit(2)
	}

	candidates := lowWeightDiffCandidates(messageBits, 2, 768)
	fmt.Printf("core: mini ARX feedback core, export/estimate only\n")
	fmt.Printf("message_bits=%d output_bits=%d candidates=%d eta_noise_bound=%d timeout_hint=%ds\n", messageBits, outputBits, len(candidates), 16*cliEta, timeoutSec)
	fmt.Println("rounds | variables | constraints | min active bits | best input diff | warning")
	fmt.Println("-------+-----------+-------------+-----------------+-----------------+--------")
	for _, r := range rounds {
		minActive := outputBits + 1
		bestDiff := uint64(0)
		for _, diff := range candidates {
			active := estimateMiniCoreActiveOutput(r, messageBits, outputBits, diff)
			if active < minActive {
				minActive = active
				bestDiff = diff
			}
		}
		variables := messageBits + (r+1)*32 + r*24
		constraints := r*8*18 + outputBits
		warning := ""
		if minActive < max(2, outputBits/4) {
			warning = "Potential weak differential propagation"
		}
		fmt.Printf("%6d | %9d | %11d | %15d | 0x%016x | %s\n",
			r, variables, constraints, minActive, bestDiff, warning)
	}
}

func algebraicDegreeHarness(rounds []int, messageBits, outputBits, timeoutSec int) {
	fmt.Printf("\n== Algebraic degree propagation estimate (eta=%d) ==\n", cliEta)
	messageBits, outputBits = clampMiniCoreBits("algebraic", messageBits, outputBits)
	if timeoutSec <= 0 {
		fmt.Fprintln(os.Stderr, "error: algebraic-timeout-sec must be positive")
		os.Exit(2)
	}
	fmt.Printf("core: mini ARX feedback core, degree-only ANF approximation\n")
	fmt.Printf("message_bits=%d output_bits=%d eta_noise_bound=%d timeout_hint=%ds\n", messageBits, outputBits, 16*cliEta, timeoutSec)
	fmt.Println("rounds | max degree | mean degree | expected cap | warning")
	fmt.Println("-------+------------+-------------+--------------+--------")
	for _, r := range rounds {
		degrees := estimateMiniCoreDegrees(r, messageBits, outputBits)
		sum := 0
		maxDegree := 0
		for _, d := range degrees {
			sum += d
			if d > maxDegree {
				maxDegree = d
			}
		}
		meanDegree := float64(sum) / float64(len(degrees))
		capDegree := min(messageBits, 1<<min(r, 5))
		warning := ""
		if r >= 4 && maxDegree < min(messageBits, 8) {
			warning = "Potential low algebraic degree"
		}
		fmt.Printf("%6d | %10d | %11.2f | %12d | %s\n", r, maxDegree, meanDegree, capDegree, warning)
	}
}

func impossibleDifferentialExport(rounds []int, messageBits, outputBits, timeoutSec, candidates int) {
	fmt.Printf("\n== Impossible differential SMT-LIB2 export (eta=%d) ==\n", cliEta)
	messageBits, outputBits = clampMiniCoreBits("impossible", messageBits, outputBits)
	if timeoutSec <= 0 || candidates <= 0 {
		fmt.Fprintln(os.Stderr, "error: impossible-timeout-sec and impossible-candidates must be positive")
		os.Exit(2)
	}
	outDir := filepath.Join("out", "smt")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outDir, err)
		os.Exit(1)
	}

	rng := mrand.New(mrand.NewSource(0x1F0D1FF))
	fmt.Printf("core: mini ARX feedback core, QF_BV, export only\n")
	fmt.Printf("message_bits=%d output_bits=%d candidates_per_round=%d eta_noise_bound=%d\n", messageBits, outputBits, candidates, 16*cliEta)
	fmt.Println("rounds | candidate | variables | constraints | input diff | output diff | file")
	fmt.Println("-------+-----------+-----------+-------------+------------+-------------+-----")
	for _, r := range rounds {
		for i := 0; i < candidates; i++ {
			inDiff, outDiff := impossibleCandidate(rng, messageBits, outputBits, i)
			builder := buildImpossibleMiniCore(r, messageBits, outputBits, inDiff, outDiff)
			outPath := filepath.Join(outDir, fmt.Sprintf("impossible_r%d_m%d_o%d_c%02d.smt2", r, messageBits, outputBits, i))
			if err := os.WriteFile(outPath, []byte(strings.Join(builder.lines, "\n")+"\n"), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error: could not write %s: %v\n", outPath, err)
				os.Exit(1)
			}
			fmt.Printf("%6d | %9d | %9d | %11d | 0x%016x | 0x%08x | %s\n",
				r, i, builder.variables, builder.constraints, inDiff, uint32(outDiff), outPath)
		}
	}
	fmt.Printf("solver suggestion: z3 -T:%d out/smt/impossible_r<round>_m%d_o%d_c00.smt2\n", timeoutSec, messageBits, outputBits)
	fmt.Println("interpretation: z3 returns UNSAT => impossible differential candidate for that mini-core case")
}

func groebnerExport(rounds []int, messageBits, outputBits, timeoutSec int) {
	fmt.Printf("\n== Groebner/Sage polynomial export (eta=%d) ==\n", cliEta)
	messageBits, outputBits = clampTinyGroebnerBits(messageBits, outputBits)
	if timeoutSec <= 0 {
		fmt.Fprintln(os.Stderr, "error: groebner-timeout-sec must be positive")
		os.Exit(2)
	}
	outDir := filepath.Join("out", "groebner")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: could not create %s: %v\n", outDir, err)
		os.Exit(1)
	}

	fmt.Printf("core: tiny mini ARX feedback core over GF(2), Sage export only\n")
	fmt.Printf("message_bits=%d output_bits=%d eta_noise_bound=%d timeout_hint=%ds\n", messageBits, outputBits, 16*cliEta, timeoutSec)
	fmt.Println("rounds | variables | equations | file")
	fmt.Println("-------+-----------+-----------+-----")
	for _, r := range rounds {
		model := buildGroebnerSageMiniCore(r, messageBits, outputBits, timeoutSec)
		outPath := filepath.Join(outDir, fmt.Sprintf("case_r%d_m%d_o%d.sage", r, messageBits, outputBits))
		if err := os.WriteFile(outPath, []byte(model.text), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: could not write %s: %v\n", outPath, err)
			os.Exit(1)
		}
		fmt.Printf("%6d | %9d | %9d | %s\n", r, model.variables, model.equations, outPath)
	}
	fmt.Println("solver suggestion: sage out/groebner/case_r<round>_m<msgbits>_o<outbits>.sage")
}

func clampMiniCoreBits(label string, messageBits, outputBits int) (int, int) {
	if messageBits <= 0 || outputBits <= 0 {
		fmt.Fprintf(os.Stderr, "error: %s-message-bits and %s-output-bits must be positive\n", label, label)
		os.Exit(2)
	}
	if messageBits > 64 {
		fmt.Printf("%s mini-core supports at most 64 message bits; truncating requested %d to 64\n", label, messageBits)
		messageBits = 64
	}
	if outputBits > 32 {
		fmt.Printf("%s mini-core supports at most 32 output bits; truncating requested %d to 32\n", label, outputBits)
		outputBits = 32
	}
	return messageBits, outputBits
}

func clampTinyGroebnerBits(messageBits, outputBits int) (int, int) {
	if messageBits <= 0 || outputBits <= 0 {
		fmt.Fprintln(os.Stderr, "error: groebner-message-bits and groebner-output-bits must be positive")
		os.Exit(2)
	}
	if messageBits > 8 {
		fmt.Printf("groebner tiny core supports at most 8 message bits; truncating requested %d to 8\n", messageBits)
		messageBits = 8
	}
	if outputBits > 16 {
		fmt.Printf("groebner tiny core supports at most 16 output bits; truncating requested %d to 16\n", outputBits)
		outputBits = 16
	}
	return messageBits, outputBits
}

func lowWeightDiffCandidates(messageBits, maxWeight, limit int) []uint64 {
	var out []uint64
	for i := 0; i < messageBits && len(out) < limit; i++ {
		out = append(out, uint64(1)<<i)
	}
	if maxWeight >= 2 {
		for i := 0; i < messageBits && len(out) < limit; i++ {
			for j := i + 1; j < messageBits && len(out) < limit; j++ {
				out = append(out, (uint64(1)<<i)|(uint64(1)<<j))
			}
		}
	}
	return out
}

func estimateMiniCoreActiveOutput(rounds, messageBits, outputBits int, diff uint64) int {
	msg := activeWordFromDiff(diff, messageBits)
	a := activeXor(msg)
	c := activeAddConst(activeRotl(msg, 1))
	d := activeXor(activeRotl(msg, 3))
	e := activeAddConst(msg)
	etaWord := activeEtaWord()
	for r := 0; r < rounds; r++ {
		fb := activeXor(a, c, d, e, etaWord)
		na := activeAdd(a, c, fb)
		nd := activeRotl(activeXor(e, na), 4)
		nc := activeAddConst(activeAdd(d, nd))
		nb := activeRotl(activeXor(c, nc, fb), 3)
		a, c, d, e = na, nb, nc, nd
	}
	return countActiveOutputBits([]activeWord{a, c, d, e}, outputBits)
}

func activeEtaWord() activeWord {
	var out activeWord
	for i := 0; i < min(8, cliEta); i++ {
		out[(i*3+1)&7] = true
	}
	return out
}

func activeWordFromDiff(diff uint64, messageBits int) activeWord {
	var out activeWord
	limit := min(messageBits, 8)
	for i := 0; i < limit; i++ {
		out[i] = ((diff >> i) & 1) == 1
	}
	return out
}

func activeXor(words ...activeWord) activeWord {
	var out activeWord
	for _, w := range words {
		for i := 0; i < 8; i++ {
			out[i] = out[i] || w[i]
		}
	}
	return out
}

func activeRotl(w activeWord, shift int) activeWord {
	var out activeWord
	shift %= 8
	for i := 0; i < 8; i++ {
		out[(i+shift)&7] = w[i]
	}
	return out
}

func activeAdd(words ...activeWord) activeWord {
	if len(words) == 0 {
		return activeWord{}
	}
	acc := words[0]
	for i := 1; i < len(words); i++ {
		acc = activeAdd2(acc, words[i])
	}
	return acc
}

func activeAdd2(a, b activeWord) activeWord {
	var out activeWord
	carry := false
	for i := 0; i < 8; i++ {
		out[i] = a[i] || b[i] || carry
		if a[i] || b[i] {
			carry = true
		}
	}
	return out
}

func activeAddConst(a activeWord) activeWord {
	var out activeWord
	carry := false
	for i := 0; i < 8; i++ {
		out[i] = a[i] || carry
		if a[i] {
			carry = true
		}
	}
	return out
}

func countActiveOutputBits(words []activeWord, outputBits int) int {
	count := 0
	for bit := 0; bit < outputBits; bit++ {
		wordIndex := bit / 8
		if wordIndex >= len(words) {
			break
		}
		if words[wordIndex][bit%8] {
			count++
		}
	}
	return count
}

type degreeWord [8]int

func estimateMiniCoreDegrees(rounds, messageBits, outputBits int) []int {
	msg := degreeWordFromMessage(messageBits)
	a := degreeXor(msg)
	c := degreeAddConst(degreeRotl(msg, 1), messageBits)
	d := degreeXor(degreeRotl(msg, 3))
	e := degreeAddConst(msg, messageBits)
	for r := 0; r < rounds; r++ {
		fb := degreeXor(a, c, d, e)
		na := degreeAdd(messageBits, a, c, fb)
		nd := degreeRotl(degreeXor(e, na), 4)
		nc := degreeAddConst(degreeAdd(messageBits, d, nd), messageBits)
		nb := degreeRotl(degreeXor(c, nc, fb), 3)
		a, c, d, e = na, nb, nc, nd
	}
	words := []degreeWord{a, c, d, e}
	degrees := make([]int, 0, outputBits)
	for bit := 0; bit < outputBits; bit++ {
		wordIndex := bit / 8
		if wordIndex >= len(words) {
			break
		}
		degrees = append(degrees, words[wordIndex][bit%8])
	}
	return degrees
}

func degreeWordFromMessage(messageBits int) degreeWord {
	var out degreeWord
	for i := 0; i < min(messageBits, 8); i++ {
		out[i] = 1
	}
	return out
}

func degreeXor(words ...degreeWord) degreeWord {
	var out degreeWord
	for _, w := range words {
		for i := 0; i < 8; i++ {
			if w[i] > out[i] {
				out[i] = w[i]
			}
		}
	}
	return out
}

func degreeRotl(w degreeWord, shift int) degreeWord {
	var out degreeWord
	shift %= 8
	for i := 0; i < 8; i++ {
		out[(i+shift)&7] = w[i]
	}
	return out
}

func degreeAdd(messageBits int, words ...degreeWord) degreeWord {
	if len(words) == 0 {
		return degreeWord{}
	}
	acc := words[0]
	for i := 1; i < len(words); i++ {
		acc = degreeAdd2(acc, words[i], messageBits)
	}
	return acc
}

func degreeAdd2(a, b degreeWord, capDegree int) degreeWord {
	var out degreeWord
	carryDegree := 0
	for i := 0; i < 8; i++ {
		out[i] = max(max(a[i], b[i]), carryDegree)
		nextCarry := max(max(a[i]+b[i], a[i]+carryDegree), b[i]+carryDegree)
		if nextCarry > capDegree {
			nextCarry = capDegree
		}
		carryDegree = nextCarry
	}
	return out
}

func degreeAddConst(a degreeWord, capDegree int) degreeWord {
	var out degreeWord
	carryDegree := 0
	for i := 0; i < 8; i++ {
		out[i] = max(a[i], carryDegree)
		nextCarry := max(a[i], carryDegree)
		if a[i] > 0 && carryDegree > 0 {
			nextCarry = max(nextCarry, min(capDegree, a[i]+carryDegree))
		}
		carryDegree = nextCarry
	}
	return out
}

func impossibleCandidate(rng *mrand.Rand, messageBits, outputBits, index int) (uint64, uint64) {
	if index < messageBits {
		inDiff := uint64(1) << index
		outDiff := uint64(1) << (index % outputBits)
		return inDiff, outDiff
	}
	weight := 1 + rng.Intn(3)
	inBits := randomDistinctBits(rng, messageBits, weight)
	outBits := randomDistinctBits(rng, outputBits, weight)
	var inDiff, outDiff uint64
	for _, bit := range inBits {
		inDiff |= uint64(1) << bit
	}
	for _, bit := range outBits {
		outDiff |= uint64(1) << bit
	}
	return inDiff, outDiff
}

func buildImpossibleMiniCore(rounds, messageBits, outputBits int, inDiff, outDiff uint64) smtBuilder {
	var b smtBuilder
	b.line("(set-logic QF_BV)")
	b.line("(set-option :produce-models true)")
	b.line("; Pure Re-LWE impossible differential mini-core harness")
	b.line("; UNSAT means the requested input/output difference pair cannot occur in this reduced model.")
	b.line("; eta = %d", cliEta)
	b.declare("m1", messageBits)
	b.define("m2", messageBits, fmt.Sprintf("(bvxor m1 %s)", bvConst(inDiff, messageBits)))
	out1 := defineMiniCoreHash(&b, "h1", "m1", messageBits, rounds)
	out2 := defineMiniCoreHash(&b, "h2", "m2", messageBits, rounds)
	b.define("outdiff", outputBits, fmt.Sprintf("(bvxor %s %s)", bvLow(out1, 32, outputBits), bvLow(out2, 32, outputBits)))
	b.assert(fmt.Sprintf("(= outdiff %s)", bvConst(outDiff, outputBits)))
	b.line("(check-sat)")
	b.line("(get-model)")
	return b
}

type groebnerModel struct {
	text      string
	variables int
	equations int
}

type groebnerBuilder struct {
	vars      []string
	eqs       []string
	nextCarry int
	nextTmp   int
}

func buildGroebnerSageMiniCore(rounds, messageBits, outputBits, timeoutSec int) groebnerModel {
	g := &groebnerBuilder{}
	msg := make([]string, 8)
	for i := 0; i < messageBits; i++ {
		msg[i] = g.varName(fmt.Sprintf("m%d", i))
	}
	for i := messageBits; i < 8; i++ {
		msg[i] = "0"
	}

	a := g.defineWord("a0", xorConstWord(msg, miniConstByte(0x65)))
	c := g.addConstWord("c0", rotlExprWord(msg, 1), miniConstByte(0x9b))
	d := g.defineWord("d0", xorConstWord(rotlExprWord(msg, 3), miniConstByte(0xa7)))
	e := g.addConstWord("e0", msg, miniConstByte(0x3d))
	for r := 0; r < rounds; r++ {
		fbExpr := xorExprWords(a, c, d, e)
		fb := g.defineWord(fmt.Sprintf("fb%d", r), fbExpr)
		na := g.addWords(fmt.Sprintf("a%d", r+1), a, c, fb)
		nd := g.defineWord(fmt.Sprintf("d%d", r+1), rotlExprWord(xorExprWords(e, na), 4))
		nc := g.addConstWord(fmt.Sprintf("c%d", r+1), g.addWords(fmt.Sprintf("tc%d", r), d, nd), miniConstByte((r*17+11)&0xff))
		nb := g.defineWord(fmt.Sprintf("b%d", r+1), rotlExprWord(xorExprWords(c, nc, fb), 3))
		a, c, d, e = na, nb, nc, nd
	}

	out := concatLowWords(a, c, d, e, outputBits)
	target := patternTarget(outputBits)
	for i := 0; i < outputBits; i++ {
		bit := "0"
		if ((target >> i) & 1) == 1 {
			bit = "1"
		}
		g.eqs = append(g.eqs, fmt.Sprintf("%s + %s", out[i], bit))
	}

	var sb strings.Builder
	sb.WriteString("# Pure Re-LWE tiny mini-core Groebner harness\n")
	sb.WriteString("# Export only. This models the ARX mini-core, not the full polynomial ring.\n")
	sb.WriteString(fmt.Sprintf("# eta = %d\n", cliEta))
	sb.WriteString(fmt.Sprintf("# Suggested external limit: %d seconds\n", timeoutSec))
	sb.WriteString("from sage.all import *\n\n")
	sb.WriteString(fmt.Sprintf("names = %s\n", pythonStringList(g.vars)))
	sb.WriteString("R = PolynomialRing(GF(2), names=names, order='degrevlex')\n")
	sb.WriteString("vars = R.gens_dict()\n")
	for _, name := range g.vars {
		sb.WriteString(fmt.Sprintf("%s = vars['%s']\n", name, name))
	}
	sb.WriteString("\nF = [\n")
	for _, eq := range g.eqs {
		sb.WriteString(fmt.Sprintf("    %s,\n", eq))
	}
	sb.WriteString("]\n")
	sb.WriteString("print('variables', len(names))\n")
	sb.WriteString("print('equations', len(F))\n")
	sb.WriteString("I = ideal(F)\n")
	sb.WriteString("print('computing Groebner basis for tiny core...')\n")
	sb.WriteString("G = I.groebner_basis()\n")
	sb.WriteString("print('basis length', len(G))\n")
	sb.WriteString("print(G)\n")
	return groebnerModel{text: sb.String(), variables: len(g.vars), equations: len(g.eqs)}
}

func (g *groebnerBuilder) varName(name string) string {
	g.vars = append(g.vars, name)
	return name
}

func (g *groebnerBuilder) defineWord(prefix string, exprs []string) []string {
	out := make([]string, 8)
	for i := 0; i < 8; i++ {
		name := g.varName(fmt.Sprintf("%s_%d", prefix, i))
		g.eqs = append(g.eqs, fmt.Sprintf("%s + %s", name, exprs[i]))
		out[i] = name
	}
	return out
}

func (g *groebnerBuilder) addWords(prefix string, words ...[]string) []string {
	if len(words) == 0 {
		return constWord("0")
	}
	acc := words[0]
	for i := 1; i < len(words); i++ {
		acc = g.add2Words(fmt.Sprintf("%s_add%d", prefix, i), acc, words[i])
	}
	return g.defineWord(prefix, acc)
}

func (g *groebnerBuilder) addConstWord(prefix string, word []string, value byte) []string {
	return g.addWords(prefix, word, constWordFromByte(value))
}

func (g *groebnerBuilder) add2Words(prefix string, a, b []string) []string {
	out := make([]string, 8)
	carry := "0"
	for i := 0; i < 8; i++ {
		sum := g.varName(fmt.Sprintf("%s_s%d_%d", prefix, i, g.nextTmp))
		g.nextTmp++
		g.eqs = append(g.eqs, fmt.Sprintf("%s + %s + %s + %s", sum, a[i], b[i], carry))
		out[i] = sum
		nextCarry := g.varName(fmt.Sprintf("%s_c%d_%d", prefix, i, g.nextCarry))
		g.nextCarry++
		g.eqs = append(g.eqs, fmt.Sprintf("%s + %s*%s + %s*%s + %s*%s", nextCarry, a[i], b[i], a[i], carry, b[i], carry))
		carry = nextCarry
	}
	return out
}

func constWord(bit string) []string {
	out := make([]string, 8)
	for i := range out {
		out[i] = bit
	}
	return out
}

func constWordFromByte(value byte) []string {
	out := make([]string, 8)
	for i := range out {
		if ((value >> i) & 1) == 1 {
			out[i] = "1"
		} else {
			out[i] = "0"
		}
	}
	return out
}

func rotlExprWord(word []string, shift int) []string {
	out := make([]string, 8)
	shift %= 8
	for i := 0; i < 8; i++ {
		out[(i+shift)&7] = word[i]
	}
	return out
}

func xorExprWords(words ...[]string) []string {
	out := constWord("0")
	for _, word := range words {
		for i := 0; i < 8; i++ {
			if out[i] == "0" {
				out[i] = word[i]
			} else if word[i] != "0" {
				out[i] = fmt.Sprintf("(%s + %s)", out[i], word[i])
			}
		}
	}
	return out
}

func xorConstWord(word []string, value byte) []string {
	out := append([]string(nil), word...)
	for i := 0; i < 8; i++ {
		if ((value >> i) & 1) == 1 {
			if out[i] == "0" {
				out[i] = "1"
			} else {
				out[i] = fmt.Sprintf("(%s + 1)", out[i])
			}
		}
	}
	return out
}

func concatLowWords(a, c, d, e []string, outputBits int) []string {
	words := [][]string{a, c, d, e}
	out := make([]string, 0, outputBits)
	for bit := 0; bit < outputBits; bit++ {
		wordIndex := bit / 8
		if wordIndex >= len(words) {
			break
		}
		out = append(out, words[wordIndex][bit%8])
	}
	return out
}

func pythonStringList(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = strconv.Quote(value)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func distanceStats(distances []int) (mean, stdev float64, minDist, maxDist int) {
	minDist = distances[0]
	maxDist = distances[0]
	sum := 0
	for _, d := range distances {
		sum += d
		if d < minDist {
			minDist = d
		}
		if d > maxDist {
			maxDist = d
		}
	}
	mean = float64(sum) / float64(len(distances))
	var variance float64
	for _, d := range distances {
		delta := float64(d) - mean
		variance += delta * delta
	}
	stdev = math.Sqrt(variance / float64(len(distances)))
	return mean, stdev, minDist, maxDist
}

func avalancheQuality(meanPct, stdev, inBandRatio float64) string {
	meanError := math.Abs(meanPct - 50.0)
	stdevError := math.Abs(stdev - 8.0)
	if meanError <= 0.75 && stdevError <= 1.5 && inBandRatio >= 0.84 {
		return "Good"
	}
	if meanError <= 2.0 && stdevError <= 3.0 && inBandRatio >= 0.70 {
		return "Fair"
	}
	return "Poor"
}

func printHistogram(distances []int, binWidth, maxBar int) {
	_, _, minDist, maxDist := distanceStats(distances)
	low := (minDist / binWidth) * binWidth
	high := ((maxDist + binWidth - 1) / binWidth) * binWidth
	type bin struct {
		start int
		end   int
		count int
	}
	var bins []bin
	peak := 0
	for start := low; start <= high; start += binWidth {
		end := start + binWidth - 1
		count := 0
		for _, d := range distances {
			if start <= d && d <= end {
				count++
			}
		}
		if count > peak {
			peak = count
		}
		bins = append(bins, bin{start: start, end: end, count: count})
	}
	if peak == 0 {
		peak = 1
	}
	for _, b := range bins {
		barLen := int(math.Round(float64(maxBar) * float64(b.count) / float64(peak)))
		fmt.Printf("%3d-%3d: %5d %s\n", b.start, b.end, b.count, strings.Repeat("#", barLen))
	}
}

func randomMessageTest(rounds, attempts, threads, prefixBits, k, outputBits int) {
	fmt.Printf("\n== Goroutine random message test (eta=%d) ==\n", cliEta)
	if threads <= 0 {
		threads = 1
	}
	fmt.Printf("[random rounds=%d] workers=%d, attempts=%d\n", rounds, threads, attempts)
	start := time.Now()
	perWorker := make([]int, threads)
	for i := range perWorker {
		perWorker[i] = attempts / threads
		if i < attempts%threads {
			perWorker[i]++
		}
	}

	rowsCh := make(chan []workerRow, threads)
	var wg sync.WaitGroup
	for workerID, count := range perWorker {
		if count == 0 {
			continue
		}
		wg.Add(1)
		go func(workerID, count int) {
			defer wg.Done()
			rowsCh <- randomWorker(workerID, rounds, k, outputBits, prefixBits, count)
		}(workerID, count)
	}
	go func() {
		wg.Wait()
		close(rowsCh)
	}()

	seen := make(map[string]seenEntry)
	completed := 0
	for rows := range rowsCh {
		for _, row := range rows {
			completed++
			prev, ok := seen[row.key]
			if ok && !bytes.Equal(prev.msg, row.msg) {
				printCollision(collisionResult{
					attempts:      completed,
					key:           row.key,
					digestA:       prev.digest,
					digestB:       row.digest,
					msgA:          prev.msg,
					msgB:          row.msg,
					fullCollision: prev.digest == row.digest,
				}, fmt.Sprintf("random rounds=%d", rounds), prefixBits)
				return
			}
			seen[row.key] = seenEntry{msg: row.msg, digest: row.digest}
		}
	}
	fmt.Printf("[random rounds=%d] No collision in %d attempts (%s)\n", rounds, attempts, time.Since(start).Round(time.Millisecond))
}

func randomWorker(workerID, rounds, k, outputBits, prefixBits, attempts int) []workerRow {
	h := newAttackHash(k, rounds, outputBits)
	local := make(map[string]seenEntry)
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano() ^ int64(workerID*0x9E3779B1)))
	prefix := []byte("worker=0000|")
	binary.LittleEndian.PutUint32(prefix[7:11], uint32(workerID))
	for i := 0; i < attempts; i++ {
		msg := append(append([]byte{}, prefix...), randomMessageFrom(rng)...)
		digest := h.HashBytes(msg)
		key := digestKey(digest, prefixBits)
		if prev, ok := local[key]; ok && !bytes.Equal(prev.msg, msg) {
			return []workerRow{
				{key: key, msg: prev.msg, digest: prev.digest},
				{key: key, msg: msg, digest: digest},
			}
		}
		local[key] = seenEntry{msg: msg, digest: digest}
	}
	rows := make([]workerRow, 0, len(local))
	for key, entry := range local {
		rows = append(rows, workerRow{key: key, msg: entry.msg, digest: entry.digest})
	}
	return rows
}

func checkCollision(seen map[string]seenEntry, key, digest string, msg []byte, attempts int) *collisionResult {
	if prev, ok := seen[key]; ok {
		if bytes.Equal(prev.msg, msg) {
			return nil
		}
		return &collisionResult{
			attempts:      attempts,
			key:           key,
			digestA:       prev.digest,
			digestB:       digest,
			msgA:          prev.msg,
			msgB:          msg,
			fullCollision: prev.digest == digest,
		}
	}
	seen[key] = seenEntry{msg: msg, digest: digest}
	return nil
}

func printCollision(result collisionResult, label string, prefixBits int) {
	kind := fmt.Sprintf("%d-bit truncated", prefixBits)
	if result.fullCollision {
		kind = "FULL"
	}
	fmt.Printf("[%s] Found %s collision after %d messages!\n", label, kind, result.attempts)
	fmt.Printf("  prefix:   %d bits\n", prefixBits)
	fmt.Printf("  key:      %s\n", result.key)
	fmt.Printf("  digest A: %s\n", result.digestA)
	fmt.Printf("  digest B: %s\n", result.digestB)
	fmt.Printf("  msg A:    %s\n", hex.EncodeToString(result.msgA))
	fmt.Printf("  msg B:    %s\n", hex.EncodeToString(result.msgB))
}

func parseRounds(text string) ([]int, error) {
	var rounds []int
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		v, err := strconv.Atoi(part)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("invalid round count %q", part)
		}
		rounds = append(rounds, v)
	}
	if len(rounds) == 0 {
		return nil, fmt.Errorf("at least one round count is required")
	}
	return rounds, nil
}

func parseAttackSet(text string) map[string]bool {
	out := map[string]bool{}
	valid := map[string]bool{
		"reduced":              true,
		"birthday":             true,
		"differential":         true,
		"random":               true,
		"stat-avalanche":       true,
		"linear":               true,
		"rotational":           true,
		"cycle":                true,
		"low-entropy":          true,
		"targeted-conditional": true,
		"state-trace":          true,
		"state-evolution":      true,
		"state-rank":           true,
		"higher-order-state":   true,
		"degree-growth":        true,
		"walsh-bias":           true,
		"mutual-info":          true,
		"sat-smt":              true,
		"milp":                 true,
		"algebraic":            true,
		"impossible":           true,
		"groebner":             true,
	}
	for _, item := range strings.Split(text, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		if item == "avalanche" {
			item = "stat-avalanche"
		}
		if !valid[item] {
			fmt.Fprintf(os.Stderr, "unknown attack: %s\n", item)
			os.Exit(2)
		}
		out[item] = true
	}
	return out
}

func digestKey(digest string, prefixBits int) string {
	if prefixBits <= 0 {
		return ""
	}
	totalBits := len(digest) * 4
	if prefixBits >= totalBits {
		return digest
	}
	fullNibbles := prefixBits / 4
	remainingBits := prefixBits % 4
	if remainingBits == 0 {
		return digest[:fullNibbles]
	}
	next := hexNibble(digest[fullNibbles])
	mask := byte(0xF << (4 - remainingBits))
	return digest[:fullNibbles] + string("0123456789abcdef"[next&mask])
}

func hexNibble(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	default:
		return 0
	}
}

func hammingHex(a, b string) int {
	ab, _ := hex.DecodeString(a)
	bb, _ := hex.DecodeString(b)
	return hammingBytes(ab, bb)
}

func hammingBytes(a, b []byte) int {
	n := min(len(a), len(b))
	total := 0
	for i := 0; i < n; i++ {
		total += bits.OnesCount8(a[i] ^ b[i])
	}
	return total
}

func rotateBits(data []byte, shift int) []byte {
	bitLen := len(data) * 8
	out := make([]byte, len(data))
	if bitLen == 0 {
		return out
	}
	shift %= bitLen
	if shift < 0 {
		shift += bitLen
	}
	for i := 0; i < bitLen; i++ {
		if bitAt(data, i) == 1 {
			setBit(out, (i+shift)%bitLen)
		}
	}
	return out
}

func bitAt(data []byte, bitIndex int) byte {
	return (data[bitIndex/8] >> (bitIndex % 8)) & 1
}

func setBit(data []byte, bitIndex int) {
	data[bitIndex/8] |= byte(1 << (bitIndex % 8))
}

func flipOneBit(data []byte, bitIndex int) []byte {
	out := append([]byte{}, data...)
	out[bitIndex/8] ^= byte(1 << (bitIndex % 8))
	return out
}

func flipBits(data []byte, bitPositions []int) []byte {
	out := append([]byte{}, data...)
	for _, bitIndex := range bitPositions {
		out[bitIndex/8] ^= byte(1 << (bitIndex % 8))
	}
	return out
}

func randomDistinctBits(rng *mrand.Rand, bitLimit, count int) []int {
	if count > bitLimit {
		count = bitLimit
	}
	seen := make(map[int]struct{}, count)
	out := make([]int, 0, count)
	for len(out) < count {
		bitIndex := rng.Intn(bitLimit)
		if _, ok := seen[bitIndex]; ok {
			continue
		}
		seen[bitIndex] = struct{}{}
		out = append(out, bitIndex)
	}
	sort.Ints(out)
	return out
}

func parityAtPositions(data []byte, bitPositions []int) int {
	parity := 0
	for _, bitIndex := range bitPositions {
		parity ^= int((data[bitIndex/8] >> (bitIndex % 8)) & 1)
	}
	return parity
}

func formatPositions(positions []int, limit int) string {
	if len(positions) == 0 {
		return "[]"
	}
	n := min(len(positions), limit)
	parts := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		parts = append(parts, strconv.Itoa(positions[i]))
	}
	if len(positions) > limit {
		parts = append(parts, "...")
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func formatInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return strings.Join(parts, ",")
}

func splitWork(total, workers int) []int {
	if workers <= 0 {
		workers = 1
	}
	out := make([]int, workers)
	for i := range out {
		out[i] = total / workers
		if i < total%workers {
			out[i]++
		}
	}
	return out
}

func lowEntropyMessages() [][]byte {
	out := make([][]byte, 0)
	for _, item := range namedLowEntropyMessages() {
		out = append(out, item.message)
	}
	return out
}

func namedLowEntropyMessages() []lowEntropyResult {
	return []lowEntropyResult{
		{name: "empty", message: []byte{}},
		{name: "zero1", message: bytes.Repeat([]byte{0x00}, 1)},
		{name: "zero32", message: bytes.Repeat([]byte{0x00}, 32)},
		{name: "zero128", message: bytes.Repeat([]byte{0x00}, 128)},
		{name: "ff128", message: bytes.Repeat([]byte{0xFF}, 128)},
		{name: "aa128", message: bytes.Repeat([]byte{0xAA}, 128)},
		{name: "55128", message: bytes.Repeat([]byte{0x55}, 128)},
		{name: "inc64", message: incrementingBytes(64)},
		{name: "pattern01", message: bytes.Repeat([]byte{0x00, 0xFF}, 64)},
		{name: "short-a", message: []byte("a")},
		{name: "short-test", message: []byte("test")},
		{name: "repeat-ab", message: bytes.Repeat([]byte("ab"), 64)},
	}
}

func incrementingBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

func bitOnesRatio(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	ones := 0
	for _, b := range data {
		ones += bits.OnesCount8(b)
	}
	return float64(ones) / float64(len(data)*8)
}

func longestBitRun(data []byte) int {
	best, cur := 0, 0
	var prev byte = 2
	for i := 0; i < len(data)*8; i++ {
		b := bitAt(data, i)
		if b == prev {
			cur++
		} else {
			cur = 1
			prev = b
		}
		if cur > best {
			best = cur
		}
	}
	return best
}

func byteChiSquare(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	counts := make([]int, 256)
	for _, b := range data {
		counts[int(b)]++
	}
	expected := float64(len(data)) / 256.0
	var chi float64
	for _, c := range counts {
		delta := float64(c) - expected
		chi += delta * delta / expected
	}
	return chi
}

func similarMessage(base []byte, counter int) []byte {
	out := append(append([]byte{}, base...), []byte("|nonce=")...)
	var buf [8]byte
	for i := 0; i < 8; i++ {
		buf[i] = byte(counter >> (8 * i))
	}
	return append(out, buf[:]...)
}

func randomMessage() []byte {
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	return randomMessageFrom(rng)
}

func randomMessageFrom(rng *mrand.Rand) []byte {
	size := 1 + rng.Intn(96)
	out := make([]byte, size)
	rng.Read(out)
	return out
}

func randomBirthdayMessageFrom(rng *mrand.Rand) []byte {
	size := 32 + rng.Intn(97)
	out := make([]byte, size)
	rng.Read(out)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
