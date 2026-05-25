package main

import (
	"cryptography/relwe"
	"flag"
	"fmt"
	"time"
)

func benchmarkThroughput(h *relwe.ReLWEHash, name string, dataSizeMB int, iterations int) {
	dataSize := dataSizeMB * 1024 * 1024
	data := make([]byte, dataSize)

	// Warm-up
	for i := 0; i < 5; i++ {
		h.HashBytes(data)
	}

	start := time.Now()

	for i := 0; i < iterations; i++ {
		h.HashBytes(data)
	}

	elapsed := time.Since(start)
	totalBytes := uint64(dataSize) * uint64(iterations)
	mbps := float64(totalBytes) / (1024 * 1024) / elapsed.Seconds()

	fmt.Printf("=== %s Benchmark ===\n", name)
	fmt.Printf("Data size per hash: %d MB\n", dataSizeMB)
	fmt.Printf("Iterations: %d\n", iterations)
	fmt.Printf("Total processed: %.2f GB\n", float64(totalBytes)/(1024*1024*1024))
	fmt.Printf("Elapsed time: %v\n", elapsed)
	fmt.Printf("Throughput: %.2f MB/s\n\n", mbps)
}

func main() {
	dataSizeMB := flag.Int("data-mb", 1, "data size per hash in MiB")
	iterations := flag.Int("iterations", 10, "hash iterations")
	rounds := flag.Int("rounds", relwe.DefaultRounds, "pure recursive rounds")
	flag.Parse()

	h := relwe.NewFromConfig(relwe.Config{
		K:          relwe.DefaultK,
		Rounds:     *rounds,
		OutputBits: relwe.DefaultOutput,
		Eta:        relwe.DefaultEta,
	})
	benchmarkThroughput(h, "Pure Re-LWE Hash", *dataSizeMB, *iterations)
}
