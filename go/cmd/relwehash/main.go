package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"cryptography/relwe"
)

func main() {
	filePath := flag.String("file", "", "hash a file's binary contents")
	fileShort := flag.String("f", "", "hash a file's binary contents")
	rounds := flag.Int("rounds", relwe.DefaultRounds, "round count")
	pure := flag.Bool("pure", false, "deprecated alias; pure recursive mode is always used")
	k := flag.Int("k", relwe.DefaultK, "module rank")
	outputBits := flag.Int("output-bits", relwe.DefaultOutput, "digest size: 256 or 512")
	xofLen := flag.Int("xof-len", -1, "emit XOF output with this byte length")
	eta := flag.Int("eta", relwe.DefaultEta, "toy LWE noise parameter eta")
	flag.Parse()
	_ = pure

	if *eta <= 0 {
		fmt.Fprintln(os.Stderr, "error: eta must be positive")
		os.Exit(2)
	}
	if *eta > 8 {
		fmt.Fprintf(os.Stderr, "warning: eta=%d is unusually large for this toy construction\n", *eta)
	}
	h := relwe.NewFromConfig(relwe.Config{
		K:          *k,
		Rounds:     *rounds,
		OutputBits: *outputBits,
		Eta:        *eta,
	})
	path := *filePath
	if path == "" {
		path = *fileShort
	}

	if path != "" {
		if *xofLen >= 0 {
			data, err := os.ReadFile(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(hex.EncodeToString(h.XOF(data, *xofLen)))
			return
		}
		digest, err := h.HashFileE(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(digest)
		return
	}

	if flag.NArg() > 0 {
		if *xofLen >= 0 {
			fmt.Println(hex.EncodeToString(h.XOF([]byte(flag.Arg(0)), *xofLen)))
			return
		}
		fmt.Println(h.Hash(flag.Arg(0)))
		return
	}

	fmt.Printf("WARNING: %s\n", relwe.Warning)
	msg := "The stone was rolled away."
	fmt.Printf("message: %q\n", msg)
	fmt.Printf("pure-re-lwe digest: %s\n", h.Hash(msg))
	fmt.Printf("pure-re-lwe xof(64): %s\n", hex.EncodeToString(h.XOF([]byte(msg), 64)))
}
