package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math"
	"math/big"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var alphaIndex [256]int

func init() {
	for i := range alphaIndex {
		alphaIndex[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		alphaIndex[alphabet[i]] = i
	}
}

type result struct {
	address string
	seed    [32]byte
	priv    ed25519.PrivateKey
	attempt uint64
}

func validBase58(s string) bool {
	for i := 0; i < len(s); i++ {
		if alphaIndex[s[i]] < 0 {
			return false
		}
	}
	return true
}

// encodeBase58 encodes a 32-byte Solana public key. It avoids big.Int and heap-heavy generic encoders.
func encodeBase58(src []byte) string {
	zeros := 0
	for zeros < len(src) && src[zeros] == 0 {
		zeros++
	}

	// log(256)/log(58), rounded up.
	b58 := make([]byte, len(src)*138/100+1)
	length := 0
	for _, b := range src[zeros:] {
		carry := int(b)
		for i := 0; i < length; i++ {
			carry += int(b58[i]) << 8
			b58[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			b58[length] = byte(carry % 58)
			length++
			carry /= 58
		}
	}

	outLen := zeros + length
	out := make([]byte, outLen)
	for i := 0; i < zeros; i++ {
		out[i] = '1'
	}
	for i := 0; i < length; i++ {
		out[zeros+i] = alphabet[b58[length-1-i]]
	}
	return string(out)
}

func encodeKeypairBase58(priv ed25519.PrivateKey) string {
	return encodeBase58(priv)
}

// matchesPubkeyBase58 checks prefix/suffix without allocating an address string on every miss.
func matchesPubkeyBase58(src []byte, prefix, suffix string) bool {
	zeros := 0
	for zeros < len(src) && src[zeros] == 0 {
		zeros++
	}

	var b58 [45]byte // enough for 32-byte Solana public keys
	length := 0
	for _, b := range src[zeros:] {
		carry := int(b)
		for i := 0; i < length; i++ {
			carry += int(b58[i]) << 8
			b58[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			b58[length] = byte(carry % 58)
			length++
			carry /= 58
		}
	}

	addrLen := zeros + length
	charAt := func(pos int) byte {
		if pos < zeros {
			return '1'
		}
		return alphabet[b58[length-1-(pos-zeros)]]
	}

	if len(prefix) > addrLen || len(suffix) > addrLen {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if charAt(i) != prefix[i] {
			return false
		}
	}
	start := addrLen - len(suffix)
	for i := 0; i < len(suffix); i++ {
		if charAt(start+i) != suffix[i] {
			return false
		}
	}
	return true
}

func worker(ctx context.Context, id int, prefix, suffix string, passSeed []byte, attempts *atomic.Uint64, found chan<- result) {
	var seed [32]byte
	var counter uint64 = uint64(id) << 48
	buf := make([]byte, 40)
	if passSeed != nil {
		copy(buf[:32], passSeed)
	}

	// Batch entropy to avoid one getrandom syscall per key.
	randomPool := make([]byte, 32*4096)
	randomOff := len(randomPool)

	localAttempts := uint64(0)
	flush := func() uint64 {
		if localAttempts == 0 {
			return attempts.Load()
		}
		n := attempts.Add(localAttempts)
		localAttempts = 0
		return n
	}
	defer flush()

	for {
		if localAttempts&1023 == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

		if passSeed == nil {
			if randomOff >= len(randomPool) {
				if _, err := rand.Read(randomPool); err != nil {
					panic(err)
				}
				randomOff = 0
			}
			copy(seed[:], randomPool[randomOff:randomOff+32])
			randomOff += 32
		} else {
			// Deterministic stream per worker from SHA256(passSeed || counter).
			c := counter
			counter++
			for i := 0; i < 8; i++ {
				buf[39-i] = byte(c)
				c >>= 8
			}
			seed = sha256.Sum256(buf)
		}

		priv := ed25519.NewKeyFromSeed(seed[:])
		pub := priv.Public().(ed25519.PublicKey)
		localAttempts++

		if matchesPubkeyBase58(pub, prefix, suffix) {
			addr := encodeBase58(pub)
			cur := flush()
			select {
			case found <- result{address: addr, seed: seed, priv: priv, attempt: cur}:
			case <-ctx.Done():
			}
			return
		}
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}

func main() {
	prefix := flag.String("prefix", "", "match address prefix")
	suffix := flag.String("suffix", "", "match address suffix")
	threads := flag.Int("threads", runtime.NumCPU(), "worker threads")
	passphrase := flag.String("passphrase", "", "derive deterministic search stream from passphrase")
	duration := flag.Duration("duration", 0, "benchmark duration, e.g. 10s; exits without waiting for a match")
	flag.Parse()

	if *prefix == "" && *suffix == "" {
		fmt.Fprintln(os.Stderr, "Error: at least one of --prefix or --suffix required")
		os.Exit(1)
	}
	if !validBase58(*prefix) || !validBase58(*suffix) {
		fmt.Fprintln(os.Stderr, "Error: pattern must be Solana base58: 1-9 A-H J-N P-Z a-k m-z")
		os.Exit(1)
	}
	if *threads < 1 {
		*threads = 1
	}

	patternLen := len(*prefix) + len(*suffix)
	space := new(big.Int).Exp(big.NewInt(58), big.NewInt(int64(patternLen)), nil)
	avg := new(big.Int).Div(space, big.NewInt(2))
	p50 := float64(0)
	p95 := float64(0)
	if patternLen > 0 && patternLen < 12 {
		spaceF := math.Pow(58, float64(patternLen))
		// Geometric distribution: P(found by n) = 1 - (1 - 1/space)^n.
		p50 = math.Log(0.5) / math.Log1p(-1/spaceF)
		p95 = math.Log(0.05) / math.Log1p(-1/spaceF)
	}

	mode := ""
	if *prefix != "" && *suffix != "" {
		mode = fmt.Sprintf("prefix %q + suffix %q", *prefix, *suffix)
	} else if *prefix != "" {
		mode = fmt.Sprintf("prefix %q", *prefix)
	} else {
		mode = fmt.Sprintf("suffix %q", *suffix)
	}

	fmt.Printf("\nSearching for SOL address with %s...\n", mode)
	fmt.Printf("Search space: %s | Avg attempts: %s\n", space.String(), avg.String())
	if p50 > 0 {
		fmt.Printf("Probability math: p50 %.0f attempts | p95 %.0f attempts\n", p50, p95)
	}
	fmt.Printf("Using %d Go worker threads (%d CPUs)\n", *threads, runtime.NumCPU())
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println()

	var passSeed []byte
	if *passphrase != "" {
		h := sha256.Sum256([]byte(*passphrase))
		passSeed = h[:]
		fmt.Println("Passphrase: enabled (deterministic search stream)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if *duration > 0 {
		go func() {
			time.Sleep(*duration)
			cancel()
		}()
	}

	var attempts atomic.Uint64
	found := make(chan result, 1)
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			worker(ctx, id, *prefix, *suffix, passSeed, &attempts, found)
		}(i)
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case r := <-found:
			cancel()
			elapsed := time.Since(start)
			rate := float64(r.attempt) / elapsed.Seconds()
			fmt.Println(strings.Repeat("=", 60))
			fmt.Println("MATCH FOUND!")
			fmt.Println(strings.Repeat("=", 60))
			fmt.Printf("Address      : %s\n", r.address)
			fmt.Printf("Private Seed : %s\n", hex.EncodeToString(r.seed[:]))
			fmt.Printf("Keypair (bs58): %s\n", encodeKeypairBase58(r.priv))
			fmt.Printf("Attempts     : %d\n", r.attempt)
			fmt.Printf("Time         : %.1fs\n", elapsed.Seconds())
			fmt.Printf("Speed        : %.0f keys/sec (%d threads)\n", rate, *threads)
			fmt.Println(strings.Repeat("=", 60))
			wg.Wait()
			return
		case <-ticker.C:
			cur := attempts.Load()
			elapsed := time.Since(start)
			rate := float64(cur) / elapsed.Seconds()
			eta := "?"
			if rate > 0 && avg.IsUint64() {
				remaining := float64(avg.Uint64()) - float64(cur)
				if remaining < 0 {
					remaining = 0
				}
				eta = formatDuration(time.Duration(remaining/rate) * time.Second)
			}
			fmt.Printf("  ... %d attempts | %.0f keys/sec | ETA ~%s\n", cur, rate, eta)
		case <-ctx.Done():
			cancel()
			wg.Wait()
			cur := attempts.Load()
			elapsed := time.Since(start)
			rate := float64(cur) / elapsed.Seconds()
			if *duration > 0 {
				fmt.Printf("\nBENCH attempts=%d seconds=%.3f keys_per_sec=%.0f threads=%d\n", cur, elapsed.Seconds(), rate, *threads)
				return
			}
			fmt.Println("\nStopped.")
			return
		}
	}
}
