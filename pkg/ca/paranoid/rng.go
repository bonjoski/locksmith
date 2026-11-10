package paranoid

import (
	"errors"
	"io"
	"math"
)

const (
	rngSampleSize = 512
	// maxConsecutiveIdenticalBytes is the NIST SP 800-90B Repetition Count Test (RCT) threshold
	maxConsecutiveIdenticalBytes = 10
	// maxByteFrequencyThreshold is the NIST SP 800-90B Adaptive Proportion Test (APT) threshold
	// for a window of 512 bytes (expected uniform frequency is 2; 32 is > 6 sigma)
	maxByteFrequencyThreshold = 32
	// minEntropyBitsThreshold ensures sample has at least 6.5 bits/byte over 512 bytes
	minEntropyBitsThreshold = 6.5
)

// CheckRNGHealth performs pre-flight NIST SP 800-90B continuous health tests
// on the provided random byte source (e.g. crypto/rand.Reader).
// It executes:
// 1. Repetition Count Test (RCT) to detect stuck RNG hardware/software states.
// 2. Adaptive Proportion Test (APT) to detect entropy collapse.
// 3. Shannon entropy floor test (> 6.5 bits/byte across 512 samples).
func CheckRNGHealth(r io.Reader) error {
	if r == nil {
		return errors.New("RNG source is nil")
	}

	sample := make([]byte, rngSampleSize)
	if _, err := io.ReadFull(r, sample); err != nil {
		return errors.Join(ErrRNGHealthTestFailed, err)
	}

	// 1. Repetition Count Test (RCT)
	consecutiveCount := 1
	for i := 1; i < len(sample); i++ {
		if sample[i] == sample[i-1] {
			consecutiveCount++
			if consecutiveCount >= maxConsecutiveIdenticalBytes {
				return ErrRNGHealthTestFailed
			}
		} else {
			consecutiveCount = 1
		}
	}

	// 2. Adaptive Proportion Test (APT) & Shannon Entropy
	freq := make(map[byte]int)
	for _, b := range sample {
		freq[b]++
		if freq[b] > maxByteFrequencyThreshold {
			return ErrRNGHealthTestFailed
		}
	}

	// 3. Shannon Entropy Floor
	var entropy float64
	total := float64(len(sample))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	if entropy < minEntropyBitsThreshold {
		return ErrRNGHealthTestFailed
	}

	return nil
}
