package paranoid

import (
	"crypto/rsa"
	"errors"
	"math/big"
)

var (
	minRSABits = 2048
	maxRSABits = 8192
	minRSAExp  = 65537

	// Small primes under 1000 for trial division
	smallPrimes = []int64{
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
		73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
		157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
		239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
		331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
		421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
		509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
		613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
		709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
		821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
		919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
	}

	// ROCA small test primes
	rocaPrimes = []int64{3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53}
)

// CheckRSAPublicKey checks an RSA public key for small exponents, invalid modulus length,
// small prime divisors, and the ROCA vulnerability (CVE-2017-15361).
func CheckRSAPublicKey(pub *rsa.PublicKey, opts CheckOptions) error {
	if pub == nil || pub.N == nil {
		return errors.New("RSA public key or modulus is nil")
	}

	bitLen := pub.N.BitLen()
	if bitLen < minRSABits || bitLen > maxRSABits {
		return ErrInvalidRSAModulusBits
	}

	// Public exponent enforcement: e >= 65537 and e is odd
	if pub.E < minRSAExp || pub.E%2 == 0 {
		return ErrSmallPublicExponent
	}

	// Small prime factor trial division (< 1000)
	rem := new(big.Int)
	for _, p := range smallPrimes {
		rem.Mod(pub.N, big.NewInt(p))
		if rem.Sign() == 0 {
			return ErrSmallPrimeFactor
		}
	}

	// ROCA vulnerability check (CVE-2017-15361)
	if opts.EnforceROCA && isROCAVulnerable(pub.N) {
		return ErrROCAVulnerable
	}

	return nil
}

// CheckRSAPrivateKey checks an RSA private key for structural anomalies and close-prime
// vulnerabilities factorable via Fermat's difference of squares.
func CheckRSAPrivateKey(priv *rsa.PrivateKey, opts CheckOptions) error {
	if priv == nil {
		return errors.New("RSA private key is nil")
	}
	if err := CheckRSAPublicKey(&priv.PublicKey, opts); err != nil {
		return err
	}

	// Fermat close-prime factorization check
	if opts.EnforceFermatCheck && len(priv.Primes) >= 2 {
		p := priv.Primes[0]
		q := priv.Primes[1]
		if p != nil && q != nil {
			diff := new(big.Int).Sub(p, q)
			diff.Abs(diff)

			// Bound: |p - q| < 2^(bitLen/4)
			bitLen := priv.PublicKey.N.BitLen()
			threshold := new(big.Int).Lsh(bigOne, uint(bitLen/4))
			if diff.Cmp(threshold) < 0 {
				return ErrFermatFactorable
			}
		}
	}

	return nil
}

// isROCAVulnerable performs residue checks against the Infineon ROCA fingerprint.
func isROCAVulnerable(n *big.Int) bool {
	gen := big.NewInt(65537)
	rem := new(big.Int)

	for _, m := range rocaPrimes {
		mBig := big.NewInt(m)
		// Generate subgroup G = {65537^k mod m}
		subgroup := make(map[int64]bool)
		curr := new(big.Int).Mod(gen, mBig)
		for {
			val := curr.Int64()
			if subgroup[val] {
				break
			}
			subgroup[val] = true
			curr.Mul(curr, gen)
			curr.Mod(curr, mBig)
		}

		// Product set P = {s1 * s2 mod m | s1, s2 in subgroup}
		productSet := make(map[int64]bool)
		for s1 := range subgroup {
			for s2 := range subgroup {
				p := (s1 * s2) % m
				productSet[p] = true
			}
		}

		rem.Mod(n, mBig)
		if !productSet[rem.Int64()] {
			// Not in product set for this prime -> definitely not ROCA
			return false
		}
	}

	// Matches ROCA fingerprint across all test primes
	return true
}
