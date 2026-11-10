package paranoid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"math"
	"math/big"
)

var (
	bigOne   = big.NewInt(1)
	bigThree = big.NewInt(3)
	// minScalarThreshold is 2^64 (to prevent trivially small scalars susceptible to BSGS/Kangaroo)
	minScalarThreshold = new(big.Int).Lsh(bigOne, 64)
)

func checkCurveSupported(curve elliptic.Curve) error {
	if curve == nil {
		return errors.New("curve is nil")
	}
	name := curve.Params().Name
	if name != "P-256" && name != "P-384" && name != "P-521" {
		return ErrUnsupportedCurve
	}
	return nil
}

func checkPointCoordinatesInField(pub *ecdsa.PublicKey) error {
	p := pub.Curve.Params().P
	if pub.X.Sign() <= 0 || pub.X.Cmp(p) >= 0 || pub.Y.Sign() <= 0 || pub.Y.Cmp(p) >= 0 {
		return ErrPointNotOnCurve
	}
	return nil
}

func checkWeierstrassEquation(pub *ecdsa.PublicKey) error {
	p := pub.Curve.Params().P

	// 1. LHS = y^2 mod p
	lhs := new(big.Int).Mul(pub.Y, pub.Y)
	lhs.Mod(lhs, p)

	// 2. RHS = (x^3 - 3x + b) mod p
	x2 := new(big.Int).Mul(pub.X, pub.X)
	x2.Mod(x2, p)
	x3 := new(big.Int).Mul(x2, pub.X)
	x3.Mod(x3, p)

	threeX := new(big.Int).Mul(pub.X, bigThree)
	threeX.Mod(threeX, p)

	rhs := new(big.Int).Sub(x3, threeX)
	rhs.Add(rhs, pub.Curve.Params().B)
	rhs.Mod(rhs, p)
	if rhs.Sign() < 0 {
		rhs.Add(rhs, p)
	}

	if lhs.Cmp(rhs) != 0 {
		return ErrPointNotOnCurve
	}
	return nil
}

// CheckECPublicKey verifies that the elliptic curve public key point lies strictly
// on the curve, is not at infinity, and conforms to standard NIST prime curves.
func CheckECPublicKey(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return ErrPointAtInfinity
	}
	if pub.X.Sign() == 0 && pub.Y.Sign() == 0 {
		return ErrPointAtInfinity
	}
	if err := checkCurveSupported(pub.Curve); err != nil {
		return err
	}
	if err := checkPointCoordinatesInField(pub); err != nil {
		return err
	}
	return checkWeierstrassEquation(pub)
}

func checkScalarBounds(d, n *big.Int) error {
	if d == nil || d.Sign() == 0 {
		return ErrWeakScalarRange
	}
	nMinusOne := new(big.Int).Sub(n, bigOne)
	if d.Cmp(bigOne) <= 0 || d.Cmp(nMinusOne) >= 0 {
		return ErrWeakScalarRange
	}
	if d.Cmp(minScalarThreshold) < 0 {
		return ErrWeakScalarRange
	}
	return nil
}

func checkScalarEntropyAndWeight(dBytes []byte, minRatio float64) error {
	if hasRepeatingBytePattern(dBytes) {
		return ErrRepeatingBytePattern
	}
	if hasSignExtensionPattern(dBytes) {
		return ErrSignExtendedScalar
	}
	if minRatio > 0 && computeNormalizedEntropy(dBytes) < minRatio {
		return ErrWeakScalarEntropy
	}
	totalBits := len(dBytes) * 8
	weight := computeHammingWeight(dBytes)
	if weight < totalBits/5 || weight > (totalBits*4)/5 {
		return ErrWeakScalarEntropy
	}
	return nil
}

func padScalarToCurveLen(dBytes []byte, curveByteLen int) []byte {
	if len(dBytes) >= curveByteLen {
		return dBytes
	}
	padded := make([]byte, curveByteLen)
	copy(padded[curveByteLen-len(dBytes):], dBytes)
	return padded
}

// CheckECPrivateKey executes full cryptanalytic verification on an ECDSA private key,
// checking point integrity, scalar numerical bounds, sign-extension, repeating patterns,
// Shannon entropy, and public key mathematical correspondence.
func CheckECPrivateKey(priv *ecdsa.PrivateKey, opts CheckOptions) error {
	if priv == nil {
		return errors.New("private key is nil")
	}
	if err := CheckECPublicKey(&priv.PublicKey); err != nil {
		return err
	}
	if err := checkScalarBounds(priv.D, priv.Params().N); err != nil {
		return err
	}

	curveByteLen := (priv.Params().BitSize + 7) / 8
	dBytes := padScalarToCurveLen(priv.D.Bytes(), curveByteLen)

	if err := checkScalarEntropyAndWeight(dBytes, opts.MinEntropyRatio); err != nil {
		return err
	}

	x, y := priv.ScalarBaseMult(priv.D.Bytes())
	if x.Cmp(priv.X) != 0 || y.Cmp(priv.Y) != 0 {
		return ErrPointNotOnCurve
	}

	return nil
}

func hasRepeatingBytePattern(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	allSame := true
	for i := 1; i < len(data); i++ {
		if data[i] != data[0] {
			allSame = false
			break
		}
	}
	if allSame {
		return true
	}

	if len(data)%2 == 0 && checkPeriodicPattern(data, 2) {
		return true
	}
	if len(data)%4 == 0 && checkPeriodicPattern(data, 4) {
		return true
	}
	return false
}

func checkPeriodicPattern(data []byte, period int) bool {
	for i := period; i < len(data); i++ {
		if data[i] != data[i%period] {
			return false
		}
	}
	return true
}

func hasSignExtensionPattern(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	for i := 0; i < len(data)-8; i++ {
		if data[i] != 0xFF {
			return false
		}
	}
	return true
}

func computeHammingWeight(data []byte) int {
	weight := 0
	for _, b := range data {
		for i := 0; i < 8; i++ {
			if (b & (1 << i)) != 0 {
				weight++
			}
		}
	}
	return weight
}

func computeNormalizedEntropy(data []byte) float64 {
	if len(data) <= 1 {
		return 0
	}
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	total := float64(len(data))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	maxPossible := math.Log2(math.Min(total, 256))
	if maxPossible <= 0 {
		return 0
	}
	return entropy / maxPossible
}
