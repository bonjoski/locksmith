package paranoid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"
)

// TestAdversarial_InvalidCurveAttacks verifies that points outside the curve
// or with manipulated coordinates are strictly rejected.
func TestAdversarial_InvalidCurveAttacks(t *testing.T) {
	curve := elliptic.P256()
	p := curve.Params().P

	// Test 1: Coordinate x == p (modular wrap-around attack)
	pubXEqualP := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).Set(p),
		Y:     big.NewInt(1),
	}
	if err := CheckECPublicKey(pubXEqualP); !errors.Is(err, ErrPointNotOnCurve) {
		t.Errorf("expected ErrPointNotOnCurve for x == p, got: %v", err)
	}

	// Test 2: Coordinate y == p
	pubYEqualP := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(1),
		Y:     new(big.Int).Set(p),
	}
	if err := CheckECPublicKey(pubYEqualP); !errors.Is(err, ErrPointNotOnCurve) {
		t.Errorf("expected ErrPointNotOnCurve for y == p, got: %v", err)
	}

	// Test 3: Coordinate x > p
	pubXGreaterP := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).Add(p, big.NewInt(5)),
		Y:     big.NewInt(1),
	}
	if err := CheckECPublicKey(pubXGreaterP); !errors.Is(err, ErrPointNotOnCurve) {
		t.Errorf("expected ErrPointNotOnCurve for x > p, got: %v", err)
	}

	// Test 4: Negative coordinates
	pubNeg := &ecdsa.PublicKey{
		Curve: curve,
		X:     big.NewInt(-1),
		Y:     big.NewInt(5),
	}
	if err := CheckECPublicKey(pubNeg); !errors.Is(err, ErrPointNotOnCurve) {
		t.Errorf("expected ErrPointNotOnCurve for negative coordinate, got: %v", err)
	}
}

// TestAdversarial_ScalarBoundaryAttacks verifies edge cases on private scalar boundaries.
func TestAdversarial_ScalarBoundaryAttacks(t *testing.T) {
	opts := DefaultCheckOptions()
	curve := elliptic.P256()
	n := curve.Params().N

	// 1. Scalar d == 0
	priv0 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         big.NewInt(0),
	}
	if err := CheckECPrivateKey(priv0, opts); !errors.Is(err, ErrWeakScalarRange) && !errors.Is(err, ErrPointAtInfinity) {
		t.Errorf("expected ErrWeakScalarRange or ErrPointAtInfinity for d=0, got: %v", err)
	}

	// 2. Scalar d == 1
	priv1 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         big.NewInt(1),
	}
	priv1.PublicKey.X, priv1.PublicKey.Y = curve.ScalarBaseMult(priv1.D.Bytes())
	if err := CheckECPrivateKey(priv1, opts); !errors.Is(err, ErrWeakScalarRange) {
		t.Errorf("expected ErrWeakScalarRange for d=1, got: %v", err)
	}

	// 3. Scalar d == n - 1 (order boundary)
	nMinusOne := new(big.Int).Sub(n, big.NewInt(1))
	privNMinus1 := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         nMinusOne,
	}
	privNMinus1.PublicKey.X, privNMinus1.PublicKey.Y = curve.ScalarBaseMult(privNMinus1.D.Bytes())
	if err := CheckECPrivateKey(privNMinus1, opts); !errors.Is(err, ErrWeakScalarRange) {
		t.Errorf("expected ErrWeakScalarRange for d=n-1, got: %v", err)
	}

	// 4. Scalar d == n
	privN := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: curve},
		D:         new(big.Int).Set(n),
	}
	if err := CheckECPrivateKey(privN, opts); !errors.Is(err, ErrWeakScalarRange) && !errors.Is(err, ErrPointAtInfinity) {
		t.Errorf("expected ErrWeakScalarRange or ErrPointAtInfinity for d=n, got: %v", err)
	}
}

// TestAdversarial_MismatchedKeypair verifies that a mismatched (d, Q) keypair is caught.
func TestAdversarial_MismatchedKeypair(t *testing.T) {
	opts := DefaultCheckOptions()
	priv1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Swapped public key: priv1's D with priv2's PublicKey
	mismatched := &ecdsa.PrivateKey{
		PublicKey: priv2.PublicKey,
		D:         priv1.D,
	}
	if err := CheckECPrivateKey(mismatched, opts); !errors.Is(err, ErrPointNotOnCurve) {
		t.Errorf("expected ErrPointNotOnCurve for mismatched keypair, got: %v", err)
	}
}
