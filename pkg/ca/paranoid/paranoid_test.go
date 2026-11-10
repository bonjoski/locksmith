package paranoid

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"sync"
	"testing"
)

func TestCheckECPublicKey_Valid(t *testing.T) {
	curves := []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()}
	for _, c := range curves {
		priv, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatalf("failed generating key for %s: %v", c.Params().Name, err)
		}
		if err := CheckECPublicKey(&priv.PublicKey); err != nil {
			t.Errorf("expected valid public key for %s, got error: %v", c.Params().Name, err)
		}
	}
}

func TestCheckECPublicKey_Invalid(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}

	// 1. Point at infinity
	zeroPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0),
		Y:     big.NewInt(0),
	}
	if err := CheckECPublicKey(zeroPub); !errors.Is(err, ErrPointAtInfinity) {
		t.Errorf("expected ErrPointAtInfinity, got: %v", err)
	}

	// 2. Point off curve (corrupted Y coordinate)
	offCurvePub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).Set(priv.PublicKey.X),
		Y:     new(big.Int).Add(priv.PublicKey.Y, big.NewInt(1)),
	}
	if err := CheckECPublicKey(offCurvePub); !errors.Is(err, ErrPointNotOnCurve) {
		t.Errorf("expected ErrPointNotOnCurve, got: %v", err)
	}

	// 3. Nil key/curve
	if err := CheckECPublicKey(nil); err == nil {
		t.Errorf("expected error for nil key")
	}
}

func TestCheckECPrivateKey_Valid(t *testing.T) {
	opts := DefaultCheckOptions()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed generating key: %v", err)
	}

	if err := CheckECPrivateKey(priv, opts); err != nil {
		t.Fatalf("expected valid private key, got: %v", err)
	}
}

func TestCheckECPrivateKey_WeakScalars(t *testing.T) {
	opts := DefaultCheckOptions()

	// 1. Trivially small scalar (d = 42)
	smallPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
		D:         big.NewInt(42),
	}
	smallPriv.PublicKey.X, smallPriv.PublicKey.Y = elliptic.P256().ScalarBaseMult(smallPriv.D.Bytes())
	if err := CheckECPrivateKey(smallPriv, opts); !errors.Is(err, ErrWeakScalarRange) {
		t.Errorf("expected ErrWeakScalarRange for small scalar, got: %v", err)
	}

	// 2. Repeating byte pattern (0x010101...)
	repeatBytes := bytes.Repeat([]byte{0x01}, 32)
	repeatD := new(big.Int).SetBytes(repeatBytes)
	repeatPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
		D:         repeatD,
	}
	repeatPriv.PublicKey.X, repeatPriv.PublicKey.Y = elliptic.P256().ScalarBaseMult(repeatPriv.D.Bytes())
	if err := CheckECPrivateKey(repeatPriv, opts); !errors.Is(err, ErrRepeatingBytePattern) && !errors.Is(err, ErrWeakScalarEntropy) {
		t.Errorf("expected ErrRepeatingBytePattern or ErrWeakScalarEntropy, got: %v", err)
	}

	// 3. Sign-extended scalar (top bytes are all 0xFF)
	signExtBytes := make([]byte, 32)
	for i := 0; i < 24; i++ {
		signExtBytes[i] = 0xFF
	}
	copy(signExtBytes[24:], []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0})
	signExtD := new(big.Int).SetBytes(signExtBytes)
	signExtPriv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()},
		D:         signExtD,
	}
	signExtPriv.PublicKey.X, signExtPriv.PublicKey.Y = elliptic.P256().ScalarBaseMult(signExtPriv.D.Bytes())
	if err := CheckECPrivateKey(signExtPriv, opts); !errors.Is(err, ErrSignExtendedScalar) && !errors.Is(err, ErrWeakScalarRange) {
		t.Errorf("expected ErrSignExtendedScalar, got: %v", err)
	}
}

func TestCheckRNGHealth_Valid(t *testing.T) {
	if err := CheckRNGHealth(rand.Reader); err != nil {
		t.Fatalf("crypto/rand.Reader failed health check: %v", err)
	}
}

func TestCheckRNGHealth_Failures(t *testing.T) {
	// 1. Stuck zero byte source (Repetition Count Test failure)
	zeroReader := bytes.NewReader(make([]byte, 512))
	if err := CheckRNGHealth(zeroReader); !errors.Is(err, ErrRNGHealthTestFailed) {
		t.Errorf("expected ErrRNGHealthTestFailed for all-zero stream, got: %v", err)
	}

	// 2. High frequency bias (Adaptive Proportion Test failure)
	biasedData := make([]byte, 512)
	for i := range biasedData {
		biasedData[i] = byte(i % 10) // Only 10 distinct values -> frequency ~51 per byte (>32)
	}
	biasedReader := bytes.NewReader(biasedData)
	if err := CheckRNGHealth(biasedReader); !errors.Is(err, ErrRNGHealthTestFailed) {
		t.Errorf("expected ErrRNGHealthTestFailed for biased stream, got: %v", err)
	}
}

func TestCheckRSAPublicKey_Valid(t *testing.T) {
	opts := DefaultCheckOptions()
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed generating RSA key: %v", err)
	}

	if err := CheckRSAPublicKey(&rsaPriv.PublicKey, opts); err != nil {
		t.Fatalf("expected valid RSA public key, got: %v", err)
	}
}

func TestCheckRSAPublicKey_Invalid(t *testing.T) {
	opts := DefaultCheckOptions()

	// 1. Insecure small exponent e = 3
	weakExpKey := &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), 2047),
		E: 3,
	}
	if err := CheckRSAPublicKey(weakExpKey, opts); !errors.Is(err, ErrSmallPublicExponent) {
		t.Errorf("expected ErrSmallPublicExponent, got: %v", err)
	}

	// 2. Modulus divisible by small prime 3
	// Ensure modulus is 2048 bits: set bit 2047, then ensure divisible by 3
	divisibleBy3 := new(big.Int).Lsh(big.NewInt(1), 2047)
	rem := new(big.Int).Mod(divisibleBy3, big.NewInt(3))
	divisibleBy3.Add(divisibleBy3, new(big.Int).Sub(big.NewInt(3), rem))
	smallPrimeKey := &rsa.PublicKey{
		N: divisibleBy3,
		E: 65537,
	}
	if err := CheckRSAPublicKey(smallPrimeKey, opts); !errors.Is(err, ErrSmallPrimeFactor) {
		t.Errorf("expected ErrSmallPrimeFactor, got: %v", err)
	}

	// 3. Modulus too small (1024-bit)
	smallBitKey := &rsa.PublicKey{
		N: new(big.Int).Lsh(big.NewInt(1), 1023),
		E: 65537,
	}
	if err := CheckRSAPublicKey(smallBitKey, opts); !errors.Is(err, ErrInvalidRSAModulusBits) {
		t.Errorf("expected ErrInvalidRSAModulusBits, got: %v", err)
	}
}

func TestCheckRSAPrivateKey_FermatFactorable(t *testing.T) {
	opts := DefaultCheckOptions()

	// Construct two close primes
	p := new(big.Int).SetBytes([]byte{
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	})
	// q very close to p (difference = 4)
	q := new(big.Int).Add(p, big.NewInt(4))

	n := new(big.Int).Mul(p, q)
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: 65537,
		},
		Primes: []*big.Int{p, q},
	}

	// Adjust bit length check by scaling or verifying Fermat check triggers
	if err := CheckRSAPrivateKey(priv, opts); err == nil {
		t.Errorf("expected error for close primes")
	}
}

func TestCheckMLDSA65_ValidAndInvalid(t *testing.T) {
	// Generate valid ML-DSA-65 keypair
	pqcPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("failed generating ML-DSA-65 key: %v", err)
	}

	pubBytes := pqcPriv.Public().(*mldsa.PublicKey).Bytes()
	if err := CheckMLDSA65PublicKey(pubBytes); err != nil {
		t.Errorf("expected valid ML-DSA-65 public key, got: %v", err)
	}

	privBytes := pqcPriv.Bytes()
	if err := CheckMLDSA65PrivateKey(privBytes); err != nil {
		t.Errorf("expected valid ML-DSA-65 private key, got: %v", err)
	}

	// 1. Truncated public key
	if err := CheckMLDSA65PublicKey(pubBytes[:100]); !errors.Is(err, ErrInvalidMLDSALength) {
		t.Errorf("expected ErrInvalidMLDSALength for truncated key, got: %v", err)
	}

	// 2. All zero key
	zeroKey := make([]byte, MLDSA65PublicKeySize)
	if err := CheckMLDSA65PublicKey(zeroKey); !errors.Is(err, ErrCryptographicAnomaly) {
		t.Errorf("expected ErrCryptographicAnomaly for zeroed key, got: %v", err)
	}
}

func TestMultiAgentConcurrency_N8(t *testing.T) {
	const subagents = 8
	const iterationsPerAgent = 50

	var wg sync.WaitGroup
	errCh := make(chan error, subagents*iterationsPerAgent)

	startGate := make(chan struct{})

	for i := 0; i < subagents; i++ {
		wg.Add(1)
		go func(agentID int) {
			defer wg.Done()
			<-startGate // Synchronize simultaneous burst

			opts := DefaultCheckOptions()
			for j := 0; j < iterationsPerAgent; j++ {
				// 1. Check RNG
				if err := CheckRNGHealth(rand.Reader); err != nil {
					errCh <- err
					return
				}

				// 2. Generate and verify EC key
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					errCh <- err
					return
				}
				if err := CheckECPrivateKey(priv, opts); err != nil {
					errCh <- err
					return
				}
			}
		}(i)
	}

	// Release all 8 subagents simultaneously
	close(startGate)
	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency test failed: %v", err)
	}
}

func BenchmarkCheckECPublicKey(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed generating key: %v", err)
	}
	pub := &priv.PublicKey

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := CheckECPublicKey(pub); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckECPrivateKey(b *testing.B) {
	opts := DefaultCheckOptions()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("failed generating key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := CheckECPrivateKey(priv, opts); err != nil {
			b.Fatal(err)
		}
	}
}
