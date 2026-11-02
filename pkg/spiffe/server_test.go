package spiffe_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/locksmith/v2/pkg/ca"
	"github.com/bonjoski/locksmith/v2/pkg/spiffe"
)

func newUnixHTTPClient(sockPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sockPath)
			},
		},
		Timeout: 5 * time.Second,
	}
}

func parseCert(t *testing.T, pemData string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode([]byte(pemData))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("failed to decode certificate PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func shortTempSock(t *testing.T, prefix string) string {
	f, err := os.CreateTemp("/tmp", prefix+"-*.sock")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()
	_ = f.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	return path
}

func testServerHealth(t *testing.T, client *http.Client) {
	t.Helper()
	resp, err := client.Get("http://localhost/v1/health")
	if err != nil {
		t.Fatalf("GET /v1/health failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from health, got %d", resp.StatusCode)
	}
}

func testServerBundle(t *testing.T, client *http.Client) {
	t.Helper()
	bResp, err := client.Get("http://localhost/v1/bundle")
	if err != nil {
		t.Fatalf("GET /v1/bundle failed: %v", err)
	}
	defer bResp.Body.Close()
	var bundle spiffe.BundleResponse
	if err := json.NewDecoder(bResp.Body).Decode(&bundle); err != nil {
		t.Fatalf("failed decoding bundle response: %v", err)
	}
	if bundle.TrustDomain != "bonjoski.local" || len(bundle.CAPEM) == 0 {
		t.Errorf("invalid bundle response: %+v", bundle)
	}
}

func testServerSVID(t *testing.T, client *http.Client, rootCert *x509.Certificate) {
	t.Helper()
	svidURL := "http://localhost/v1/svid?spiffe_id=spiffe://bonjoski.local/ns/dev/sa/test-agent&ttl=15m"
	sResp, err := client.Get(svidURL)
	if err != nil {
		t.Fatalf("GET /v1/svid failed: %v", err)
	}
	defer sResp.Body.Close()
	if sResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from svid, got %d", sResp.StatusCode)
	}

	var svid spiffe.SVIDResponse
	if err := json.NewDecoder(sResp.Body).Decode(&svid); err != nil {
		t.Fatalf("failed decoding SVID response: %v", err)
	}

	if svid.SPIFFEID != "spiffe://bonjoski.local/ns/dev/sa/test-agent" {
		t.Errorf("SVID SPIFFE ID = %q, want spiffe://bonjoski.local/ns/dev/sa/test-agent", svid.SPIFFEID)
	}

	cert := parseCert(t, svid.CertPEM)
	if len(cert.URIs) != 1 || cert.URIs[0].String() != svid.SPIFFEID {
		t.Errorf("cert URI SAN = %v, want %s", cert.URIs, svid.SPIFFEID)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: time.Now(),
	}); err != nil {
		t.Fatalf("failed to verify issued SVID against root CA: %v", err)
	}
}

func TestWorkloadServer_EndToEnd(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Test Dual CA", "Bonjoski Test Org", 30)
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}

	sockPath := shortTempSock(t, "workload")
	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		TrustDomain: "bonjoski.local",
		CA:          rootCA,
	})
	if err != nil {
		t.Fatalf("failed to create workload server: %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		if err := ws.Start(); err != nil && err != http.ErrServerClosed {
			serverErrCh <- err
		}
	}()

	time.Sleep(100 * time.Millisecond)

	client := newUnixHTTPClient(sockPath)

	testServerHealth(t, client)
	testServerBundle(t, client)
	testServerSVID(t, client, rootCA.Certificate)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ws.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Errorf("expected socket file %s to be removed after Stop", sockPath)
	}
}

func TestWorkloadServer_VsockBridge(t *testing.T) {
	rootCA, err := ca.GenerateRootCA("Test Dual CA", "Bonjoski Test Org", 30)
	if err != nil {
		t.Fatalf("failed to generate root CA: %v", err)
	}

	sockPath := shortTempSock(t, "vsock-test")
	ws, err := spiffe.NewWorkloadServer(spiffe.ServerConfig{
		SocketPath:  sockPath,
		VsockPort:   19099,
		TrustDomain: "bonjoski.local",
		CA:          rootCA,
	})
	if err != nil {
		t.Fatalf("failed to create workload server with vsock: %v", err)
	}

	go func() {
		_ = ws.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	// Test request over vsock bridge port
	resp, err := http.Get("http://127.0.0.1:19099/v1/svid")
	if err != nil {
		t.Fatalf("GET /v1/svid over vsock failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from vsock svid, got %d", resp.StatusCode)
	}

	var svid spiffe.SVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&svid); err != nil {
		t.Fatalf("failed decoding svid response: %v", err)
	}
	if svid.SPIFFEID != "spiffe://bonjoski.local/vm/cid/3" {
		t.Errorf("expected vm CID 3 SPIFFE ID, got: %s", svid.SPIFFEID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = ws.Stop(ctx)
}
