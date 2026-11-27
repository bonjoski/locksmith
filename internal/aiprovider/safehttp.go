package aiprovider

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const (
	// MaxUpstreamResponseBytes caps upstream LLM HTTP response bodies at 10 MiB.
	MaxUpstreamResponseBytes int64 = 10 << 20
)

var (
	ErrUnsafeUpstreamURL   = errors.New("aiprovider: unsafe or invalid upstream base URL")
	ErrUnsafeUpstreamIP    = errors.New("aiprovider: blocked connection to non-public or metadata IP")
	ErrCrossOriginRedirect = errors.New("aiprovider: cross-origin redirect blocked")
	ErrResponseTooLarge    = errors.New("aiprovider: upstream response exceeded maximum allowed size")
	ErrInvalidModelName    = errors.New("aiprovider: invalid model identifier")

	validModelNameRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

	blockedIPPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"), // CGNAT / Tailscale / Alibaba Cloud IMDS
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), // Link-local / AWS, GCP, Azure IMDS
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 (wraps IPv4 IMDS)
		netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use
		netip.MustParsePrefix("100::/64"),       // Discard-only
		netip.MustParsePrefix("2001::/32"),      // Teredo
		netip.MustParsePrefix("2001:db8::/32"),  // Documentation
		netip.MustParsePrefix("2002::/16"),      // 6to4
		netip.MustParsePrefix("fc00::/7"),       // Unique local (includes AWS IPv6 IMDS fd00:ec2::254)
		netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
		netip.MustParsePrefix("ff00::/8"),       // IPv6 multicast
	}
)

// ValidateModelName ensures a model identifier contains only safe characters before URL construction.
func ValidateModelName(model string) error {
	if model == "" || len(model) > 128 || !validModelNameRegex.MatchString(model) {
		return fmt.Errorf("%w: %q", ErrInvalidModelName, model)
	}
	if strings.Contains(model, "..") {
		return fmt.Errorf("%w: path traversal in model %q", ErrInvalidModelName, model)
	}
	return nil
}

// isLiteralLoopbackHost returns true only for explicit local loopback hostnames/IPs.
func isLiteralLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().IsLoopback()
	}
	return false
}

func checkIPv6Restricted(addr netip.Addr, allowLoopback bool) (handled bool, err error) {
	if !addr.Is6() || addr.Is4In6() {
		return false, nil
	}
	for _, pfx := range blockedIPPrefixes {
		if pfx.Addr().Is6() && pfx.Contains(addr) {
			if allowLoopback && addr.IsLoopback() {
				return true, nil
			}
			return true, fmt.Errorf("%w: %s in restricted range %s", ErrUnsafeUpstreamIP, addr, pfx)
		}
	}
	return false, nil
}

func isNonPublicAddress(addr netip.Addr) bool {
	return !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()
}

// CheckSafeIP validates that an IP address is safe to dial.
func CheckSafeIP(addr netip.Addr, allowLoopback bool) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid IP", ErrUnsafeUpstreamIP)
	}
	if handled, err := checkIPv6Restricted(addr, allowLoopback); handled {
		return err
	}

	unmapped := addr.Unmap()
	if unmapped.IsLoopback() {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("%w: loopback address %s not permitted", ErrUnsafeUpstreamIP, unmapped)
	}
	if isNonPublicAddress(unmapped) {
		return fmt.Errorf("%w: non-public address %s", ErrUnsafeUpstreamIP, unmapped)
	}
	for _, pfx := range blockedIPPrefixes {
		if pfx.Contains(unmapped) {
			return fmt.Errorf("%w: %s in restricted range %s", ErrUnsafeUpstreamIP, unmapped, pfx)
		}
	}
	return nil
}

func parseAndValidateURLStructure(rawURL string) (*url.URL, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return nil, fmt.Errorf("%w: empty URL", ErrUnsafeUpstreamURL)
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafeUpstreamURL, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("%w: unsupported scheme %q", ErrUnsafeUpstreamURL, u.Scheme)
	}
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: malformed authority, query, or userinfo in base URL", ErrUnsafeUpstreamURL)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("%w: missing hostname", ErrUnsafeUpstreamURL)
	}
	return u, nil
}

// ValidateBaseURL validates a provider BaseURL against SSRF, scheme downgrade, and credential-in-URL abuse.
func ValidateBaseURL(rawURL string, allowLoopback bool, requireHTTPS bool) (string, error) {
	u, err := parseAndValidateURLStructure(rawURL)
	if err != nil {
		return "", err
	}
	hostname := u.Hostname()
	if requireHTTPS && u.Scheme != "https" && !(allowLoopback && isLiteralLoopbackHost(hostname)) {
		return "", fmt.Errorf("%w: https scheme required for non-loopback upstream", ErrUnsafeUpstreamURL)
	}
	if ip, err := netip.ParseAddr(hostname); err == nil {
		if err := CheckSafeIP(ip, allowLoopback); err != nil {
			return "", err
		}
	}
	return strings.TrimRight(u.String(), "/"), nil
}

// NewSafeHTTPClient returns an http.Client hardened against SSRF, DNS rebinding, and cross-origin redirects.
func NewSafeHTTPClient(timeout time.Duration, allowLoopback bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrUnsafeUpstreamIP, err)
			}
			if idx := strings.IndexByte(host, '%'); idx != -1 {
				host = host[:idx]
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrUnsafeUpstreamIP, err)
			}
			return CheckSafeIP(ip, allowLoopback)
		},
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
	}

	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) == 0 {
				return nil
			}
			if len(via) >= 3 {
				return fmt.Errorf("%w: too many redirects", ErrCrossOriginRedirect)
			}
			orig := via[0].URL
			if !strings.EqualFold(req.URL.Scheme, orig.Scheme) || !strings.EqualFold(req.URL.Host, orig.Host) {
				return fmt.Errorf("%w: redirect from %s://%s to %s://%s denied",
					ErrCrossOriginRedirect, orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
			}
			return nil
		},
	}
}

// ReadBoundedBody reads at most limit bytes from r, failing closed if the stream exceeds limit.
func ReadBoundedBody(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = MaxUpstreamResponseBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, ErrResponseTooLarge
	}
	return data, nil
}

// sanitizeTransportError strips raw *url.Error URLs so upstream URLs and query strings never leak in errors.
func sanitizeTransportError(err error) error {
	if err == nil {
		return nil
	}
	var uErr *url.Error
	if errors.As(err, &uErr) && uErr.Err != nil {
		return fmt.Errorf("%s request failed: %w", uErr.Op, uErr.Err)
	}
	return err
}
