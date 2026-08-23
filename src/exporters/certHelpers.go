package exporters

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/joe-elliott/cert-exporter/src/args"
)

type certMetric struct {
	durationUntilExpiry float64
	notAfter, notBefore float64
	issuer              string
	cn                  string
	// serial is the certificate serial number in lowercase hex. Used as a
	// Prometheus label so multiple PEMs that share cn/issuer (e.g. rotated
	// service-CA bundles) do not overwrite one another.
	serial string
}

func secondsToExpiryFromCertAsFile(file string) ([]certMetric, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, "")
}

func secondsToExpiryFromCertAsBase64String(s string) ([]certMetric, error) {
	certBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, "")
}

func secondsToExpiryFromCertAsBytes(certBytes []byte, certPassword string) ([]certMetric, error) {
	var metrics []certMetric

	parsed, metrics, pemErr := parseAsPEM(certBytes)
	if parsed {
		return metrics, pemErr
	}
	// Fall back to PKCS#12 for binary keystore formats (.p12/.pfx).
	parsed, metrics, pkcsErr := parseAsPKCS(certBytes, certPassword)
	if parsed {
		return metrics, nil
	}
	// Prefer the PEM error when the payload is clearly textual; PKCS#12 ASN.1
	// errors on garbage text are noisy and change across crypto/asn1 versions.
	if pemErr != nil && !looksLikePKCS12(certBytes) {
		return nil, fmt.Errorf("failed to parse as pem and pkcs12: %w", pemErr)
	}
	if pkcsErr != nil {
		return nil, fmt.Errorf("failed to parse as pem and pkcs12: %w", pkcsErr)
	}
	return nil, fmt.Errorf("failed to parse as pem and pkcs12")
}

// looksLikePKCS12 reports whether data might be a PKCS#12/PFX binary.
// PKCS#12 is an ASN.1 SEQUENCE (tag 0x30); PEM text never starts that way.
func looksLikePKCS12(data []byte) bool {
	return len(data) > 0 && data[0] == 0x30
}

func getCertificateMetrics(cert *x509.Certificate) certMetric {
	var metric certMetric
	metric.notAfter = float64(cert.NotAfter.Unix())
	metric.notBefore = float64(cert.NotBefore.Unix())
	metric.durationUntilExpiry = time.Until(cert.NotAfter).Seconds()
	metric.issuer = cert.Issuer.CommonName
	metric.cn = cert.Subject.CommonName
	if cert.SerialNumber != nil {
		metric.serial = cert.SerialNumber.Text(16)
	}
	return metric
}

func parseAsPKCS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	var metrics []certMetric
	_, cert, caCerts, err := pkcs12.DecodeChain(certBytes, certPassword)
	if err != nil {
		return false, nil, err
	}
	metric := getCertificateMetrics(cert)
	metrics = append(metrics, metric)
	for _, cert := range caCerts {
		metric := getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}

func parseAsPEM(certBytes []byte) (bool, []certMetric, error) {
	var metrics []certMetric
	var blocks []*pem.Block

	block, rest := pem.Decode(certBytes)
	if block == nil {
		return false, metrics, fmt.Errorf("Failed to parse as a pem")
	}
	// Remove trailing whitespaces to prevent possible error in loop
	rest = []byte(strings.TrimRightFunc(string(rest), unicode.IsSpace))
	if block.Type == "CERTIFICATE" {
		blocks = append(blocks, block)
	}
	// Export the remaining certificates in the certificate chain
	for len(rest) != 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			return true, metrics, fmt.Errorf("Failed to parse intermediate as a pem")
		}
		if block.Type == "CERTIFICATE" {
			blocks = append(blocks, block)
		}
	}
	for _, block := range blocks {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return true, metrics, err
		}
		metric := getCertificateMetrics(cert)
		metrics = append(metrics, metric)
	}
	return true, metrics, nil
}

// matchGlobs reports whether s matches any of the given glob patterns.
// An empty s matches only an explicit "" or "*" pattern, so certs without
// the attribute are not swept up by broad globs accidentally.
func matchGlobs(s string, globs args.GlobArgs) bool {
	if s == "" {
		for _, pattern := range globs {
			if pattern == "" || pattern == "*" {
				return true
			}
		}
		return false
	}
	for _, pattern := range globs {
		matched, err := filepath.Match(pattern, s)
		if err != nil {
			slog.Warn("Malformed glob pattern", "pattern", pattern, "value", s, "err", err)
			continue
		}
		if matched {
			return true
		}
	}
	return false
}

// filterMetrics drops metrics whose CN or issuer matches the exclude globs.
func filterMetrics(metrics []certMetric, excludeCNGlobs, excludeIssuerGlobs args.GlobArgs) []certMetric {
	if len(excludeCNGlobs) == 0 && len(excludeIssuerGlobs) == 0 {
		return metrics
	}
	filtered := make([]certMetric, 0, len(metrics))
	for _, m := range metrics {
		if len(excludeCNGlobs) > 0 && matchGlobs(m.cn, excludeCNGlobs) {
			continue
		}
		if len(excludeIssuerGlobs) > 0 && matchGlobs(m.issuer, excludeIssuerGlobs) {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}
