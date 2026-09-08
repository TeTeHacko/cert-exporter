package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
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

func secondsToExpiryFromCertAsFile(file, certPassword string) ([]certMetric, error) {
	certBytes, err := os.ReadFile(file)
	if err != nil {
		return []certMetric{}, err
	}

	return secondsToExpiryFromCertAsBytes(certBytes, certPassword)
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
	// JKS keystores are identified by their own magic number, so a failure
	// there is reported in preference to the PEM and PKCS#12 guesses.
	parsed, metrics, jksErr := parseAsJKS(certBytes, certPassword)
	if parsed {
		return metrics, jksErr
	}
	// Prefer the PEM error when the payload is clearly textual; PKCS#12 ASN.1
	// errors on garbage text are noisy and change across crypto/asn1 versions.
	if pemErr != nil && !looksLikePKCS12(certBytes) {
		return nil, fmt.Errorf("failed to parse as pem, pkcs12 or jks: %w", pemErr)
	}
	if pkcsErr != nil {
		return nil, fmt.Errorf("failed to parse as pem, pkcs12 or jks: %w", pkcsErr)
	}
	return nil, fmt.Errorf("failed to parse as pem, pkcs12 or jks")
}

// looksLikePKCS12 reports whether data might be a PKCS#12/PFX binary.
// PKCS#12 is an ASN.1 SEQUENCE (tag 0x30); PEM text never starts that way.
func looksLikePKCS12(data []byte) bool {
	return len(data) > 0 && data[0] == 0x30
}

// looksLikeJKS reports whether data starts with the JKS magic number.
func looksLikeJKS(data []byte) bool {
	return len(data) >= 4 && data[0] == 0xfe && data[1] == 0xed && data[2] == 0xfe && data[3] == 0xed
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

// parseAsJKS reads certificates out of a Java KeyStore, covering both trusted
// certificate entries and the chains attached to private key entries.
//
// The keystore password also unlocks private key entries. A key protected by a
// password of its own is skipped rather than failing the whole keystore, since
// the certificates of the other entries are still worth exporting.
//
// A keystore can hold several entries sharing a cn and issuer, which collapse
// into one Prometheus series unless --include-serial-label is set.
func parseAsJKS(certBytes []byte, certPassword string) (bool, []certMetric, error) {
	if !looksLikeJKS(certBytes) {
		return false, nil, nil
	}

	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(certBytes), []byte(certPassword)); err != nil {
		// The magic number says JKS, so this is a real failure (typically a
		// wrong or missing password), not a format mismatch.
		return true, nil, fmt.Errorf("failed to load jks keystore: %w", err)
	}

	var metrics []certMetric
	for _, alias := range ks.Aliases() {
		switch {
		case ks.IsTrustedCertificateEntry(alias):
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return true, metrics, fmt.Errorf("failed to read trusted certificate entry %q: %w", alias, err)
			}
			cert, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				return true, metrics, fmt.Errorf("failed to parse trusted certificate %q: %w", alias, err)
			}
			metrics = append(metrics, getCertificateMetrics(cert))
		case ks.IsPrivateKeyEntry(alias):
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(certPassword))
			if err != nil {
				// The key has its own password; its chain stays unexported.
				continue
			}
			for i, chainCert := range entry.CertificateChain {
				cert, err := x509.ParseCertificate(chainCert.Content)
				if err != nil {
					return true, metrics, fmt.Errorf("failed to parse certificate %d in chain of %q: %w", i, alias, err)
				}
				metrics = append(metrics, getCertificateMetrics(cert))
			}
		}
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
