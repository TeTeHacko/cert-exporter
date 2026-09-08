package exporters

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

func TestParseAsPEM(t *testing.T) {
	const certCN = "cert"
	cert := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: certCN,
		Days:       90,
		IsCA:       false,
	})
	const rootCN = "root-cert"
	root := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName: rootCN,
		Days:       365,
		IsCA:       true,
	})
	const intermediateCN = "intermediate-cert"
	intermediate := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName: intermediateCN,
		Days:       180,
		IsCA:       false,
	}, root)

	tests := []struct {
		name         string
		setupFunc    func(t *testing.T) []byte
		wantParsed   bool
		wantMetrics  int
		wantErr      bool
		validateFunc func(t *testing.T, metrics []certMetric)
	}{
		{
			name: "valid single certificate",
			setupFunc: func(t *testing.T) []byte {
				return cert.CertPEM
			},
			wantParsed:  true,
			wantMetrics: 1,
			wantErr:     false,
			validateFunc: func(t *testing.T, metrics []certMetric) {
				if metrics[0].cn != certCN {
					t.Errorf("Expected CN '%s', got '%s'", certCN, metrics[0].cn)
				}
				if metrics[0].durationUntilExpiry <= 0 {
					t.Errorf("Expected positive duration until expiry, got %f", metrics[0].durationUntilExpiry)
				}
			},
		},
		{
			name: "valid certificate chain",
			setupFunc: func(t *testing.T) []byte {
				return testutil.CreateCertBundle(intermediate, root)
			},
			wantParsed:  true,
			wantMetrics: 2,
			wantErr:     false,
			validateFunc: func(t *testing.T, metrics []certMetric) {
				if metrics[0].cn != intermediateCN {
					t.Errorf("Expected first cert CN '%s', got '%s'", intermediateCN, metrics[0].cn)
				}
				if metrics[1].cn != rootCN {
					t.Errorf("Expected second cert CN '%s', got '%s'", rootCN, metrics[1].cn)
				}
			},
		},
		{
			name: "certificate and chain with whitespaces",
			setupFunc: func(t *testing.T) []byte {
				// Combine and add whitespaces.
				combined := append(cert.CertPEM, []byte("   \n\t  \n")...)
				combined = append(combined, intermediate.CertPEM...)
				combined = append(combined, []byte("\n\n")...)
				combined = append(combined, root.CertPEM...)
				combined = append(combined, []byte("\n\t\t\n")...)
				return combined
			},
			wantParsed:  true,
			wantMetrics: 3,
			wantErr:     false,
		},
		{
			name: "certificate with private key and chain (should only parse certificates)",
			setupFunc: func(t *testing.T) []byte {
				// Combine cert and key.
				combined := append(cert.CertPEM, cert.PrivateKeyPEM...)
				// And the chain.
				combined = append(combined, intermediate.CertPEM...)
				combined = append(combined, root.CertPEM...)
				return combined
			},
			wantParsed:  true,
			wantMetrics: 3, // Should only parse the certificate, not the key.
			wantErr:     false,
		},
		{
			name: "certificate with private key (on first place) and chain (should only parse certificates)",
			setupFunc: func(t *testing.T) []byte {
				// Combine cert and key.
				combined := append(cert.PrivateKeyPEM, cert.CertPEM...)
				// And the chain.
				combined = append(combined, intermediate.CertPEM...)
				combined = append(combined, root.CertPEM...)
				return combined
			},
			wantParsed:  true,
			wantMetrics: 3, // Should only parse the certificate, not the key.
			wantErr:     false,
		},
		{
			name: "invalid PEM data",
			setupFunc: func(t *testing.T) []byte {
				return []byte("this is not a valid PEM certificate")
			},
			wantParsed:  false,
			wantMetrics: 0,
			wantErr:     true,
		},
		{
			name: "empty input",
			setupFunc: func(t *testing.T) []byte {
				return []byte("")
			},
			wantParsed:  false,
			wantMetrics: 0,
			wantErr:     true,
		},
		{
			name: "only private key (no certificate)",
			setupFunc: func(t *testing.T) []byte {
				return cert.PrivateKeyPEM
			},
			wantParsed:  true,
			wantMetrics: 0, // No certificates, only key.
			wantErr:     false,
		},
		{
			name: "corrupted certificate data",
			setupFunc: func(t *testing.T) []byte {
				// Create a PEM block with invalid certificate data.
				block := &pem.Block{
					Type:  "CERTIFICATE",
					Bytes: []byte("invalid certificate data"),
				}
				return pem.EncodeToMemory(block)
			},
			wantParsed:  true,
			wantMetrics: 0,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certBytes := tt.setupFunc(t)
			parsed, metrics, err := parseAsPEM(certBytes)

			if parsed != tt.wantParsed {
				t.Errorf("parseAsPEM() parsed = %v, want %v", parsed, tt.wantParsed)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("parseAsPEM() error = %v, wantErr %v", err, tt.wantErr)
			}

			if len(metrics) != tt.wantMetrics {
				t.Errorf("parseAsPEM() returned %d metrics, want %d", len(metrics), tt.wantMetrics)
			}

			// Validate metrics if validation function is provided.
			if tt.validateFunc != nil && len(metrics) > 0 {
				tt.validateFunc(t, metrics)
			}

			// Validate common metric properties if we have metrics.
			if len(metrics) > 0 && !tt.wantErr {
				for i, metric := range metrics {
					if metric.notBefore == 0 {
						t.Errorf("metric[%d] notBefore should not be zero", i)
					}
					if metric.notAfter == 0 {
						t.Errorf("metric[%d] notAfter should not be zero", i)
					}
					if metric.serial == "" {
						t.Errorf("metric[%d] serial should not be empty", i)
					}
				}
			}
		})
	}
}

// jksWithTrustedCert builds an in-memory JKS holding one trusted certificate
// entry per supplied bundle, keyed by the given aliases.
func jksWithTrustedCerts(t *testing.T, password string, certs map[string]*testutil.CertBundle) []byte {
	t.Helper()

	ks := keystore.New()
	for alias, bundle := range certs {
		entry := keystore.TrustedCertificateEntry{
			CreationTime: time.Now(),
			Certificate: keystore.Certificate{
				Type:    "X.509",
				Content: bundle.Cert.Raw,
			},
		}
		if err := ks.SetTrustedCertificateEntry(alias, entry); err != nil {
			t.Fatalf("SetTrustedCertificateEntry(%q) failed: %v", alias, err)
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	return buf.Bytes()
}

// jksWithPrivateKey builds an in-memory JKS holding a private key entry whose
// chain is the supplied certificate. keyPassword protects the key itself.
func jksWithPrivateKey(t *testing.T, storePassword, keyPassword string, alias string, bundle *testutil.CertBundle) []byte {
	t.Helper()

	key, err := x509.MarshalPKCS8PrivateKey(bundle.PrivateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() failed: %v", err)
	}

	ks := keystore.New()
	entry := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   key,
		CertificateChain: []keystore.Certificate{{
			Type:    "X.509",
			Content: bundle.Cert.Raw,
		}},
	}
	if err := ks.SetPrivateKeyEntry(alias, entry, []byte(keyPassword)); err != nil {
		t.Fatalf("SetPrivateKeyEntry() failed: %v", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(storePassword)); err != nil {
		t.Fatalf("Store() failed: %v", err)
	}
	return buf.Bytes()
}

func TestParseAsJKSTrustedCertificates(t *testing.T) {
	const password = "changeit"
	first := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "first-ca", Days: 90, IsCA: true})
	second := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "second-ca", Days: 90, IsCA: true})

	store := jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{
		"first":  first,
		"second": second,
	})

	parsed, metrics, err := parseAsJKS(store, password)
	if !parsed {
		t.Fatal("parseAsJKS() reported the payload is not a keystore")
	}
	if err != nil {
		t.Fatalf("parseAsJKS() returned %v, want nil", err)
	}
	if len(metrics) != 2 {
		t.Fatalf("parseAsJKS() returned %d metrics, want 2", len(metrics))
	}

	found := map[string]bool{}
	for _, m := range metrics {
		found[m.cn] = true
	}
	for _, cn := range []string{"first-ca", "second-ca"} {
		if !found[cn] {
			t.Errorf("missing a metric for cn %q, got %v", cn, found)
		}
	}
}

func TestParseAsJKSPrivateKeyChain(t *testing.T) {
	const password = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "keyed-cert", Days: 90})
	store := jksWithPrivateKey(t, password, password, "keyed", bundle)

	parsed, metrics, err := parseAsJKS(store, password)
	if !parsed || err != nil {
		t.Fatalf("parseAsJKS() = (%v, _, %v), want (true, _, nil)", parsed, err)
	}
	if len(metrics) != 1 {
		t.Fatalf("parseAsJKS() returned %d metrics, want 1", len(metrics))
	}
	if metrics[0].cn != "keyed-cert" {
		t.Errorf("cn = %q, want %q", metrics[0].cn, "keyed-cert")
	}
}

// A key protected by its own password must not cost us the rest of the
// keystore, so the entry is skipped rather than failing the whole file.
func TestParseAsJKSKeyWithOwnPasswordIsSkipped(t *testing.T) {
	const storePassword = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "keyed-cert", Days: 90})
	store := jksWithPrivateKey(t, storePassword, "a-different-password", "keyed", bundle)

	parsed, metrics, err := parseAsJKS(store, storePassword)
	if !parsed {
		t.Fatal("parseAsJKS() reported the payload is not a keystore")
	}
	if err != nil {
		t.Fatalf("parseAsJKS() returned %v, want nil", err)
	}
	if len(metrics) != 0 {
		t.Fatalf("parseAsJKS() returned %d metrics, want 0", len(metrics))
	}
}

func TestParseAsJKSWrongPassword(t *testing.T) {
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "first-ca", Days: 90, IsCA: true})
	store := jksWithTrustedCerts(t, "changeit", map[string]*testutil.CertBundle{"first": bundle})

	parsed, _, err := parseAsJKS(store, "wrong")
	if !parsed {
		t.Error("parseAsJKS() reported a format mismatch, want it recognised by magic number")
	}
	if err == nil {
		t.Error("parseAsJKS() returned nil, want an error for the wrong password")
	}
}

func TestParseAsJKSRejectsOtherFormats(t *testing.T) {
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "pem-cert", Days: 90})

	for name, payload := range map[string][]byte{
		"pem":   bundle.CertPEM,
		"empty": {},
		"short": {0xfe, 0xed},
		"junk":  []byte("not a keystore"),
	} {
		t.Run(name, func(t *testing.T) {
			parsed, metrics, err := parseAsJKS(payload, "")
			if parsed {
				t.Error("parseAsJKS() claimed the payload is a keystore")
			}
			if err != nil {
				t.Errorf("parseAsJKS() returned %v, want nil for a format mismatch", err)
			}
			if metrics != nil {
				t.Errorf("parseAsJKS() returned %v, want no metrics", metrics)
			}
		})
	}
}

// The password has to reach the parser from the exporter, which is what the
// --cert-password-file flag feeds.
func TestSecondsToExpiryFromCertAsFileReadsJKS(t *testing.T) {
	const password = "changeit"
	bundle := testutil.GenerateCertificate(t, testutil.CertConfig{CommonName: "store-cert", Days: 90, IsCA: true})
	store := jksWithTrustedCerts(t, password, map[string]*testutil.CertBundle{"store": bundle})

	file := filepath.Join(t.TempDir(), "keystore.jks")
	if err := os.WriteFile(file, store, 0o600); err != nil {
		t.Fatalf("WriteFile() failed: %v", err)
	}

	metrics, err := secondsToExpiryFromCertAsFile(file, password)
	if err != nil {
		t.Fatalf("secondsToExpiryFromCertAsFile() returned %v, want nil", err)
	}
	if len(metrics) != 1 || metrics[0].cn != "store-cert" {
		t.Fatalf("got %v, want a single metric for store-cert", metrics)
	}

	if _, err := secondsToExpiryFromCertAsFile(file, ""); err == nil {
		t.Error("secondsToExpiryFromCertAsFile() with no password returned nil, want an error")
	}
}
