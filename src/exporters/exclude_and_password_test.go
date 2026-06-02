package exporters

import (
	"os"
	"testing"

	"github.com/joe-elliott/cert-exporter/internal/testutil"
	"github.com/joe-elliott/cert-exporter/src/args"
	"github.com/joe-elliott/cert-exporter/src/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMatchGlobs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		globs args.GlobArgs
		want  bool
	}{
		{
			name:  "exact match",
			input: "test-cert",
			globs: args.GlobArgs{"test-cert"},
			want:  true,
		},
		{
			name:  "wildcard match",
			input: "my-service.example.com",
			globs: args.GlobArgs{"*.example.com"},
			want:  true,
		},
		{
			name:  "no match",
			input: "other-service.internal",
			globs: args.GlobArgs{"*.example.com"},
			want:  false,
		},
		{
			name:  "multiple globs - first matches",
			input: "test-ca",
			globs: args.GlobArgs{"test-*", "prod-*"},
			want:  true,
		},
		{
			name:  "multiple globs - second matches",
			input: "prod-ca",
			globs: args.GlobArgs{"test-*", "prod-*"},
			want:  true,
		},
		{
			name:  "multiple globs - none match",
			input: "staging-ca",
			globs: args.GlobArgs{"test-*", "prod-*"},
			want:  false,
		},
		{
			name:  "empty string with non-star glob - no match",
			input: "",
			globs: args.GlobArgs{"test-*"},
			want:  false,
		},
		{
			name:  "empty string with star glob - matches",
			input: "",
			globs: args.GlobArgs{"*"},
			want:  true,
		},
		{
			name:  "empty string with empty pattern - matches",
			input: "",
			globs: args.GlobArgs{""},
			want:  true,
		},
		{
			name:  "empty glob list - no match",
			input: "anything",
			globs: args.GlobArgs{},
			want:  false,
		},
		{
			name:  "question mark wildcard",
			input: "cert-a",
			globs: args.GlobArgs{"cert-?"},
			want:  true,
		},
		{
			name:  "character class",
			input: "cert-1",
			globs: args.GlobArgs{"cert-[0-9]"},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchGlobs(tt.input, tt.globs)
			if got != tt.want {
				t.Errorf("matchGlobs(%q, %v) = %v, want %v", tt.input, tt.globs, got, tt.want)
			}
		})
	}
}

func TestFilterMetrics(t *testing.T) {
	inputMetrics := []certMetric{
		{cn: "web.example.com", issuer: "Let's Encrypt", Alias: "web-alias", durationUntilExpiry: 100},
		{cn: "internal.corp.local", issuer: "Internal CA", Alias: "", durationUntilExpiry: 200},
		{cn: "api.example.com", issuer: "DigiCert", Alias: "api-alias", durationUntilExpiry: 300},
		{cn: "db.internal", issuer: "Internal CA", Alias: "db-alias", durationUntilExpiry: 400},
	}

	tests := []struct {
		name              string
		excludeCNGlobs    args.GlobArgs
		excludeAliasGlobs args.GlobArgs
		excludeIssuerGlobs args.GlobArgs
		wantCount         int
		wantCNs           []string
	}{
		{
			name:       "no exclude globs - all pass through",
			wantCount:  4,
			wantCNs:    []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal"},
		},
		{
			name:           "exclude by CN glob",
			excludeCNGlobs: args.GlobArgs{"*.example.com"},
			wantCount:      2,
			wantCNs:        []string{"internal.corp.local", "db.internal"},
		},
		{
			name:              "exclude by issuer glob",
			excludeIssuerGlobs: args.GlobArgs{"Internal CA"},
			wantCount:         2,
			wantCNs:           []string{"web.example.com", "api.example.com"},
		},
		{
			name:              "exclude by alias glob",
			excludeAliasGlobs: args.GlobArgs{"*-alias"},
			wantCount:         1,
			wantCNs:           []string{"internal.corp.local"}, // only one without alias (empty alias doesn't match)
		},
		{
			name:              "exclude by multiple criteria",
			excludeCNGlobs:    args.GlobArgs{"web.*"},
			excludeIssuerGlobs: args.GlobArgs{"DigiCert"},
			wantCount:         2,
			wantCNs:           []string{"internal.corp.local", "db.internal"},
		},
		{
			name:           "exclude all with wildcard",
			excludeCNGlobs: args.GlobArgs{"*"},
			wantCount:      0,
			wantCNs:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterMetrics(inputMetrics, tt.excludeCNGlobs, tt.excludeAliasGlobs, tt.excludeIssuerGlobs)

			if len(result) != tt.wantCount {
				t.Errorf("filterMetrics() returned %d metrics, want %d", len(result), tt.wantCount)
			}

			for i, wantCN := range tt.wantCNs {
				if i >= len(result) {
					break
				}
				if result[i].cn != wantCN {
					t.Errorf("filterMetrics()[%d].cn = %q, want %q", i, result[i].cn, wantCN)
				}
			}
		})
	}
}

func TestCertExporter_ExcludeGlobs(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	tmpDir := testutil.CreateTempCertDir(t)

	// Create two certificates
	cert1 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "included.example.com",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})
	cert1File := tmpDir + "/included.crt"
	testutil.WriteCertToFile(t, cert1.CertPEM, cert1File)

	cert2 := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "excluded.internal",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	})
	cert2File := tmpDir + "/excluded.crt"
	testutil.WriteCertToFile(t, cert2.CertPEM, cert2File)

	// Create exporter with CN exclude glob
	exporter := NewCertExporter(nil, "", args.GlobArgs{"*.internal"}, nil, nil)
	exporter.ResetMetrics()

	// Export the included cert
	err := exporter.ExportMetrics(cert1File, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed for included cert: %v", err)
	}

	// Export the excluded cert
	err = exporter.ExportMetrics(cert2File, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed for excluded cert: %v", err)
	}

	// Gather metrics - should only have the included cert
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	var metricCount int
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			metricCount = len(mf.GetMetric())
		}
	}

	if metricCount != 1 {
		t.Errorf("Expected 1 metric (excluded.internal should be filtered), got %d", metricCount)
	}
}

func TestCertExporter_WithPassword(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	tmpDir := testutil.CreateTempCertDir(t)

	// Create a PKCS12 file with password
	root := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "root-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	cert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "password-protected",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	}, root)

	password := "test-p12-password"
	pfxData := testutil.CreatePKCS12Bundle(t, cert, []*testutil.CertBundle{root}, password)
	certFile := tmpDir + "/protected.p12"
	err := os.WriteFile(certFile, pfxData, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKCS12 file: %v", err)
	}

	// Test with correct password via password spec
	var specs args.PasswordSpecFlag
	specs.Set(tmpDir + "/*.p12:" + password)

	exporter := NewCertExporter(specs, "", nil, nil, nil)
	exporter.ResetMetrics()

	err = exporter.ExportMetrics(certFile, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed with correct password: %v", err)
	}

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetric := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				foundMetric = true
			}
		}
	}

	if !foundMetric {
		t.Error("Expected metrics for password-protected PKCS12 certificate")
	}
}

func TestCertExporter_DefaultPassword(t *testing.T) {
	// Create a custom registry for this test to avoid collisions
	testRegistry := prometheus.NewRegistry()
	metrics.Init(true, testRegistry)

	tmpDir := testutil.CreateTempCertDir(t)

	// Create a PKCS12 file with password
	root := testutil.GenerateCertificate(t, testutil.CertConfig{
		CommonName:   "root-ca",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         365,
		IsCA:         true,
	})

	cert := testutil.GenerateSignedCertificate(t, testutil.CertConfig{
		CommonName:   "default-pass-cert",
		Organization: "test-org",
		Country:      "US",
		Province:     "CA",
		Days:         30,
		IsCA:         false,
	}, root)

	password := "default-password"
	pfxData := testutil.CreatePKCS12Bundle(t, cert, []*testutil.CertBundle{root}, password)
	certFile := tmpDir + "/default-pass.p12"
	err := os.WriteFile(certFile, pfxData, 0644)
	if err != nil {
		t.Fatalf("Failed to write PKCS12 file: %v", err)
	}

	// Test with default password (no spec matches)
	exporter := NewCertExporter(nil, password, nil, nil, nil)
	exporter.ResetMetrics()

	err = exporter.ExportMetrics(certFile, "test-node")
	if err != nil {
		t.Fatalf("ExportMetrics() failed with default password: %v", err)
	}

	// Verify metrics were created
	mfs, err := testRegistry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	foundMetric := false
	for _, mf := range mfs {
		if mf.GetName() == "cert_exporter_cert_expires_in_seconds" {
			if len(mf.GetMetric()) > 0 {
				foundMetric = true
			}
		}
	}

	if !foundMetric {
		t.Error("Expected metrics for PKCS12 certificate with default password")
	}
}
