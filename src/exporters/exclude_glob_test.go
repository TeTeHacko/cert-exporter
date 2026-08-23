package exporters

import (
	"testing"

	"github.com/joe-elliott/cert-exporter/src/args"
)

func TestMatchGlobs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		globs args.GlobArgs
		want  bool
	}{
		{name: "exact match", input: "test-cert", globs: args.GlobArgs{"test-cert"}, want: true},
		{name: "wildcard match", input: "my-service.example.com", globs: args.GlobArgs{"*.example.com"}, want: true},
		{name: "no match", input: "other-service.internal", globs: args.GlobArgs{"*.example.com"}, want: false},
		{name: "multiple globs - first matches", input: "test-ca", globs: args.GlobArgs{"test-*", "prod-*"}, want: true},
		{name: "multiple globs - second matches", input: "prod-ca", globs: args.GlobArgs{"test-*", "prod-*"}, want: true},
		{name: "multiple globs - none match", input: "staging-ca", globs: args.GlobArgs{"test-*", "prod-*"}, want: false},
		{name: "empty string with non-star glob - no match", input: "", globs: args.GlobArgs{"test-*"}, want: false},
		{name: "empty string with star glob - matches", input: "", globs: args.GlobArgs{"*"}, want: true},
		{name: "empty string with empty pattern - matches", input: "", globs: args.GlobArgs{""}, want: true},
		{name: "empty glob list - no match", input: "anything", globs: args.GlobArgs{}, want: false},
		{name: "question mark wildcard", input: "cert-a", globs: args.GlobArgs{"cert-?"}, want: true},
		{name: "character class", input: "cert-1", globs: args.GlobArgs{"cert-[0-9]"}, want: true},
		{name: "malformed pattern is skipped", input: "cert-1", globs: args.GlobArgs{"cert-[", "cert-*"}, want: true},
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
		{cn: "web.example.com", issuer: "Let's Encrypt", durationUntilExpiry: 100},
		{cn: "internal.corp.local", issuer: "Internal CA", durationUntilExpiry: 200},
		{cn: "api.example.com", issuer: "DigiCert", durationUntilExpiry: 300},
		{cn: "db.internal", issuer: "Internal CA", durationUntilExpiry: 400},
	}

	tests := []struct {
		name               string
		excludeCNGlobs     args.GlobArgs
		excludeIssuerGlobs args.GlobArgs
		wantCNs            []string
	}{
		{
			name:    "no exclude globs - all pass through",
			wantCNs: []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal"},
		},
		{
			name:           "exclude by CN glob",
			excludeCNGlobs: args.GlobArgs{"*.example.com"},
			wantCNs:        []string{"internal.corp.local", "db.internal"},
		},
		{
			name:               "exclude by issuer glob",
			excludeIssuerGlobs: args.GlobArgs{"Internal CA"},
			wantCNs:            []string{"web.example.com", "api.example.com"},
		},
		{
			name:               "exclude by multiple criteria",
			excludeCNGlobs:     args.GlobArgs{"web.*"},
			excludeIssuerGlobs: args.GlobArgs{"DigiCert"},
			wantCNs:            []string{"internal.corp.local", "db.internal"},
		},
		{
			name:           "exclude all with wildcard",
			excludeCNGlobs: args.GlobArgs{"*"},
			wantCNs:        []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterMetrics(inputMetrics, tt.excludeCNGlobs, tt.excludeIssuerGlobs)

			if len(result) != len(tt.wantCNs) {
				t.Fatalf("filterMetrics() returned %d metrics, want %d", len(result), len(tt.wantCNs))
			}
			for i, wantCN := range tt.wantCNs {
				if result[i].cn != wantCN {
					t.Errorf("filterMetrics()[%d].cn = %q, want %q", i, result[i].cn, wantCN)
				}
			}
		})
	}
}
