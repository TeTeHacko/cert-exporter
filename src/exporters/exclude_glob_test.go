package exporters

import (
	"strings"
	"testing"
)

func TestMatchGlobs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		globs []string
		want  bool
	}{
		{name: "exact match", input: "test-cert", globs: []string{"test-cert"}, want: true},
		{name: "wildcard match", input: "my-service.example.com", globs: []string{"*.example.com"}, want: true},
		{name: "wildcard is not a DNS wildcard", input: "a.b.example.com", globs: []string{"*.example.com"}, want: true},
		{name: "no match", input: "other-service.internal", globs: []string{"*.example.com"}, want: false},
		{name: "multiple globs - first matches", input: "test-ca", globs: []string{"test-*", "prod-*"}, want: true},
		{name: "multiple globs - second matches", input: "prod-ca", globs: []string{"test-*", "prod-*"}, want: true},
		{name: "multiple globs - none match", input: "staging-ca", globs: []string{"test-*", "prod-*"}, want: false},
		{name: "empty glob list - no match", input: "anything", globs: []string{}, want: false},
		{name: "question mark wildcard", input: "cert-a", globs: []string{"cert-?"}, want: true},
		{name: "character class", input: "cert-1", globs: []string{"cert-[0-9]"}, want: true},

		// CNs are not paths: a slash must not stop a wildcard. URI-style names
		// (SPIFFE IDs, OpenSSL-style names) contain slashes.
		{name: "star matches a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"*"}, want: true},
		{name: "doublestar matches a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"**"}, want: true},
		{name: "star crosses slashes mid-pattern", input: "spiffe://cluster.local/ns/foo", globs: []string{"spiffe://*"}, want: true},
		{name: "star matches inside a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"*cluster*"}, want: true},
		{name: "prefix glob on a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"spiffe://cluster.local/ns/*"}, want: true},
		{name: "non-matching glob on a URI CN", input: "spiffe://cluster.local/ns/foo", globs: []string{"spiffe://other.local/*"}, want: false},
		{name: "slash in an OpenSSL style name", input: "/CN=web/O=Acme", globs: []string{"*O=Acme"}, want: true},
		{name: "question mark matches a slash", input: "/", globs: []string{"?"}, want: true},

		// Braces are metacharacters, which is a change from filepath.Match.
		{name: "alternation", input: "prod-ca", globs: []string{"{test,prod}-ca"}, want: true},
		{name: "alternation with a single star branch matches everything", input: "web.example.com", globs: []string{"{*}"}, want: true},
		{name: "unescaped braces are not literal", input: "{a,b}", globs: []string{"{a,b}"}, want: false},
		{name: "escaped braces are literal", input: "{a}", globs: []string{`\{a\}`}, want: true},

		// A cert with no CN is matched only by a pattern that matches "".
		{name: "empty string with non-star glob - no match", input: "", globs: []string{"test-*"}, want: false},
		{name: "empty string with question mark - no match", input: "", globs: []string{"?"}, want: false},
		{name: "empty string with character class - no match", input: "", globs: []string{"[a-z]"}, want: false},
		{name: "empty string with star glob - matches", input: "", globs: []string{"*"}, want: true},
		{name: "empty string with doublestar glob - matches", input: "", globs: []string{"**"}, want: true},
		{name: "empty string with empty pattern - matches", input: "", globs: []string{""}, want: true},
		{name: "empty string with empty alternation branch - matches", input: "", globs: []string{"{,internal}"}, want: true},

		// The separator folding must stay injective: a NUL in a CN (which Go
		// will decode from a UTF8String) must not collide with a "/" pattern.
		{name: "slash pattern does not match a NUL in the CN", input: "a\x00b", globs: []string{"a/b"}, want: false},
		{name: "slash pattern matches an actual slash", input: "a/b", globs: []string{"a/b"}, want: true},
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

func TestValidateCertGlobs(t *testing.T) {
	tests := []struct {
		name    string
		globs   []string
		wantErr bool
	}{
		{name: "no globs", globs: nil},
		{name: "plain name", globs: []string{"web.example.com"}},
		{name: "wildcard", globs: []string{"*"}},
		{name: "doublestar", globs: []string{"**"}},
		{name: "character class", globs: []string{"cert-[0-9]"}},
		{name: "alternation", globs: []string{"{test,prod}-ca"}},
		{name: "escaped braces", globs: []string{`\{a\}`}},
		{name: "uri style", globs: []string{"spiffe://cluster.local/ns/*"}},
		{name: "unterminated character class", globs: []string{"cert-["}, wantErr: true},
		{name: "unterminated alternation", globs: []string{"{a"}, wantErr: true},
		{name: "unescaped closing brace", globs: []string{"a}b"}, wantErr: true},
		{name: "unterminated class among valid patterns", globs: []string{"cert-*", "cert-["}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCertGlobs(tt.globs)
			if tt.wantErr && err == nil {
				t.Errorf("ValidateCertGlobs(%v) = nil, want an error", tt.globs)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("ValidateCertGlobs(%v) = %v, want nil", tt.globs, err)
			}
		})
	}
}

// The startup error is the operator's only clue about which flag value is
// wrong, so it has to name the offending pattern.
func TestValidateCertGlobsErrorNamesThePattern(t *testing.T) {
	err := ValidateCertGlobs([]string{"cert-*", "cert-["})
	if err == nil {
		t.Fatal("ValidateCertGlobs() = nil, want an error")
	}
	if !strings.Contains(err.Error(), "cert-[") {
		t.Errorf("error %q does not name the offending pattern %q", err, "cert-[")
	}
}

func TestFilterMetrics(t *testing.T) {
	inputMetrics := []certMetric{
		{cn: "web.example.com", issuer: "Let's Encrypt", durationUntilExpiry: 100},
		{cn: "internal.corp.local", issuer: "Internal CA", durationUntilExpiry: 200},
		{cn: "api.example.com", issuer: "DigiCert", durationUntilExpiry: 300},
		{cn: "db.internal", issuer: "Internal CA", durationUntilExpiry: 400},
		{cn: "spiffe://cluster.local/ns/foo", issuer: "spiffe://cluster.local/ca", durationUntilExpiry: 500},
	}

	tests := []struct {
		name               string
		excludeCNGlobs     []string
		excludeIssuerGlobs []string
		wantCNs            []string
	}{
		{
			name:    "no exclude globs - all pass through",
			wantCNs: []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:           "exclude by CN glob",
			excludeCNGlobs: []string{"*.example.com"},
			wantCNs:        []string{"internal.corp.local", "db.internal", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:               "exclude by issuer glob",
			excludeIssuerGlobs: []string{"Internal CA"},
			wantCNs:            []string{"web.example.com", "api.example.com", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:               "exclude by multiple criteria",
			excludeCNGlobs:     []string{"web.*"},
			excludeIssuerGlobs: []string{"DigiCert"},
			wantCNs:            []string{"internal.corp.local", "db.internal", "spiffe://cluster.local/ns/foo"},
		},
		{
			name:           "exclude a URI CN with a wildcard that has to cross slashes",
			excludeCNGlobs: []string{"spiffe://*"},
			wantCNs:        []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal"},
		},
		{
			name:               "exclude a URI issuer with a wildcard that has to cross slashes",
			excludeIssuerGlobs: []string{"spiffe://*"},
			wantCNs:            []string{"web.example.com", "internal.corp.local", "api.example.com", "db.internal"},
		},
		{
			name:           "exclude all with wildcard",
			excludeCNGlobs: []string{"*"},
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
