package args

import (
	"testing"
)

func TestPasswordSpecFlag_Set(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantErr     bool
		wantPattern string
		wantPass    string
	}{
		{
			name:        "valid spec with simple glob",
			input:       "/etc/ssl/*.jks:mypassword",
			wantErr:     false,
			wantPattern: "/etc/ssl/*.jks",
			wantPass:    "mypassword",
		},
		{
			name:        "valid spec with password containing colon",
			input:       "/path/*.p12:pass:word:123",
			wantErr:     false,
			wantPattern: "/path/*.p12",
			wantPass:    "pass:word:123",
		},
		{
			name:        "valid spec with empty password",
			input:       "*.jks:",
			wantErr:     false,
			wantPattern: "*.jks",
			wantPass:    "",
		},
		{
			name:    "invalid spec without colon separator",
			input:   "no-colon-here",
			wantErr: true,
		},
		{
			name:    "invalid spec with empty glob pattern",
			input:   ":password",
			wantErr: true,
		},
		{
			name:    "invalid glob pattern",
			input:   "[invalid:password",
			wantErr: true,
		},
		{
			name:        "glob with double star",
			input:       "/etc/**/*.pem:certpass",
			wantErr:     false,
			wantPattern: "/etc/**/*.pem",
			wantPass:    "certpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var psf PasswordSpecFlag
			err := psf.Set(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("PasswordSpecFlag.Set() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if len(psf) != 1 {
					t.Fatalf("Expected 1 spec, got %d", len(psf))
				}
				if psf[0].GlobPattern != tt.wantPattern {
					t.Errorf("GlobPattern = %q, want %q", psf[0].GlobPattern, tt.wantPattern)
				}
				if psf[0].Password != tt.wantPass {
					t.Errorf("Password = %q, want %q", psf[0].Password, tt.wantPass)
				}
				if psf[0].CompiledGlob == nil {
					t.Error("CompiledGlob should not be nil")
				}
			}
		})
	}
}

func TestPasswordSpecFlag_SetMultiple(t *testing.T) {
	var psf PasswordSpecFlag

	specs := []string{
		"/etc/ssl/*.jks:jkspass",
		"/opt/certs/*.p12:p12pass",
		"/var/lib/**/*.pem:pempass",
	}

	for _, spec := range specs {
		err := psf.Set(spec)
		if err != nil {
			t.Fatalf("Unexpected error setting spec %q: %v", spec, err)
		}
	}

	if len(psf) != 3 {
		t.Fatalf("Expected 3 specs, got %d", len(psf))
	}

	// Verify order is preserved
	if psf[0].GlobPattern != "/etc/ssl/*.jks" {
		t.Errorf("First spec pattern = %q, want /etc/ssl/*.jks", psf[0].GlobPattern)
	}
	if psf[1].Password != "p12pass" {
		t.Errorf("Second spec password = %q, want p12pass", psf[1].Password)
	}
	if psf[2].GlobPattern != "/var/lib/**/*.pem" {
		t.Errorf("Third spec pattern = %q, want /var/lib/**/*.pem", psf[2].GlobPattern)
	}
}

func TestPasswordSpecFlag_String(t *testing.T) {
	var psf PasswordSpecFlag

	// Empty should return ""
	if psf.String() != "" {
		t.Errorf("Empty PasswordSpecFlag.String() = %q, want empty", psf.String())
	}

	// With values should obfuscate passwords
	psf.Set("*.jks:secret123")
	result := psf.String()
	if result == "" {
		t.Error("String() should not be empty after Set()")
	}
	// Password should be obfuscated
	if contains(result, "secret123") {
		t.Errorf("String() should obfuscate password, got %q", result)
	}
}

func TestPasswordSpecFlag_GlobMatching(t *testing.T) {
	var psf PasswordSpecFlag
	psf.Set("/etc/ssl/*.jks:jkspass")

	if !psf[0].CompiledGlob.Match("/etc/ssl/keystore.jks") {
		t.Error("Glob should match /etc/ssl/keystore.jks")
	}
	if psf[0].CompiledGlob.Match("/etc/ssl/cert.pem") {
		t.Error("Glob should not match /etc/ssl/cert.pem")
	}
	if psf[0].CompiledGlob.Match("/opt/ssl/keystore.jks") {
		t.Error("Glob should not match /opt/ssl/keystore.jks")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
