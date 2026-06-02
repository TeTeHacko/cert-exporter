package exporters

import (
	"testing"

	"github.com/joe-elliott/cert-exporter/src/args"
)

func TestGetPasswordForFile(t *testing.T) {
	var specs args.PasswordSpecFlag
	specs.Set("/etc/ssl/*.jks:jkspassword")
	specs.Set("/opt/certs/**/*.p12:p12password")
	specs.Set("/var/lib/specific.pem:specificpass")

	tests := []struct {
		name            string
		filePath        string
		defaultPassword string
		want            string
	}{
		{
			name:            "matches first spec (JKS glob)",
			filePath:        "/etc/ssl/keystore.jks",
			defaultPassword: "default",
			want:            "jkspassword",
		},
		{
			name:            "matches second spec (P12 glob)",
			filePath:        "/opt/certs/subdir/cert.p12",
			defaultPassword: "default",
			want:            "p12password",
		},
		{
			name:            "matches third spec (exact file)",
			filePath:        "/var/lib/specific.pem",
			defaultPassword: "default",
			want:            "specificpass",
		},
		{
			name:            "no match returns default",
			filePath:        "/tmp/unknown.crt",
			defaultPassword: "default",
			want:            "default",
		},
		{
			name:            "no match with empty default",
			filePath:        "/tmp/unknown.crt",
			defaultPassword: "",
			want:            "",
		},
		{
			name:            "first match wins (order matters)",
			filePath:        "/etc/ssl/keystore.jks",
			defaultPassword: "fallback",
			want:            "jkspassword",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetPasswordForFile(tt.filePath, specs, tt.defaultPassword)
			if got != tt.want {
				t.Errorf("GetPasswordForFile() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetPasswordForFile_EmptySpecs(t *testing.T) {
	// With no specs, should always return default
	got := GetPasswordForFile("/any/file.jks", nil, "mydefault")
	if got != "mydefault" {
		t.Errorf("GetPasswordForFile() with nil specs = %q, want %q", got, "mydefault")
	}

	got = GetPasswordForFile("/any/file.jks", []args.PasswordSpec{}, "mydefault")
	if got != "mydefault" {
		t.Errorf("GetPasswordForFile() with empty specs = %q, want %q", got, "mydefault")
	}
}
