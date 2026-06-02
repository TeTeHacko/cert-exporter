package args

import (
	"fmt"
	"os"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

// PasswordSpec defines a glob pattern and its associated password.
type PasswordSpec struct {
	GlobPattern string
	Password    string
}

// PasswordSpecFlag is a custom flag type for collecting multiple PasswordSpec.
type PasswordSpecFlag []PasswordSpec

// String implements flag.Value
func (psf *PasswordSpecFlag) String() string {
	if psf == nil || len(*psf) == 0 {
		return ""
	}
	var parts []string
	for _, spec := range *psf {
		// Obfuscate password in string output for help messages or logging
		parts = append(parts, fmt.Sprintf("%q:%s", spec.GlobPattern, "****"))
	}
	return strings.Join(parts, ", ")
}

// Set implements flag.Value
func (psf *PasswordSpecFlag) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format for password spec. Expected 'glob:password', got %q", value)
	}
	globPattern := strings.TrimSpace(parts[0])
	password := parts[1] // Password itself might contain colons or leading/trailing spaces

	if globPattern == "" {
		return fmt.Errorf("glob pattern cannot be empty in password spec %q", value)
	}

	if !doublestar.ValidatePattern(globPattern) {
		return fmt.Errorf("invalid glob pattern %q in spec %q", globPattern, value)
	}

	*psf = append(*psf, PasswordSpec{
		GlobPattern: globPattern,
		Password:    password,
	})
	return nil
}

// LoadPasswordSpecsFromFile reads password specs from a file, one "glob:password"
// per line. Empty lines and lines starting with '#' are ignored. This is the
// secure alternative to -cert-password-spec as it keeps passwords out of the
// process command line (visible via `ps`, /proc, container inspect, etc.).
func LoadPasswordSpecsFromFile(path string) (PasswordSpecFlag, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read password spec file %q: %w", path, err)
	}

	var specs PasswordSpecFlag
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if err := specs.Set(line); err != nil {
			return nil, fmt.Errorf("error in password spec file %q line %d: %w", path, i+1, err)
		}
	}
	return specs, nil
}

// LoadPasswordFromFile reads a single password from a file, stripping a trailing
// newline. This is the secure alternative to -cert-file-password.
func LoadPasswordFromFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read password file %q: %w", path, err)
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}
