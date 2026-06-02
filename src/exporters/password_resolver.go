package exporters

import (
	"github.com/bmatcuk/doublestar/v4"
	"github.com/joe-elliott/cert-exporter/src/args"
)

// GetPasswordForFile resolves the password for a given file path based on password specifications.
// It iterates through the specs and returns the password of the first matching glob.
// If no spec matches, it returns the defaultPassword.
func GetPasswordForFile(filePath string, specs []args.PasswordSpec, defaultPassword string) string {
	for _, spec := range specs {
		if matched, err := doublestar.Match(spec.GlobPattern, filePath); err == nil && matched {
			return spec.Password
		}
	}
	return defaultPassword
}
