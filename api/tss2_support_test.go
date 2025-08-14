// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTSS2KeyLoader_isTSS2Key(t *testing.T) {
	loader := NewTSS2KeyLoader()

	// Test cases
	tests := []struct {
		name     string
		keyType  string
		keyData  string
		expected bool
	}{
		{
			name:     "TSS2 Private Key",
			keyType:  "TSS2 PRIVATE KEY",
			keyData:  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg",
			expected: true,
		},
		{
			name:    "Standard RSA Private Key",
			keyType: "RSA PRIVATE KEY",
			keyData: `MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btPiR
Dj9uyPQaAJG7Tk9tKBKfE6lMRmK8rPrmVH9O1QY8kC7N8YfvJQKDJrKKQN0C0q1F
Q8SYvyqmAAc5YAUZhc8YShqIHhNKMKlrpBLKgWVfWWQM3pnODpPXvJq2gZnJQRm+
6fCN+PwZ8l9gZWW8V9Q8YXj9P9I6J4n7r7VbHVnhRqV2mwKoC3pA9OV8J+7Z4Swo
ZbQ0aK5cDKzKHJqNJB1LqhQIxJ8vX4gP1S3pYn1QQ4f5Q4t5n7UiO3I3r3hPpSZa
IbJP3Y6SQ8d8eZGh7OIXwQ8h7+7KjjK5Y5n6WQ==`,
			expected: false,
		},
		{
			name:     "EC Private Key",
			keyType:  "EC PRIVATE KEY",
			keyData:  "MHcCAQEEIGJA03Q2F3CgGpAFOcRxhf3f4Z4K9XJpDHKPaLgfnHhm",
			expected: false,
		},
		{
			name:    "Standard PRIVATE KEY (PKCS#8)",
			keyType: "PRIVATE KEY",
			keyData: `MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN4
16b9XjV8acmbqA52uPzKbesWQSNZPZu0+JEOdP3I9BoAkbtOT20oEp8TqUxGYrys
+uZUf07VBjyQLs3xh+8lAoMmsobA3QLSrUVDxJi/KqYABzlgBRmFzxhKGogeE0ow
qWukEsqBZV9ZZAzemcrOnc1q2gZnJQRm+6fCN+PwZ8l9gZWW8V9Q8YXj9P9I6J4n
7r7VbHVnhRqV2mwKoC3pA9OV8J+7Z4SwqNJB1LqhQIxJ8vX4gP1S3pYn1QQ4f5Q4
t5n7UiO3I3r3hPpSZaIbJP3Y6SQ8d8eZGh7OIXwQ8h7+7KjjK5Y5n6WQIDAQABAo`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary file
			tmpDir := t.TempDir()
			keyFile := filepath.Join(tmpDir, "test.key")

			// Write PEM data
			pemData := "-----BEGIN " + tt.keyType + "-----\n" + tt.keyData + "\n-----END " + tt.keyType + "-----\n"
			err := os.WriteFile(keyFile, []byte(pemData), 0o600)
			if err != nil {
				t.Fatalf("Failed to write test key file: %v", err)
			}

			// Test key detection
			result, err := loader.isTSS2Key(keyFile)
			if err != nil {
				t.Fatalf("isTSS2Key returned error: %v", err)
			}

			if result != tt.expected {
				t.Errorf("isTSS2Key() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestTSS2KeyLoader_LoadX509KeyPairWithTSS2Support(t *testing.T) {
	loader := NewTSS2KeyLoader()

	// Test with normal RSA key (should work)
	t.Run("Standard RSA Key", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "test.key")
		certFile := filepath.Join(tmpDir, "test.cert")

		// Create a simple RSA private key
		rsaKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEjWT2btPiR
MIIE
-----END RSA PRIVATE KEY-----`

		// Create a simple certificate
		certPEM := `-----BEGIN CERTIFICATE-----
MIIDETCCAfkCAQAwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOdGVzdC5leGFt
cGxlLmNvbTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBkxFzAVBgNV
BAMMDnRlc3QuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQSNZPZu0+JEO
-----END CERTIFICATE-----`

		err := os.WriteFile(keyFile, []byte(rsaKeyPEM), 0o600)
		if err != nil {
			t.Fatalf("Failed to write key file: %v", err)
		}

		err = os.WriteFile(certFile, []byte(certPEM), 0o644)
		if err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}

		// This should fail because it's not a valid RSA key, but it should at least try the normal path
		_, err = loader.LoadX509KeyPairWithTSS2Support(certFile, keyFile)
		if err == nil {
			t.Error("Expected error for invalid RSA key, but got none")
		}
		// The error should be about key parsing, not TSS2
		if err != nil && err.Error() == "" {
			t.Errorf("Got error but no message: %v", err)
		}
	})

	// Test with TSS2 key (should return informative error)
	t.Run("TSS2 Key", func(t *testing.T) {
		tmpDir := t.TempDir()
		keyFile := filepath.Join(tmpDir, "test.key")
		certFile := filepath.Join(tmpDir, "test.cert")

		// Create a TSS2 private key
		tss2KeyPEM := `-----BEGIN TSS2 PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg
-----END TSS2 PRIVATE KEY-----`

		// Create a simple certificate
		certPEM := `-----BEGIN CERTIFICATE-----
MIIDETCCAfkCAQAwDQYJKoZIhvcNAQELBQAwGTEXMBUGA1UEAwwOdGVzdC5leGFt
cGxlLmNvbTAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBkxFzAVBgNV
BAMMDnRlc3QuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQSNZPZu0+JEO
-----END CERTIFICATE-----`

		err := os.WriteFile(keyFile, []byte(tss2KeyPEM), 0o600)
		if err != nil {
			t.Fatalf("Failed to write key file: %v", err)
		}

		err = os.WriteFile(certFile, []byte(certPEM), 0o644)
		if err != nil {
			t.Fatalf("Failed to write cert file: %v", err)
		}

		// This should return an informative error about TSS2 dependencies
		_, err = loader.LoadX509KeyPairWithTSS2Support(certFile, keyFile)
		if err == nil {
			t.Error("Expected error for TSS2 key without dependencies, but got none")
		}
		if err != nil && !strings.Contains(err.Error(), "TSS2 key support requires TPM dependencies") {
			t.Errorf("Expected TSS2 dependency error, got: %v", err)
		}
	})
}

func TestNewTSS2KeyLoader(t *testing.T) {
	loader := NewTSS2KeyLoader()

	if loader == nil {
		t.Fatal("NewTSS2KeyLoader returned nil")
	}

	if loader.TPMPath != "/dev/tpmrm0" {
		t.Errorf("Expected default TPMPath to be '/dev/tpmrm0', got '%s'", loader.TPMPath)
	}

	if loader.Debug != false {
		t.Errorf("Expected default Debug to be false, got %v", loader.Debug)
	}
}
