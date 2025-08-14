// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package api

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2/transport"
)

// TSS2KeyLoader provides functionality to detect and load TSS2-formatted private keys
// for TPM-based certificate authentication.
type TSS2KeyLoader struct {
	TPMPath string // Path to TPM device, defaults to "/dev/tpmrm0"
	Debug   bool   // Enable debug logging
}

// NewTSS2KeyLoader creates a new TSS2KeyLoader with default settings
func NewTSS2KeyLoader() *TSS2KeyLoader {
	return &TSS2KeyLoader{
		TPMPath: "/dev/tpmrm0",
		Debug:   false,
	}
}

// LoadX509KeyPairWithTSS2Support loads a certificate and private key pair,
// automatically detecting and handling both standard and TSS2-formatted keys.
// This is a drop-in replacement for tls.LoadX509KeyPair that adds TPM support.
func (t *TSS2KeyLoader) LoadX509KeyPairWithTSS2Support(certFile, keyFile string) (tls.Certificate, error) {
	// Load certificate (same for both TSS2 and normal keys)
	certPEMBlock, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read certificate file: %w", err)
	}

	// Check if the private key is TSS2 format
	isTSS2, err := t.isTSS2Key(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to determine key format: %w", err)
	}

	if isTSS2 {
		if t.Debug {
			fmt.Printf("Debug: Detected TSS2 key format, using TPM signer\n")
		}
		return t.loadTSS2Certificate(certPEMBlock, keyFile)
	} else {
		if t.Debug {
			fmt.Printf("Debug: Detected standard private key format, using normal loader\n")
		}
		// Use standard Go library function for normal keys
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
}

// isTSS2Key determines if a private key file is in TSS2 format
func (t *TSS2KeyLoader) isTSS2Key(keyPath string) (bool, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return false, fmt.Errorf("failed to read key file: %w", err)
	}

	// Check for TSS2 PRIVATE KEY block type
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return false, fmt.Errorf("failed to parse key PEM")
	}

	// TSS2 keys typically use "TSS2 PRIVATE KEY" block type
	if block.Type == "TSS2 PRIVATE KEY" {
		return true, nil
	}

	// For standard private key types, explicitly return false
	if block.Type == "RSA PRIVATE KEY" || block.Type == "EC PRIVATE KEY" || block.Type == "PRIVATE KEY" {
		return false, nil
	}

	// Also check if the content looks like TSS2 format by checking for TPM-specific headers
	if strings.Contains(block.Type, "PRIVATE KEY") {
		// Look for TSS2-specific content patterns
		content := string(block.Bytes)
		if strings.Contains(content, "TSS2") {
			return true, nil
		}
	}

	return false, nil
}

// loadTSS2Certificate loads a certificate with a TSS2 private key using TPM
func (t *TSS2KeyLoader) loadTSS2Certificate(certPEMBlock []byte, keyFile string) (tls.Certificate, error) {
	// 1. Parse certificate
	block, _ := pem.Decode(certPEMBlock)
	if block == nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 2. Load TSS2 key
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key file: %w", err)
	}

	// 3. Decode TSS2 key
	tpmKey, err := keyfile.Decode(keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to decode TSS2 key: %w", err)
	}

	// 4. Open TPM transport
	rwc, err := transport.OpenTPM(t.TPMPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to open TPM at %s: %w", t.TPMPath, err)
	}
	// Note: Not closing rwc here - the signer needs it to remain open for TLS operations

	// 5. Create TPM signer
	signer, err := tpmKey.Signer(rwc, []byte{}, []byte{}) // empty owner auth and auth
	if err != nil {
		rwc.Close()
		return tls.Certificate{}, fmt.Errorf("failed to create TPM signer: %w", err)
	}

	if t.Debug {
		fmt.Printf("Debug: Successfully loaded TSS2 key from %s using TPM at %s\n", keyFile, t.TPMPath)
	}

	// 6. Create TLS certificate with TPM signer
	return tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
	}, nil
}

// Future implementation would include:
// func (t *TSS2KeyLoader) loadTSS2CertificateWithTPM(certPEMBlock []byte, keyFile string) (tls.Certificate, error) {
//     // 1. Parse certificate
//     block, _ := pem.Decode(certPEMBlock)
//     if block == nil {
//         return tls.Certificate{}, fmt.Errorf("failed to parse certificate PEM")
//     }
//     cert, err := x509.ParseCertificate(block.Bytes)
//     if err != nil {
//         return tls.Certificate{}, fmt.Errorf("failed to parse certificate: %w", err)
//     }
//
//     // 2. Load TSS2 key
//     keyPEM, err := os.ReadFile(keyFile)
//     if err != nil {
//         return tls.Certificate{}, fmt.Errorf("failed to read key file: %w", err)
//     }
//
//     // 3. Create TPM signer
//     tpmKey, err := keyfile.Decode(keyPEM)
//     if err != nil {
//         return tls.Certificate{}, fmt.Errorf("failed to decode TSS2 key: %w", err)
//     }
//
//     rwc, err := transport.OpenTPM(t.TPMPath)
//     if err != nil {
//         return tls.Certificate{}, fmt.Errorf("failed to open TPM: %w", err)
//     }
//
//     signer, err := tpmKey.Signer(rwc, []byte{}, []byte{})
//     if err != nil {
//         rwc.Close()
//         return tls.Certificate{}, fmt.Errorf("failed to create signer: %w", err)
//     }
//
//     // 4. Create TLS certificate with TPM signer
//     return tls.Certificate{
//         Certificate: [][]byte{cert.Raw},
//         PrivateKey:  signer,
//     }, nil
// }
