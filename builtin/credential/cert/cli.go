// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package cert

import (
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type CLIHandler struct{}

func (h *CLIHandler) Auth(c *api.Client, m map[string]string) (*api.Secret, error) {
	var data struct {
		Mount string `mapstructure:"mount"`
		Name  string `mapstructure:"name"`
	}
	if err := mapstructure.WeakDecode(m, &data); err != nil {
		return nil, err
	}

	if data.Mount == "" {
		data.Mount = "cert"
	}

	options := map[string]interface{}{
		"name": data.Name,
	}
	path := fmt.Sprintf("auth/%s/login", data.Mount)
	secret, err := c.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("empty response from credential provider")
	}

	return secret, nil
}

func (h *CLIHandler) Help() string {
	help := `
Usage: vault login -method=cert [CONFIG K=V...]

  The certificate auth method allows users to authenticate with a
  client certificate passed with the request. The -client-cert and -client-key
  flags are included with the "vault login" command, NOT as configuration to the
  auth method.

  Both standard private keys (RSA, ECDSA) and TSS2-formatted TPM keys are supported.
  The system automatically detects the key format and uses the appropriate authentication method.

  Authenticate using a local client certificate with standard private key:

      $ vault login -method=cert -client-cert=cert.pem -client-key=key.pem

  Authenticate using a local client certificate with TSS2 TPM key:

      $ vault login -method=cert -client-cert=cert.pem -client-key=tpm-key.pem

  For TSS2 keys, ensure the TPM device is accessible (typically /dev/tpmrm0).

Configuration:

  name=<string>
      Certificate role to authenticate against.

TSS2/TPM Key Support:

  TSS2-formatted private keys are automatically detected and handled using TPM hardware.
  This provides enhanced security by keeping private keys secured within the TPM.
  
  Requirements for TSS2 keys:
  - TPM 2.0 device available (usually /dev/tpmrm0)
  - TSS2 PRIVATE KEY format in PEM file
  - Appropriate TPM permissions for the vault process
`

	return strings.TrimSpace(help)
}
