// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCiliumGatewayAuthPolicyCRDIncludesValidationRules(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to resolve test file path")
	}

	crdPath := filepath.Join(filepath.Dir(filename), "..", "client", "crds", "v2alpha1", "ciliumgatewayauthpolicies.yaml")
	content, err := os.ReadFile(crdPath)
	if err != nil {
		t.Fatalf("failed to read CRD manifest: %v", err)
	}

	crd := string(content)
	for _, snippet := range []string{
		"message: at least one provider or authorization block must be specified",
		"message: targetRefs must reference gateway.networking.k8s.io Gateway,",
		"message: basicAuth may not be combined with apiKeyAuth, jwt, or oidc",
		"message: apiKeyAuth may not be combined with jwt or oidc",
		"message: jwt and oidc may not both be specified",
		"message: exactly one of localJWKS or remoteJWKS must be specified",
		"message: exactly one of secret or configMap must be specified",
	} {
		if !strings.Contains(crd, snippet) {
			t.Fatalf("CRD manifest missing validation snippet %q", snippet)
		}
	}
}
