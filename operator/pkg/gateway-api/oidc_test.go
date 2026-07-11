// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestResolveOIDCEndpointsUsesDiscoveryAndOverrides(t *testing.T) {
	var requests int
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`{
			"authorization_endpoint":"` + server.URL + `/authorize",
			"token_endpoint":"` + server.URL + `/token",
			"userinfo_endpoint":"` + server.URL + `/userinfo",
			"jwks_uri":"` + server.URL + `/jwks",
			"end_session_endpoint":"` + server.URL + `/logout"
		}`))
	}))
	defer server.Close()

	r := &gatewayReconciler{
		oidcDiscoveryClient: server.Client(),
		oidcDiscoveryCache:  newOIDCDiscoveryCache(oidcDiscoveryCacheTTL),
	}

	auth := &ciliumv2alpha1.CiliumGatewayOIDCAuth{
		Issuer: server.URL,
		Endpoints: &ciliumv2alpha1.CiliumGatewayOIDCEndpoints{
			Token: stringPtr("https://override.example.com/token"),
		},
	}

	endpoints, err := r.resolveOIDCEndpoints(context.Background(), auth)
	if err != nil {
		t.Fatalf("resolveOIDCEndpoints() error = %v", err)
	}
	if endpoints.Authorization != server.URL+"/authorize" {
		t.Fatalf("authorization endpoint = %q, want discovery value", endpoints.Authorization)
	}
	if endpoints.Token != "https://override.example.com/token" {
		t.Fatalf("token endpoint = %q, want override value", endpoints.Token)
	}

	_, err = r.resolveOIDCEndpoints(context.Background(), auth)
	if err != nil {
		t.Fatalf("second resolveOIDCEndpoints() error = %v", err)
	}
	if requests != 1 {
		t.Fatalf("discovery request count = %d, want 1 due to cache", requests)
	}
}

func TestGatewayOIDCEndpointsMerge(t *testing.T) {
	base := &model.GatewayOIDCEndpoints{
		Authorization: "https://issuer.example.com/authorize",
		Token:         "https://issuer.example.com/token",
		JWKS:          "https://issuer.example.com/jwks",
	}
	merged := base.Merge(&model.GatewayOIDCEndpoints{
		Token:      "https://override.example.com/token",
		EndSession: "https://override.example.com/logout",
	})

	if merged.Authorization != base.Authorization {
		t.Fatalf("authorization endpoint = %q, want %q", merged.Authorization, base.Authorization)
	}
	if merged.Token != "https://override.example.com/token" {
		t.Fatalf("token endpoint = %q, want override value", merged.Token)
	}
	if merged.EndSession != "https://override.example.com/logout" {
		t.Fatalf("end session endpoint = %q, want override value", merged.EndSession)
	}
}

func stringPtr(v string) *string {
	return &v
}
