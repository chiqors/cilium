// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"slices"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestIndexCiliumGatewayAuthPolicyBySecret(t *testing.T) {
	tests := []struct {
		name   string
		policy *ciliumv2alpha1.CiliumGatewayAuthPolicy
		want   []string
	}{
		{
			name: "indexes provider secrets without duplicates",
			policy: &ciliumv2alpha1.CiliumGatewayAuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth",
					Namespace: "default",
				},
				Spec: ciliumv2alpha1.CiliumGatewayAuthPolicySpec{
					BasicAuth: &ciliumv2alpha1.CiliumGatewayBasicAuth{
						Secret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "basic", Key: "auth"},
					},
					APIKeyAuth: &ciliumv2alpha1.CiliumGatewayAPIKeyAuth{
						Credentials: []ciliumv2alpha1.CiliumGatewayAPIKeyCredentialRef{
							{Secret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "api-key", Key: "key"}},
						},
					},
					JWT: &ciliumv2alpha1.CiliumGatewayJWTAuth{
						LocalJWKS: &ciliumv2alpha1.CiliumGatewayLocalJWKS{
							Secret: &ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "jwks", Key: "jwks.json"},
						},
					},
					OIDC: &ciliumv2alpha1.CiliumGatewayOIDCAuth{
						ClientSecret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "oidc-client", Key: "client-secret"},
						CookieSecret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "oidc-cookie", Key: "cookie-secret"},
					},
				},
			},
			want: []string{
				"default/api-key",
				"default/basic",
				"default/jwks",
				"default/oidc-client",
				"default/oidc-cookie",
			},
		},
		{
			name: "empty policy has no secret refs",
			policy: &ciliumv2alpha1.CiliumGatewayAuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth",
					Namespace: "default",
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IndexCiliumGatewayAuthPolicyBySecret(tt.policy)
			slices.Sort(got)
			slices.Sort(tt.want)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("IndexCiliumGatewayAuthPolicyBySecret() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIndexCiliumGatewayAuthPolicyByConfigMap(t *testing.T) {
	tests := []struct {
		name   string
		policy *ciliumv2alpha1.CiliumGatewayAuthPolicy
		want   []string
	}{
		{
			name: "indexes local jwks configmap",
			policy: &ciliumv2alpha1.CiliumGatewayAuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth",
					Namespace: "default",
				},
				Spec: ciliumv2alpha1.CiliumGatewayAuthPolicySpec{
					JWT: &ciliumv2alpha1.CiliumGatewayJWTAuth{
						LocalJWKS: &ciliumv2alpha1.CiliumGatewayLocalJWKS{
							ConfigMap: &ciliumv2alpha1.CiliumGatewayConfigMapKeyRef{Name: "jwks", Key: "jwks.json"},
						},
					},
				},
			},
			want: []string{"default/jwks"},
		},
		{
			name: "no configmaps when local jwks omitted",
			policy: &ciliumv2alpha1.CiliumGatewayAuthPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "auth",
					Namespace: "default",
				},
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IndexCiliumGatewayAuthPolicyByConfigMap(tt.policy)
			slices.Sort(got)
			slices.Sort(tt.want)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("IndexCiliumGatewayAuthPolicyByConfigMap() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIndexCiliumGatewayAuthPolicyTargets(t *testing.T) {
	policy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	policy.SetNamespace("default")
	policy.Spec.TargetRefs = []gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
				Group: gatewayv1.Group(gatewayv1.GroupName),
				Kind:  gatewayv1.Kind("Gateway"),
				Name:  gatewayv1.ObjectName("gw"),
			},
		},
		{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
				Group: gatewayv1.Group(gatewayv1.GroupName),
				Kind:  gatewayv1.Kind("HTTPRoute"),
				Name:  gatewayv1.ObjectName("http-app"),
			},
		},
		{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
				Group: gatewayv1.Group(gatewayv1.GroupName),
				Kind:  gatewayv1.Kind("GRPCRoute"),
				Name:  gatewayv1.ObjectName("grpc-app"),
			},
		},
	}

	if got := IndexCiliumGatewayAuthPolicyByGateway(policy); len(got) != 1 || got[0] != "default/gw" {
		t.Fatalf("IndexCiliumGatewayAuthPolicyByGateway() = %v, want [default/gw]", got)
	}
	if got := IndexCiliumGatewayAuthPolicyByHTTPRoute(policy); len(got) != 1 || got[0] != "default/http-app" {
		t.Fatalf("IndexCiliumGatewayAuthPolicyByHTTPRoute() = %v, want [default/http-app]", got)
	}
	if got := IndexCiliumGatewayAuthPolicyByGRPCRoute(policy); len(got) != 1 || got[0] != "default/grpc-app" {
		t.Fatalf("IndexCiliumGatewayAuthPolicyByGRPCRoute() = %v, want [default/grpc-app]", got)
	}
}
