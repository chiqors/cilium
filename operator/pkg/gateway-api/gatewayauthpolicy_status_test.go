// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/model"
)

func TestGatewayAuthPolicyHasUnresolvedRefs(t *testing.T) {
	tests := []struct {
		name   string
		policy model.GatewayAuthPolicy
		want   bool
	}{
		{
			name: "basic auth secret missing",
			policy: model.GatewayAuthPolicy{
				BasicAuth: &model.GatewayBasicAuth{
					Secret: model.GatewayAuthSecretRef{Name: "basic", Key: "auth", Found: false},
				},
			},
			want: true,
		},
		{
			name: "jwt configmap present",
			policy: model.GatewayAuthPolicy{
				JWT: &model.GatewayJWTAuth{
					LocalJWKS: &model.GatewayLocalJWKS{
						ConfigMap: &model.GatewayAuthConfigMapRef{Name: "jwks", Key: "jwks.json", Found: true},
					},
				},
			},
			want: false,
		},
		{
			name: "oidc cookie secret missing",
			policy: model.GatewayAuthPolicy{
				OIDC: &model.GatewayOIDCAuth{
					ClientSecret: model.GatewayAuthSecretRef{Name: "client", Key: "secret", Found: true},
					CookieSecret: model.GatewayAuthSecretRef{Name: "cookie", Key: "secret", Found: false},
				},
			},
			want: true,
		},
		{
			name: "oidc discovery unresolved",
			policy: model.GatewayAuthPolicy{
				OIDC: &model.GatewayOIDCAuth{
					ClientSecret: model.GatewayAuthSecretRef{Name: "client", Key: "secret", Found: true},
					CookieSecret: model.GatewayAuthSecretRef{Name: "cookie", Key: "secret", Found: true},
				},
			},
			want: true,
		},
		{
			name: "basic auth secret empty",
			policy: model.GatewayAuthPolicy{
				BasicAuth: &model.GatewayBasicAuth{
					Secret: model.GatewayAuthSecretRef{Name: "basic", Key: "auth", Found: true},
				},
			},
			want: true,
		},
		{
			name: "jwt remote uri invalid",
			policy: model.GatewayAuthPolicy{
				JWT: &model.GatewayJWTAuth{
					RemoteJWKSURI: "ftp://issuer.example.com/jwks",
				},
			},
			want: true,
		},
		{
			name: "oidc token uri invalid",
			policy: model.GatewayAuthPolicy{
				OIDC: &model.GatewayOIDCAuth{
					ClientSecret: model.GatewayAuthSecretRef{Name: "client", Key: "secret", Found: true, Value: []byte("client")},
					CookieSecret: model.GatewayAuthSecretRef{Name: "cookie", Key: "secret", Found: true, Value: []byte("cookie")},
					Endpoints: &model.GatewayOIDCEndpoints{
						Authorization: "https://issuer.example.com/authorize",
						Token:         "ftp://issuer.example.com/token",
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gatewayAuthPolicyHasUnresolvedRefs(tt.policy); got != tt.want {
				t.Fatalf("gatewayAuthPolicyHasUnresolvedRefs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMergeGatewayAuthPolicyAncestorStatus(t *testing.T) {
	parentRef := gatewayv1.ParentReference{
		Group:     ptrTo[gatewayv1.Group]("gateway.networking.k8s.io"),
		Kind:      ptrTo[gatewayv1.Kind]("Gateway"),
		Namespace: ptrTo[gatewayv1.Namespace]("default"),
		Name:      gatewayv1.ObjectName("gw"),
	}

	accepted := metav1.Condition{
		Type:   string(gatewayv1.PolicyConditionAccepted),
		Status: metav1.ConditionTrue,
		Reason: string(gatewayv1.PolicyReasonAccepted),
	}
	resolved := metav1.Condition{
		Type:   string(gatewayv1.RouteConditionResolvedRefs),
		Status: metav1.ConditionFalse,
		Reason: string(gatewayv1.PolicyReasonInvalid),
	}

	ancestors := mergeGatewayAuthPolicyAncestorStatus(nil, parentRef, gatewayv1.GatewayController("io.cilium/gateway-controller"), accepted, resolved)
	if len(ancestors) != 1 {
		t.Fatalf("ancestor count = %d, want 1", len(ancestors))
	}
	if len(ancestors[0].Conditions) != 2 {
		t.Fatalf("condition count = %d, want 2", len(ancestors[0].Conditions))
	}

	updatedAccepted := metav1.Condition{
		Type:   string(gatewayv1.PolicyConditionAccepted),
		Status: metav1.ConditionFalse,
		Reason: string(gatewayv1.PolicyReasonConflicted),
	}
	ancestors = mergeGatewayAuthPolicyAncestorStatus(ancestors, parentRef, gatewayv1.GatewayController("io.cilium/gateway-controller"), updatedAccepted)
	if len(ancestors) != 1 {
		t.Fatalf("ancestor count after update = %d, want 1", len(ancestors))
	}

	conditions := map[string]metav1.Condition{}
	for _, cond := range ancestors[0].Conditions {
		conditions[cond.Type] = cond
	}
	if conditions[string(gatewayv1.PolicyConditionAccepted)].Reason != string(gatewayv1.PolicyReasonConflicted) {
		t.Fatalf("accepted reason = %q, want %q", conditions[string(gatewayv1.PolicyConditionAccepted)].Reason, gatewayv1.PolicyReasonConflicted)
	}
	if conditions[string(gatewayv1.RouteConditionResolvedRefs)].Reason != string(gatewayv1.PolicyReasonInvalid) {
		t.Fatalf("resolved refs reason = %q, want %q", conditions[string(gatewayv1.RouteConditionResolvedRefs)].Reason, gatewayv1.PolicyReasonInvalid)
	}
}

func TestGatewayAuthModelConflictCounting(t *testing.T) {
	authModel := &model.GatewayAuthModel{
		Policies: []model.GatewayAuthPolicy{
			{
				Source: model.FullyQualifiedResource{Name: "winner", Namespace: "default"},
			},
			{
				Source: model.FullyQualifiedResource{Name: "loser", Namespace: "default"},
			},
		},
		Conflicts: []model.GatewayAuthConflict{
			{
				Loser:  model.FullyQualifiedResource{Name: "loser", Namespace: "default"},
				Winner: model.FullyQualifiedResource{Name: "winner", Namespace: "default"},
				Scope: model.GatewayAuthAttachment{
					Level: model.GatewayAuthAttachmentLevelGateway,
				},
			},
		},
	}

	modelPoliciesBySource := make(map[types.NamespacedName][]model.GatewayAuthPolicy)
	conflictsByLoser := make(map[types.NamespacedName]int)
	for _, policy := range authModel.Policies {
		key := types.NamespacedName{Namespace: policy.Source.Namespace, Name: policy.Source.Name}
		modelPoliciesBySource[key] = append(modelPoliciesBySource[key], policy)
	}
	for _, conflict := range authModel.Conflicts {
		key := types.NamespacedName{Namespace: conflict.Loser.Namespace, Name: conflict.Loser.Name}
		conflictsByLoser[key]++
	}

	if got := len(modelPoliciesBySource[types.NamespacedName{Namespace: "default", Name: "loser"}]) - conflictsByLoser[types.NamespacedName{Namespace: "default", Name: "loser"}]; got != 0 {
		t.Fatalf("selected count for losing policy = %d, want 0", got)
	}
}

func ptrTo[T any](v T) *T {
	return &v
}
