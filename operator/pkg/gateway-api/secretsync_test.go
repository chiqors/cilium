// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestSecretSyncHandlerAuthPolicySecretReferences(t *testing.T) {
	policy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-policy",
			Namespace: "default",
		},
		Spec: ciliumv2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: gatewayv1.Group(gatewayv1.GroupName),
					Kind:  gatewayv1.Kind("Gateway"),
					Name:  gatewayv1.ObjectName("gw"),
				},
			}},
			BasicAuth: &ciliumv2alpha1.CiliumGatewayBasicAuth{
				Secret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "basic-secret", Key: "auth"},
			},
			OIDC: &ciliumv2alpha1.CiliumGatewayOIDCAuth{
				Issuer:       "https://issuer.example.com",
				ClientID:     "client-id",
				ClientSecret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "client-secret", Key: "secret"},
				CookieSecret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "cookie-secret", Key: "secret"},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(policy).
		WithIndex(&ciliumv2alpha1.CiliumGatewayAuthPolicy{}, indexers.GatewayAuthPolicySecretIndex, indexers.IndexCiliumGatewayAuthPolicyBySecret).
		Build()

	handler := NewSecretSyncHandler(client, hivetest.Logger(t), defaultControllerName)

	require.True(t, handler.IsReferencedByGatewayOrAuthPolicy(t.Context(), nil, nil, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "basic-secret", Namespace: "default"},
	}))
	require.True(t, handler.IsReferencedByGatewayOrAuthPolicy(t.Context(), nil, nil, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "client-secret", Namespace: "default"},
	}))
	require.False(t, handler.IsReferencedByGatewayOrAuthPolicy(t.Context(), nil, nil, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "default"},
	}))
}

func TestSecretSyncHandlerAuthPolicyConfigMapReferences(t *testing.T) {
	policy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "jwt-policy",
			Namespace: "default",
		},
		Spec: ciliumv2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
				LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
					Group: gatewayv1.Group(gatewayv1.GroupName),
					Kind:  gatewayv1.Kind("Gateway"),
					Name:  gatewayv1.ObjectName("gw"),
				},
			}},
			JWT: &ciliumv2alpha1.CiliumGatewayJWTAuth{
				Issuer: "https://issuer.example.com",
				LocalJWKS: &ciliumv2alpha1.CiliumGatewayLocalJWKS{
					ConfigMap: &ciliumv2alpha1.CiliumGatewayConfigMapKeyRef{Name: "jwks-config", Key: "jwks.json"},
				},
			},
		},
	}

	client := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(policy).
		WithIndex(&ciliumv2alpha1.CiliumGatewayAuthPolicy{}, indexers.GatewayAuthPolicyConfigMapIndex, indexers.IndexCiliumGatewayAuthPolicyByConfigMap).
		Build()

	handler := NewSecretSyncHandler(client, hivetest.Logger(t), defaultControllerName)

	require.True(t, handler.ConfigMapIsReferencedInGatewayOrAuthPolicy(t.Context(), nil, nil, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "jwks-config", Namespace: "default"},
	}))
	require.False(t, handler.ConfigMapIsReferencedInGatewayOrAuthPolicy(t.Context(), nil, nil, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "missing", Namespace: "default"},
	}))
}
