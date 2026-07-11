// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package indexers

import (
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func IndexCiliumGatewayAuthPolicyBySecret(rawObj client.Object) []string {
	policy := rawObj.(*ciliumv2alpha1.CiliumGatewayAuthPolicy)
	refs := make(map[string]struct{})

	add := func(ref ciliumv2alpha1.CiliumGatewaySecretKeyRef) {
		if ref.Name == "" {
			return
		}
		refs[types.NamespacedName{
			Namespace: policy.GetNamespace(),
			Name:      ref.Name,
		}.String()] = struct{}{}
	}

	if policy.Spec.BasicAuth != nil {
		add(policy.Spec.BasicAuth.Secret)
	}
	if policy.Spec.APIKeyAuth != nil {
		for _, credential := range policy.Spec.APIKeyAuth.Credentials {
			add(credential.Secret)
		}
	}
	if policy.Spec.JWT != nil && policy.Spec.JWT.LocalJWKS != nil && policy.Spec.JWT.LocalJWKS.Secret != nil {
		add(*policy.Spec.JWT.LocalJWKS.Secret)
	}
	if policy.Spec.OIDC != nil {
		add(policy.Spec.OIDC.ClientSecret)
		add(policy.Spec.OIDC.CookieSecret)
	}

	return mapKeys(refs)
}

func IndexCiliumGatewayAuthPolicyByConfigMap(rawObj client.Object) []string {
	policy := rawObj.(*ciliumv2alpha1.CiliumGatewayAuthPolicy)
	refs := make(map[string]struct{})

	if policy.Spec.JWT != nil && policy.Spec.JWT.LocalJWKS != nil && policy.Spec.JWT.LocalJWKS.ConfigMap != nil && policy.Spec.JWT.LocalJWKS.ConfigMap.Name != "" {
		refs[types.NamespacedName{
			Namespace: policy.GetNamespace(),
			Name:      policy.Spec.JWT.LocalJWKS.ConfigMap.Name,
		}.String()] = struct{}{}
	}

	return mapKeys(refs)
}

func mapKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for value := range values {
		keys = append(keys, value)
	}
	return keys
}

func IndexCiliumGatewayAuthPolicyByGateway(rawObj client.Object) []string {
	return indexCiliumGatewayAuthPolicyTargets(rawObj, "Gateway")
}

func IndexCiliumGatewayAuthPolicyByHTTPRoute(rawObj client.Object) []string {
	return indexCiliumGatewayAuthPolicyTargets(rawObj, "HTTPRoute")
}

func IndexCiliumGatewayAuthPolicyByGRPCRoute(rawObj client.Object) []string {
	return indexCiliumGatewayAuthPolicyTargets(rawObj, "GRPCRoute")
}

func indexCiliumGatewayAuthPolicyTargets(rawObj client.Object, kind gatewayv1.Kind) []string {
	policy := rawObj.(*ciliumv2alpha1.CiliumGatewayAuthPolicy)
	targets := make(map[string]struct{})

	for _, targetRef := range policy.Spec.TargetRefs {
		if targetRef.Group != gatewayv1.Group(gatewayv1.GroupName) || targetRef.Kind != kind || targetRef.Name == "" {
			continue
		}

		targets[types.NamespacedName{
			Namespace: policy.GetNamespace(),
			Name:      string(targetRef.Name),
		}.String()] = struct{}{}
	}

	return mapKeys(targets)
}
