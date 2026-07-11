// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"k8s.io/apimachinery/pkg/types"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type CiliumGatewayAuthPolicyAttachment struct {
	Policy    *ciliumv2alpha1.CiliumGatewayAuthPolicy
	TargetRef gatewayv1.LocalPolicyTargetReferenceWithSectionName
}

type CiliumGatewayAuthPolicyAttachmentCollection struct {
	Resource []CiliumGatewayAuthPolicyAttachment
	Sections map[gatewayv1.SectionName][]CiliumGatewayAuthPolicyAttachment
}

type CiliumGatewayAuthPolicyAttachments struct {
	Gateway    CiliumGatewayAuthPolicyAttachmentCollection
	HTTPRoutes map[types.NamespacedName]CiliumGatewayAuthPolicyAttachmentCollection
	GRPCRoutes map[types.NamespacedName]CiliumGatewayAuthPolicyAttachmentCollection
}

func ResolveCiliumGatewayAuthPolicyAttachments(
	gateway *gatewayv1.Gateway,
	httpRoutes []gatewayv1.HTTPRoute,
	grpcRoutes []gatewayv1.GRPCRoute,
	policies []ciliumv2alpha1.CiliumGatewayAuthPolicy,
) *CiliumGatewayAuthPolicyAttachments {
	attachments := &CiliumGatewayAuthPolicyAttachments{
		HTTPRoutes: make(map[types.NamespacedName]CiliumGatewayAuthPolicyAttachmentCollection),
		GRPCRoutes: make(map[types.NamespacedName]CiliumGatewayAuthPolicyAttachmentCollection),
	}

	if gateway == nil {
		return attachments
	}

	httpRouteIndex := make(map[types.NamespacedName]*gatewayv1.HTTPRoute, len(httpRoutes))
	for i := range httpRoutes {
		route := &httpRoutes[i]
		httpRouteIndex[clientObjectKey(route)] = route
	}

	grpcRouteIndex := make(map[types.NamespacedName]*gatewayv1.GRPCRoute, len(grpcRoutes))
	for i := range grpcRoutes {
		route := &grpcRoutes[i]
		grpcRouteIndex[clientObjectKey(route)] = route
	}

	for i := range policies {
		policy := &policies[i]
		if policy.GetNamespace() != gateway.GetNamespace() {
			continue
		}

		for _, targetRef := range policy.Spec.TargetRefs {
			if targetRef.Group != gatewayv1.Group(gatewayv1.GroupName) {
				continue
			}

			attachment := CiliumGatewayAuthPolicyAttachment{
				Policy:    policy,
				TargetRef: targetRef,
			}

			switch targetRef.Kind {
			case gatewayv1.Kind("Gateway"):
				if string(targetRef.Name) != gateway.GetName() {
					continue
				}
				if targetRef.SectionName == nil {
					attachments.Gateway.Resource = append(attachments.Gateway.Resource, attachment)
					continue
				}
				if !gatewayHasSection(*gateway, *targetRef.SectionName) {
					continue
				}
				attachments.Gateway.Sections = upsertAttachmentSection(attachments.Gateway.Sections, *targetRef.SectionName, attachment)
			case gatewayv1.Kind("HTTPRoute"):
				route, ok := httpRouteIndex[types.NamespacedName{
					Namespace: policy.GetNamespace(),
					Name:      string(targetRef.Name),
				}]
				if !ok {
					continue
				}
				key := clientObjectKey(route)
				collection := attachments.HTTPRoutes[key]
				if targetRef.SectionName == nil {
					collection.Resource = append(collection.Resource, attachment)
				} else if httpRouteHasSection(*route, *targetRef.SectionName) {
					collection.Sections = upsertAttachmentSection(collection.Sections, *targetRef.SectionName, attachment)
				}
				attachments.HTTPRoutes[key] = collection
			case gatewayv1.Kind("GRPCRoute"):
				route, ok := grpcRouteIndex[types.NamespacedName{
					Namespace: policy.GetNamespace(),
					Name:      string(targetRef.Name),
				}]
				if !ok {
					continue
				}
				key := clientObjectKey(route)
				collection := attachments.GRPCRoutes[key]
				if targetRef.SectionName == nil {
					collection.Resource = append(collection.Resource, attachment)
				} else if grpcRouteHasSection(*route, *targetRef.SectionName) {
					collection.Sections = upsertAttachmentSection(collection.Sections, *targetRef.SectionName, attachment)
				}
				attachments.GRPCRoutes[key] = collection
			}
		}
	}

	return attachments
}

func gatewayHasSection(gateway gatewayv1.Gateway, sectionName gatewayv1.SectionName) bool {
	for _, listener := range gateway.Spec.Listeners {
		if listener.Name == sectionName {
			return true
		}
	}
	return false
}

func httpRouteHasSection(route gatewayv1.HTTPRoute, sectionName gatewayv1.SectionName) bool {
	for _, rule := range route.Spec.Rules {
		if rule.Name != nil && *rule.Name == sectionName {
			return true
		}
	}
	return false
}

func grpcRouteHasSection(route gatewayv1.GRPCRoute, sectionName gatewayv1.SectionName) bool {
	for _, rule := range route.Spec.Rules {
		if rule.Name != nil && *rule.Name == sectionName {
			return true
		}
	}
	return false
}

func upsertAttachmentSection(
	sections map[gatewayv1.SectionName][]CiliumGatewayAuthPolicyAttachment,
	sectionName gatewayv1.SectionName,
	attachment CiliumGatewayAuthPolicyAttachment,
) map[gatewayv1.SectionName][]CiliumGatewayAuthPolicyAttachment {
	if sections == nil {
		sections = make(map[gatewayv1.SectionName][]CiliumGatewayAuthPolicyAttachment)
	}

	sections[sectionName] = append(sections[sectionName], attachment)
	return sections
}

func clientObjectKey(obj interface {
	GetNamespace() string
	GetName() string
}) types.NamespacedName {
	return types.NamespacedName{
		Namespace: obj.GetNamespace(),
		Name:      obj.GetName(),
	}
}
