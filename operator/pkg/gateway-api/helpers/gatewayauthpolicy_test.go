// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestResolveCiliumGatewayAuthPolicyAttachments(t *testing.T) {
	gateway := &gatewayv1.Gateway{}
	gateway.SetNamespace("default")
	gateway.SetName("gw")
	gateway.Spec.Listeners = []gatewayv1.Listener{
		{Name: gatewayv1.SectionName("web")},
		{Name: gatewayv1.SectionName("grpc")},
	}

	httpRoute := gatewayv1.HTTPRoute{}
	httpRoute.SetNamespace("default")
	httpRoute.SetName("http-app")
	httpRoute.Spec.Rules = []gatewayv1.HTTPRouteRule{
		{Name: ptr.To(gatewayv1.SectionName("login"))},
		{},
	}

	grpcRoute := gatewayv1.GRPCRoute{}
	grpcRoute.SetNamespace("default")
	grpcRoute.SetName("grpc-app")
	grpcRoute.Spec.Rules = []gatewayv1.GRPCRouteRule{
		{Name: ptr.To(gatewayv1.SectionName("rpc"))},
	}

	policies := []ciliumv2alpha1.CiliumGatewayAuthPolicy{
		newGatewayAuthPolicy("gw-all", "default", gatewayTarget("gw", nil)),
		newGatewayAuthPolicy("gw-listener", "default", gatewayTarget("gw", ptr.To(gatewayv1.SectionName("web")))),
		newGatewayAuthPolicy("gw-missing-listener", "default", gatewayTarget("gw", ptr.To(gatewayv1.SectionName("missing")))),
		newGatewayAuthPolicy("http-all", "default", httpRouteTarget("http-app", nil)),
		newGatewayAuthPolicy("http-rule", "default", httpRouteTarget("http-app", ptr.To(gatewayv1.SectionName("login")))),
		newGatewayAuthPolicy("http-missing-rule", "default", httpRouteTarget("http-app", ptr.To(gatewayv1.SectionName("missing")))),
		newGatewayAuthPolicy("grpc-rule", "default", grpcRouteTarget("grpc-app", ptr.To(gatewayv1.SectionName("rpc")))),
		newGatewayAuthPolicy("other-namespace", "other", gatewayTarget("gw", nil)),
	}

	attachments := ResolveCiliumGatewayAuthPolicyAttachments(gateway, []gatewayv1.HTTPRoute{httpRoute}, []gatewayv1.GRPCRoute{grpcRoute}, policies)

	if got := len(attachments.Gateway.Resource); got != 1 {
		t.Fatalf("gateway resource attachments = %d, want 1", got)
	}
	if attachments.Gateway.Resource[0].Policy.GetName() != "gw-all" {
		t.Fatalf("gateway resource attachment policy = %s, want gw-all", attachments.Gateway.Resource[0].Policy.GetName())
	}

	webAttachments := attachments.Gateway.Sections[gatewayv1.SectionName("web")]
	if got := len(webAttachments); got != 1 {
		t.Fatalf("gateway section attachments = %d, want 1", got)
	}
	if webAttachments[0].Policy.GetName() != "gw-listener" {
		t.Fatalf("gateway section attachment policy = %s, want gw-listener", webAttachments[0].Policy.GetName())
	}
	if _, exists := attachments.Gateway.Sections[gatewayv1.SectionName("missing")]; exists {
		t.Fatal("unexpected attachment for missing gateway section")
	}

	httpCollection := attachments.HTTPRoutes[clientObjectKey(&httpRoute)]
	if got := len(httpCollection.Resource); got != 1 {
		t.Fatalf("http route resource attachments = %d, want 1", got)
	}
	if httpCollection.Resource[0].Policy.GetName() != "http-all" {
		t.Fatalf("http route resource attachment policy = %s, want http-all", httpCollection.Resource[0].Policy.GetName())
	}
	loginAttachments := httpCollection.Sections[gatewayv1.SectionName("login")]
	if got := len(loginAttachments); got != 1 {
		t.Fatalf("http route section attachments = %d, want 1", got)
	}
	if loginAttachments[0].Policy.GetName() != "http-rule" {
		t.Fatalf("http route section attachment policy = %s, want http-rule", loginAttachments[0].Policy.GetName())
	}
	if _, exists := httpCollection.Sections[gatewayv1.SectionName("missing")]; exists {
		t.Fatal("unexpected attachment for missing http route section")
	}

	grpcCollection := attachments.GRPCRoutes[clientObjectKey(&grpcRoute)]
	rpcAttachments := grpcCollection.Sections[gatewayv1.SectionName("rpc")]
	if got := len(rpcAttachments); got != 1 {
		t.Fatalf("grpc route section attachments = %d, want 1", got)
	}
	if rpcAttachments[0].Policy.GetName() != "grpc-rule" {
		t.Fatalf("grpc route section attachment policy = %s, want grpc-rule", rpcAttachments[0].Policy.GetName())
	}
}

func newGatewayAuthPolicy(name, namespace string, targets ...gatewayv1.LocalPolicyTargetReferenceWithSectionName) ciliumv2alpha1.CiliumGatewayAuthPolicy {
	policy := ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	policy.SetName(name)
	policy.SetNamespace(namespace)
	policy.Spec.TargetRefs = targets
	return policy
}

func gatewayTarget(name string, sectionName *gatewayv1.SectionName) gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group(gatewayv1.GroupName),
			Kind:  gatewayv1.Kind("Gateway"),
			Name:  gatewayv1.ObjectName(name),
		},
		SectionName: sectionName,
	}
}

func httpRouteTarget(name string, sectionName *gatewayv1.SectionName) gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group(gatewayv1.GroupName),
			Kind:  gatewayv1.Kind("HTTPRoute"),
			Name:  gatewayv1.ObjectName(name),
		},
		SectionName: sectionName,
	}
}

func grpcRouteTarget(name string, sectionName *gatewayv1.SectionName) gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group(gatewayv1.GroupName),
			Kind:  gatewayv1.Kind("GRPCRoute"),
			Name:  gatewayv1.ObjectName(name),
		},
		SectionName: sectionName,
	}
}
