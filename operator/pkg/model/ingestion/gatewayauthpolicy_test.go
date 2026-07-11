// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	gatewayhelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func TestToGatewayAuthModel(t *testing.T) {
	gatewayPolicy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	gatewayPolicy.SetNamespace("default")
	gatewayPolicy.SetName("gw-basic")
	gatewayPolicy.SetCreationTimestamp(metav1.NewTime(time.Unix(10, 0)))
	gatewayPolicy.Spec.BasicAuth = &ciliumv2alpha1.CiliumGatewayBasicAuth{
		Secret:         ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "basic-auth", Key: "auth"},
		UsernameHeader: ptr.To("x-user"),
	}
	gatewayPolicy.Spec.Authorization = &ciliumv2alpha1.CiliumGatewayAuthorizationPolicy{
		Rules: []ciliumv2alpha1.CiliumGatewayAuthorizationRule{
			{Methods: []string{"GET"}, Paths: []string{"/admin"}},
		},
	}

	httpJWTPolicy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	httpJWTPolicy.SetNamespace("default")
	httpJWTPolicy.SetName("http-jwt")
	httpJWTPolicy.SetCreationTimestamp(metav1.NewTime(time.Unix(20, 0)))
	httpJWTPolicy.Spec.JWT = &ciliumv2alpha1.CiliumGatewayJWTAuth{
		Issuer: "https://issuer.example.com",
		LocalJWKS: &ciliumv2alpha1.CiliumGatewayLocalJWKS{
			ConfigMap: &ciliumv2alpha1.CiliumGatewayConfigMapKeyRef{Name: "jwks", Key: "jwks.json"},
		},
		ClaimToHeaders: []ciliumv2alpha1.CiliumGatewayClaimToHeader{
			{Claim: "sub", Header: "x-sub"},
		},
	}

	httpAPIKeyPolicy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	httpAPIKeyPolicy.SetNamespace("default")
	httpAPIKeyPolicy.SetName("http-api-key")
	httpAPIKeyPolicy.SetCreationTimestamp(metav1.NewTime(time.Unix(15, 0)))
	httpAPIKeyPolicy.Spec.APIKeyAuth = &ciliumv2alpha1.CiliumGatewayAPIKeyAuth{
		Sources: []ciliumv2alpha1.CiliumGatewayAPIKeySource{
			{Type: ciliumv2alpha1.CiliumGatewayAPIKeySourceHeader, Name: "x-api-key"},
		},
		Credentials: []ciliumv2alpha1.CiliumGatewayAPIKeyCredentialRef{
			{
				Secret:   ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "api-key", Key: "token"},
				Identity: ptr.To("client-a"),
			},
		},
		IdentityHeader:  ptr.To("x-identity"),
		StripCredential: ptr.To(true),
	}

	grpcOIDCPolicy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	grpcOIDCPolicy.SetNamespace("default")
	grpcOIDCPolicy.SetName("grpc-oidc")
	grpcOIDCPolicy.SetCreationTimestamp(metav1.NewTime(time.Unix(30, 0)))
	grpcOIDCPolicy.Spec.OIDC = &ciliumv2alpha1.CiliumGatewayOIDCAuth{
		Issuer:       "https://issuer.example.com",
		ClientID:     "client-id",
		ClientSecret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "oidc-client", Key: "client-secret"},
		CookieSecret: ciliumv2alpha1.CiliumGatewaySecretKeyRef{Name: "oidc-cookie", Key: "cookie-secret"},
		Endpoints: &ciliumv2alpha1.CiliumGatewayOIDCEndpoints{
			Token: ptr.To("https://issuer.example.com/token"),
		},
	}

	input := Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: gatewayv1.SectionName("web")},
					{Name: gatewayv1.SectionName("grpc")},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "http-app", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:        gatewayv1.ObjectName("gw"),
								SectionName: ptr.To(gatewayv1.SectionName("web")),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{
						{Name: ptr.To(gatewayv1.SectionName("login"))},
						{},
					},
				},
			},
		},
		GRPCRoutes: []gatewayv1.GRPCRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "grpc-app", Namespace: "default"},
				Spec: gatewayv1.GRPCRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:        gatewayv1.ObjectName("gw"),
								SectionName: ptr.To(gatewayv1.SectionName("grpc")),
							},
						},
					},
					Rules: []gatewayv1.GRPCRouteRule{
						{Name: ptr.To(gatewayv1.SectionName("rpc"))},
					},
				},
			},
		},
		AuthPolicyAttachments: &gatewayhelpers.CiliumGatewayAuthPolicyAttachments{
			Gateway: gatewayhelpers.CiliumGatewayAuthPolicyAttachmentCollection{
				Sections: map[gatewayv1.SectionName][]gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
					gatewayv1.SectionName("web"): {
						{Policy: gatewayPolicy, TargetRef: gatewayTargetRef("gw", ptr.To(gatewayv1.SectionName("web")))},
					},
				},
			},
			HTTPRoutes: map[types.NamespacedName]gatewayhelpers.CiliumGatewayAuthPolicyAttachmentCollection{
				{Namespace: "default", Name: "http-app"}: {
					Resource: []gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
						{Policy: httpAPIKeyPolicy, TargetRef: httpRouteTargetRef("http-app", nil)},
					},
					Sections: map[gatewayv1.SectionName][]gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
						gatewayv1.SectionName("login"): {
							{Policy: httpJWTPolicy, TargetRef: httpRouteTargetRef("http-app", ptr.To(gatewayv1.SectionName("login")))},
						},
					},
				},
			},
			GRPCRoutes: map[types.NamespacedName]gatewayhelpers.CiliumGatewayAuthPolicyAttachmentCollection{
				{Namespace: "default", Name: "grpc-app"}: {
					Resource: []gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
						{Policy: grpcOIDCPolicy, TargetRef: grpcRouteTargetRef("grpc-app", nil)},
					},
				},
			},
		},
		MergedListeners: []ListenerWithContext{
			{
				Listener: gatewayv1.Listener{Name: gatewayv1.SectionName("web")},
				Source: model.FullyQualifiedResource{
					Name:      "gw",
					Namespace: "default",
					Group:     gatewayv1.SchemeGroupVersion.Group,
					Version:   gatewayv1.SchemeGroupVersion.Version,
					Kind:      "Gateway",
				},
			},
			{
				Listener: gatewayv1.Listener{Name: gatewayv1.SectionName("grpc")},
				Source: model.FullyQualifiedResource{
					Name:      "gw",
					Namespace: "default",
					Group:     gatewayv1.SchemeGroupVersion.Group,
					Version:   gatewayv1.SchemeGroupVersion.Version,
					Kind:      "Gateway",
				},
			},
		},
		AuthPolicySecrets: map[types.NamespacedName]corev1.Secret{
			{Namespace: "default", Name: "basic-auth"}:  {Data: map[string][]byte{"auth": []byte("user:hash")}},
			{Namespace: "default", Name: "api-key"}:     {Data: map[string][]byte{"token": []byte("super-secret")}},
			{Namespace: "default", Name: "oidc-client"}: {Data: map[string][]byte{"client-secret": []byte("client-value")}},
			{Namespace: "default", Name: "oidc-cookie"}: {Data: map[string][]byte{"cookie-secret": []byte("cookie-value")}},
		},
		AuthPolicyConfigMaps: map[types.NamespacedName]corev1.ConfigMap{
			{Namespace: "default", Name: "jwks"}: {Data: map[string]string{"jwks.json": `{"keys":[]}`}},
		},
	}

	authModel := toGatewayAuthModel(input)
	if authModel == nil {
		t.Fatal("toGatewayAuthModel() returned nil")
	}
	if got := len(authModel.Policies); got != 4 {
		t.Fatalf("policy count = %d, want 4", got)
	}
	if got := len(authModel.Conflicts); got != 0 {
		t.Fatalf("conflict count = %d, want 0", got)
	}

	policiesByName := make(map[string]model.GatewayAuthPolicy, len(authModel.Policies))
	for _, policy := range authModel.Policies {
		policiesByName[policy.Source.Name] = policy
	}

	bindingsByScope := make(map[string]string, len(authModel.Bindings))
	for _, binding := range authModel.Bindings {
		bindingsByScope[bindingKey(binding.Scope)] = binding.Policy.Name
	}

	gwBasic := policiesByName["gw-basic"]
	if gwBasic.Attachment.Level != model.GatewayAuthAttachmentLevelListener || gwBasic.Attachment.ListenerName != "web" {
		t.Fatalf("gateway attachment = %#v, want listener:web", gwBasic.Attachment)
	}
	if gwBasic.BasicAuth == nil || !gwBasic.BasicAuth.Secret.Found || string(gwBasic.BasicAuth.Secret.Value) != "user:hash" {
		t.Fatalf("gateway basic auth secret = %#v, want resolved value", gwBasic.BasicAuth)
	}
	if gwBasic.Authorization == nil || len(gwBasic.Authorization.Rules) != 1 || gwBasic.Authorization.Rules[0].Paths[0] != "/admin" {
		t.Fatalf("gateway authorization = %#v, want copied rule", gwBasic.Authorization)
	}
	if got := bindingsByScope["Listener:web"]; got != "gw-basic" {
		t.Fatalf("listener binding = %q, want gw-basic", got)
	}

	httpJWT := policiesByName["http-jwt"]
	if httpJWT.Attachment.Level != model.GatewayAuthAttachmentLevelHTTPRule || httpJWT.Attachment.RouteRule != "login" || httpJWT.Attachment.Route == nil || httpJWT.Attachment.Route.Name != "http-app" {
		t.Fatalf("http jwt attachment = %#v, want rule attachment", httpJWT.Attachment)
	}
	if httpJWT.JWT == nil || httpJWT.JWT.LocalJWKS == nil || httpJWT.JWT.LocalJWKS.ConfigMap == nil || !httpJWT.JWT.LocalJWKS.ConfigMap.Found {
		t.Fatalf("http jwt local jwks = %#v, want resolved configmap", httpJWT.JWT)
	}
	if string(httpJWT.JWT.LocalJWKS.ConfigMap.Value) != `{"keys":[]}` {
		t.Fatalf("http jwt jwks value = %q, want {\"keys\":[]}", string(httpJWT.JWT.LocalJWKS.ConfigMap.Value))
	}
	if got := bindingsByScope["HTTPRoute:web:default/http-app"]; got != "http-api-key" {
		t.Fatalf("http route binding = %q, want http-api-key", got)
	}
	if got := bindingsByScope["HTTPRouteRule:web:default/http-app:login"]; got != "http-jwt" {
		t.Fatalf("http route rule binding = %q, want http-jwt", got)
	}

	httpAPIKey := policiesByName["http-api-key"]
	if httpAPIKey.Attachment.Level != model.GatewayAuthAttachmentLevelHTTPRoute || httpAPIKey.Attachment.Route == nil || httpAPIKey.Attachment.Route.Name != "http-app" {
		t.Fatalf("http api key attachment = %#v, want route attachment", httpAPIKey.Attachment)
	}
	if httpAPIKey.APIKeyAuth == nil || len(httpAPIKey.APIKeyAuth.Credentials) != 1 || !httpAPIKey.APIKeyAuth.Credentials[0].Secret.Found {
		t.Fatalf("http api key auth = %#v, want resolved credential", httpAPIKey.APIKeyAuth)
	}
	if !httpAPIKey.APIKeyAuth.StripCredential || httpAPIKey.APIKeyAuth.IdentityHeader != "x-identity" {
		t.Fatalf("http api key auth config = %#v, want strip + identity header", httpAPIKey.APIKeyAuth)
	}

	grpcOIDC := policiesByName["grpc-oidc"]
	if grpcOIDC.Attachment.Level != model.GatewayAuthAttachmentLevelGRPCRoute || grpcOIDC.Attachment.Route == nil || grpcOIDC.Attachment.Route.Name != "grpc-app" {
		t.Fatalf("grpc oidc attachment = %#v, want grpc route attachment", grpcOIDC.Attachment)
	}
	if grpcOIDC.OIDC == nil || !grpcOIDC.OIDC.ClientSecret.Found || !grpcOIDC.OIDC.CookieSecret.Found {
		t.Fatalf("grpc oidc secrets = %#v, want resolved refs", grpcOIDC.OIDC)
	}
	if grpcOIDC.OIDC.Endpoints == nil || grpcOIDC.OIDC.Endpoints.Token != "https://issuer.example.com/token" {
		t.Fatalf("grpc oidc endpoints = %#v, want token endpoint", grpcOIDC.OIDC.Endpoints)
	}
	if got := bindingsByScope["GRPCRoute:grpc:default/grpc-app"]; got != "grpc-oidc" {
		t.Fatalf("grpc route binding = %q, want grpc-oidc", got)
	}
}

func TestToGatewayAuthModelPrecedenceAndConflicts(t *testing.T) {
	gatewayPolicyOld := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	gatewayPolicyOld.SetNamespace("default")
	gatewayPolicyOld.SetName("gw-old")
	gatewayPolicyOld.SetCreationTimestamp(metav1.NewTime(time.Unix(10, 0)))
	gatewayPolicyNew := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	gatewayPolicyNew.SetNamespace("default")
	gatewayPolicyNew.SetName("gw-new")
	gatewayPolicyNew.SetCreationTimestamp(metav1.NewTime(time.Unix(20, 0)))

	listenerPolicy := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	listenerPolicy.SetNamespace("default")
	listenerPolicy.SetName("listener-web")
	listenerPolicy.SetCreationTimestamp(metav1.NewTime(time.Unix(30, 0)))

	routePolicyOld := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	routePolicyOld.SetNamespace("default")
	routePolicyOld.SetName("route-old")
	routePolicyOld.SetCreationTimestamp(metav1.NewTime(time.Unix(40, 0)))
	routePolicyNew := &ciliumv2alpha1.CiliumGatewayAuthPolicy{}
	routePolicyNew.SetNamespace("default")
	routePolicyNew.SetName("route-new")
	routePolicyNew.SetCreationTimestamp(metav1.NewTime(time.Unix(50, 0)))

	input := Input{
		Gateway: gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{Name: "gw", Namespace: "default"},
			Spec: gatewayv1.GatewaySpec{
				Listeners: []gatewayv1.Listener{
					{Name: gatewayv1.SectionName("web")},
					{Name: gatewayv1.SectionName("api")},
				},
			},
		},
		HTTPRoutes: []gatewayv1.HTTPRoute{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
				Spec: gatewayv1.HTTPRouteSpec{
					CommonRouteSpec: gatewayv1.CommonRouteSpec{
						ParentRefs: []gatewayv1.ParentReference{
							{
								Name:        gatewayv1.ObjectName("gw"),
								SectionName: ptr.To(gatewayv1.SectionName("web")),
							},
						},
					},
					Rules: []gatewayv1.HTTPRouteRule{{}},
				},
			},
		},
		MergedListeners: []ListenerWithContext{
			{
				Listener: gatewayv1.Listener{Name: gatewayv1.SectionName("web")},
				Source: model.FullyQualifiedResource{
					Name:      "gw",
					Namespace: "default",
					Group:     gatewayv1.SchemeGroupVersion.Group,
					Version:   gatewayv1.SchemeGroupVersion.Version,
					Kind:      "Gateway",
				},
			},
			{
				Listener: gatewayv1.Listener{Name: gatewayv1.SectionName("api")},
				Source: model.FullyQualifiedResource{
					Name:      "gw",
					Namespace: "default",
					Group:     gatewayv1.SchemeGroupVersion.Group,
					Version:   gatewayv1.SchemeGroupVersion.Version,
					Kind:      "Gateway",
				},
			},
		},
		AuthPolicyAttachments: &gatewayhelpers.CiliumGatewayAuthPolicyAttachments{
			Gateway: gatewayhelpers.CiliumGatewayAuthPolicyAttachmentCollection{
				Resource: []gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
					{Policy: gatewayPolicyOld, TargetRef: gatewayTargetRef("gw", nil)},
					{Policy: gatewayPolicyNew, TargetRef: gatewayTargetRef("gw", nil)},
				},
				Sections: map[gatewayv1.SectionName][]gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
					gatewayv1.SectionName("web"): {
						{Policy: listenerPolicy, TargetRef: gatewayTargetRef("gw", ptr.To(gatewayv1.SectionName("web")))},
					},
				},
			},
			HTTPRoutes: map[types.NamespacedName]gatewayhelpers.CiliumGatewayAuthPolicyAttachmentCollection{
				{Namespace: "default", Name: "app"}: {
					Resource: []gatewayhelpers.CiliumGatewayAuthPolicyAttachment{
						{Policy: routePolicyOld, TargetRef: httpRouteTargetRef("app", nil)},
						{Policy: routePolicyNew, TargetRef: httpRouteTargetRef("app", nil)},
					},
				},
			},
			GRPCRoutes: map[types.NamespacedName]gatewayhelpers.CiliumGatewayAuthPolicyAttachmentCollection{},
		},
	}

	authModel := toGatewayAuthModel(input)
	if authModel == nil {
		t.Fatal("toGatewayAuthModel() returned nil")
	}
	if got := len(authModel.Conflicts); got != 2 {
		t.Fatalf("conflict count = %d, want 2", got)
	}

	conflicts := make(map[string]string, len(authModel.Conflicts))
	for _, conflict := range authModel.Conflicts {
		conflicts[conflict.Loser.Name] = conflict.Winner.Name
	}
	if conflicts["gw-new"] != "gw-old" {
		t.Fatalf("gateway conflict winner = %q, want gw-old", conflicts["gw-new"])
	}
	if conflicts["route-new"] != "route-old" {
		t.Fatalf("route conflict winner = %q, want route-old", conflicts["route-new"])
	}

	bindingsByScope := make(map[string]string, len(authModel.Bindings))
	for _, binding := range authModel.Bindings {
		bindingsByScope[bindingKey(binding.Scope)] = binding.Policy.Name
	}
	if got := bindingsByScope["Listener:web"]; got != "listener-web" {
		t.Fatalf("listener web binding = %q, want listener-web", got)
	}
	if got := bindingsByScope["Listener:api"]; got != "gw-old" {
		t.Fatalf("listener api binding = %q, want gw-old", got)
	}
	if got := bindingsByScope["HTTPRoute:web:default/app"]; got != "route-old" {
		t.Fatalf("http route binding = %q, want route-old", got)
	}
}

func TestApplyGatewayAuthSelections(t *testing.T) {
	m := &model.Model{
		HTTP: []model.HTTPListener{
			{
				Name: "web",
				Routes: []model.HTTPRoute{
					{
						SourceResource: &types.NamespacedName{Namespace: "default", Name: "app"},
					},
					{
						SourceResource: &types.NamespacedName{Namespace: "default", Name: "app"},
						SourceRuleName: "login",
					},
				},
			},
		},
		GatewayAuth: &model.GatewayAuthModel{
			Bindings: []model.GatewayAuthBinding{
				{
					Scope: model.GatewayAuthAttachment{
						Level:        model.GatewayAuthAttachmentLevelHTTPRoute,
						ListenerName: "web",
						Route:        &types.NamespacedName{Namespace: "default", Name: "app"},
					},
					Policy: model.FullyQualifiedResource{Name: "route-auth", Namespace: "default"},
				},
				{
					Scope: model.GatewayAuthAttachment{
						Level:        model.GatewayAuthAttachmentLevelHTTPRule,
						ListenerName: "web",
						Route:        &types.NamespacedName{Namespace: "default", Name: "app"},
						RouteRule:    "login",
					},
					Policy: model.FullyQualifiedResource{Name: "rule-auth", Namespace: "default"},
				},
			},
		},
	}

	applyGatewayAuthSelections(m)

	if got := m.HTTP[0].Routes[0].GatewayAuthPolicy; got != "default/route-auth" {
		t.Fatalf("route-level selection = %q, want default/route-auth", got)
	}
	if got := m.HTTP[0].Routes[1].GatewayAuthPolicy; got != "default/rule-auth" {
		t.Fatalf("rule-level selection = %q, want default/rule-auth", got)
	}
}

func bindingKey(scope model.GatewayAuthAttachment) string {
	key := string(scope.Level)
	if scope.ListenerName != "" {
		key += ":" + scope.ListenerName
	}
	if scope.Route != nil {
		key += ":" + scope.Route.String()
	}
	if scope.RouteRule != "" {
		key += ":" + scope.RouteRule
	}
	return key
}

func gatewayTargetRef(name string, sectionName *gatewayv1.SectionName) gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group(gatewayv1.GroupName),
			Kind:  gatewayv1.Kind("Gateway"),
			Name:  gatewayv1.ObjectName(name),
		},
		SectionName: sectionName,
	}
}

func httpRouteTargetRef(name string, sectionName *gatewayv1.SectionName) gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group(gatewayv1.GroupName),
			Kind:  gatewayv1.Kind("HTTPRoute"),
			Name:  gatewayv1.ObjectName(name),
		},
		SectionName: sectionName,
	}
}

func grpcRouteTargetRef(name string, sectionName *gatewayv1.SectionName) gatewayv1.LocalPolicyTargetReferenceWithSectionName {
	return gatewayv1.LocalPolicyTargetReferenceWithSectionName{
		LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
			Group: gatewayv1.Group(gatewayv1.GroupName),
			Kind:  gatewayv1.Kind("GRPCRoute"),
			Name:  gatewayv1.ObjectName(name),
		},
		SectionName: sectionName,
	}
}
