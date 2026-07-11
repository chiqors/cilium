// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"os"
	"strings"
	"testing"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	basicauthv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/basic_auth/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	oauth2v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/shortener"
)

func Test_translator_Translate(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		// Gateway API related tests
		{name: "basic_http_listener"},
		{name: "basic_http_listener_without_grpc_web_translation"},
		{name: "basic_http_listener_nodeport"},
		{name: "basic_http_listener_external_traffic_policy"},
		{name: "basic_http_listener_load_balancer"},
		{name: "basic_tls_sni_listener"},
		{name: "tls_sni_weighted_backends"},
		{name: "basic_https_multi_port_listener"},
		{name: "conformance/httproute_simple_same_namespace"},
		{name: "conformance/httproute_backend_protocol_h_2_c"},
		{name: "conformance/httproute_cross_namespace"},
		{name: "conformance/httpexact_path_matching"},
		{name: "conformance/httproute_header_matching"},
		{name: "conformance/httproute_hostname_intersection"},
		{name: "conformance/httproute_listener_hostname_matching"},
		{name: "conformance/httproute_matching_across_routes"},
		{name: "conformance/httproute_matching"},
		{name: "conformance/httproute_method_matching"},
		{name: "conformance/httproute_query_param_matching"},
		{name: "conformance/httproute_request_header_modifier"},
		{name: "conformance/httproute_backend_refs_request_header_modifier"},
		{name: "conformance/httproute_request_redirect"},
		{name: "conformance/httproute_response_header_modifier"},
		{name: "conformance/httproute_backend_refs_response_header_modifier"},
		{name: "conformance/httproute_rewrite_host"},
		{name: "conformance/httproute_rewrite_path"},
		{name: "conformance/httproute_request_mirror"},
		{name: "conformance/httproute_request_redirect_with_multi_httplisteners"},
		{name: "conformance/httproute_backend_protocol_h_2_c_app_protocol"},

		// TLSRoute related tests

		{name: "conformance/tlsroute_hostname_intersection"},

		// GAMMA related tests
		{name: "conformance/gamma/mesh_frontend"},
		{name: "conformance/gamma/mesh_ports"},
		{name: "conformance/gamma/mesh_splits"},
		{name: "httproute_external_auth_grpc"},
		{name: "httproute_external_auth_grpc_with_tls"},
		{name: "httproute_external_auth_http"},
		{name: "httproute_external_auth_http_with_tls"},
		{name: "httproute_external_auth_mixed"},
		{name: "httproute_external_auth_shared_and_no_auth"},
		{name: "tcproute_basic"},
		{name: "udproute_basic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := translation.Config{}
			readInput(t, fmt.Sprintf("testdata/%s/config-input.yaml", tt.name), &cfg)
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator(cfg),
			}

			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)
			expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
			// An empty cec-output.yaml means no CEC is expected (L4-only paths,
			// e.g. TCPRoute/UDPRoute, don't produce a CiliumEnvoyConfig).
			cecYaml := readOutput(t, fmt.Sprintf("testdata/%s/cec-output.yaml", tt.name), expectedCEC)
			var wantCEC *ciliumv2.CiliumEnvoyConfig
			if cecYaml != "" {
				wantCEC = expectedCEC
			}
			expectedService := &corev1.Service{}
			readOutput(t, fmt.Sprintf("testdata/%s/service-output.yaml", tt.name), expectedService)

			cec, svc, eps, err := trans.Translate(input)

			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			require.Equal(t, expectedService, svc, "Service mismatch")
			require.NotNil(t, eps)
			for i, ep := range eps {
				require.Equal(t, svc.Name, ep.Labels[discoveryv1.LabelServiceName], "EndpointSlice[%d] must carry the Service association label", i)
			}

			diffOutput := cmp.Diff(wantCEC, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}
		})
	}
}

func Test_translator_Translate_GatewayAuthResources(t *testing.T) {
	cfg := translation.Config{
		SecretsNamespace: "cilium-secrets",
		RouteConfig: translation.RouteConfig{
			HostNameSuffixMatch: true,
		},
		ListenerConfig: translation.ListenerConfig{
			StreamIdleTimeoutSeconds: 300,
		},
		ClusterConfig: translation.ClusterConfig{
			IdleTimeoutSeconds: 60,
		},
		IPConfig: translation.IPConfig{
			IPv4Enabled: true,
			IPv6Enabled: true,
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress:  true,
			XFFNumTrustedHops: 0,
		},
	}
	trans := &gatewayAPITranslator{
		cecTranslator: translation.NewCECTranslator(cfg),
	}

	input := &model.Model{
		HTTP: []model.HTTPListener{{
			Name:     "prod-web-gw",
			Port:     80,
			Hostname: "*",
			Routes: []model.HTTPRoute{
				{
					Hostnames:         []string{"*"},
					PathMatch:         model.StringMatch{Prefix: "/basic"},
					Backends:          []model.Backend{{Name: "my-service", Namespace: "default", Port: &model.BackendPort{Port: 8080}}},
					GatewayAuthPolicy: "default/basic",
					Timeout:           model.Timeout{},
				},
				{
					Hostnames:         []string{"*"},
					PathMatch:         model.StringMatch{Prefix: "/apikey"},
					Backends:          []model.Backend{{Name: "my-service", Namespace: "default", Port: &model.BackendPort{Port: 8080}}},
					GatewayAuthPolicy: "default/api-key",
					Timeout:           model.Timeout{},
				},
				{
					Hostnames:         []string{"*"},
					PathMatch:         model.StringMatch{Prefix: "/oidc"},
					Backends:          []model.Backend{{Name: "my-service", Namespace: "default", Port: &model.BackendPort{Port: 8080}}},
					GatewayAuthPolicy: "default/oidc",
					Timeout:           model.Timeout{},
				},
				{
					Hostnames:         []string{"*"},
					PathMatch:         model.StringMatch{Prefix: "/jwt"},
					Backends:          []model.Backend{{Name: "my-service", Namespace: "default", Port: &model.BackendPort{Port: 8080}}},
					GatewayAuthPolicy: "default/jwt-authz",
					Timeout:           model.Timeout{},
				},
				{
					Hostnames: []string{"*"},
					PathMatch: model.StringMatch{Prefix: "/open"},
					Backends:  []model.Backend{{Name: "my-service", Namespace: "default", Port: &model.BackendPort{Port: 8080}}},
					Timeout:   model.Timeout{},
				},
			},
			Service: &model.Service{
				Type:                           "LoadBalancer",
				LoadBalancerSourceRangesPolicy: "Allow",
			},
			Sources: []model.FullyQualifiedResource{{
				Group:     gatewayv1.GroupName,
				Version:   gatewayv1.GroupVersion.Version,
				Kind:      "Gateway",
				Name:      "my-gateway",
				Namespace: "default",
			}},
		}},
		GatewayAuth: &model.GatewayAuthModel{
			Policies: []model.GatewayAuthPolicy{
				{
					Source: model.FullyQualifiedResource{Name: "basic", Namespace: "default"},
					BasicAuth: &model.GatewayBasicAuth{
						Secret: model.GatewayAuthSecretRef{Name: "basic-auth", Key: "auth", Found: true, Value: []byte("alice:$apr1$hash")},
					},
				},
				{
					Source: model.FullyQualifiedResource{Name: "api-key", Namespace: "default"},
					APIKeyAuth: &model.GatewayAPIKeyAuth{
						Sources:         []model.GatewayAPIKeySource{{Type: "Header", Name: "x-api-key"}},
						Credentials:     []model.GatewayAPIKeyCredential{{Secret: model.GatewayAuthSecretRef{Name: "api-key", Key: "token", Found: true, Value: []byte("secret-a")}, Identity: "client-a"}},
						IdentityHeader:  "x-identity",
						StripCredential: true,
					},
				},
				{
					Source: model.FullyQualifiedResource{Name: "oidc", Namespace: "default"},
					OIDC: &model.GatewayOIDCAuth{
						Issuer:       "https://issuer.example.com",
						ClientID:     "client-id",
						ClientSecret: model.GatewayAuthSecretRef{Name: "oidc-client", Key: "client-secret", Found: true, Value: []byte("client-secret-value")},
						CookieSecret: model.GatewayAuthSecretRef{Name: "oidc-cookie", Key: "cookie-secret", Found: true, Value: []byte("cookie-secret-value")},
						Scopes:       []string{"openid"},
						Endpoints: &model.GatewayOIDCEndpoints{
							Authorization: "https://issuer.example.com/authorize",
							Token:         "https://issuer.example.com/token",
						},
					},
				},
				{
					Source: model.FullyQualifiedResource{Name: "jwt-authz", Namespace: "default"},
					JWT: &model.GatewayJWTAuth{
						Issuer:        "https://issuer.example.com",
						Audiences:     []string{"aud-a"},
						RemoteJWKSURI: "https://issuer.example.com/.well-known/jwks.json",
					},
					Authorization: &model.GatewayAuthorization{
						Rules: []model.GatewayAuthorizationRule{{
							Methods: []string{"GET"},
							Paths:   []string{"/jwt"},
						}},
					},
				},
			},
		},
	}

	cec, svc, _, err := trans.Translate(input)
	require.NoError(t, err)
	require.NotNil(t, cec)
	require.NotNil(t, svc)

	var listener *httpConnectionManagerv3.HttpConnectionManager
	var routeConfig *envoy_config_route_v3.RouteConfiguration
	clusterNames := map[string]struct{}{}

	for _, resource := range cec.Spec.Resources {
		switch {
		case strings.HasSuffix(resource.TypeUrl, "envoy.config.listener.v3.Listener"):
			l := &envoy_config_listener_v3.Listener{}
			require.NoError(t, proto.Unmarshal(resource.Value, l))
			require.NotEmpty(t, l.GetFilterChains())
			require.NotEmpty(t, l.GetFilterChains()[0].GetFilters())
			listener = &httpConnectionManagerv3.HttpConnectionManager{}
			require.NoError(t, proto.Unmarshal(l.GetFilterChains()[0].GetFilters()[0].GetTypedConfig().GetValue(), listener))
		case strings.HasSuffix(resource.TypeUrl, "envoy.config.route.v3.RouteConfiguration"):
			routeConfig = &envoy_config_route_v3.RouteConfiguration{}
			require.NoError(t, proto.Unmarshal(resource.Value, routeConfig))
		case strings.HasSuffix(resource.TypeUrl, "envoy.config.cluster.v3.Cluster"):
			cluster := &envoy_config_cluster_v3.Cluster{}
			require.NoError(t, proto.Unmarshal(resource.Value, cluster))
			clusterNames[cluster.Name] = struct{}{}
		}
	}

	require.NotNil(t, listener)
	require.NotNil(t, routeConfig)
	require.Equal(t, []string{
		"envoy.filters.http.grpc_web",
		"envoy.filters.http.grpc_stats",
		"envoy.filters.http.basic_auth/default",
		translation.APIKeyAuthFilterName,
		"envoy.filters.http.oauth2/default/oidc",
		translation.JWTAuthFilterName,
		translation.GatewayAuthorizationFilterName,
		"envoy.filters.http.router",
	}, httpFilterNames(listener.GetHttpFilters()))

	require.Contains(t, clusterNames, "default:my-service:8080")
	require.Contains(t, clusterNames, "jwt:https:issuer.example.com:443")
	require.Contains(t, clusterNames, "oidc:https:issuer.example.com:443")

	require.Len(t, routeConfig.GetVirtualHosts(), 1)
	routesByPrefix := map[string]*envoy_config_route_v3.Route{}
	for _, route := range routeConfig.GetVirtualHosts()[0].GetRoutes() {
		routesByPrefix[route.GetMatch().GetPathSeparatedPrefix()] = route
	}

	basicRoute := routesByPrefix["/basic"]
	require.NotNil(t, basicRoute)
	basicPerRoute := &basicauthv3.BasicAuthPerRoute{}
	require.NoError(t, proto.Unmarshal(basicRoute.GetTypedPerFilterConfig()["envoy.filters.http.basic_auth/default"].GetValue(), basicPerRoute))
	require.Equal(t, "alice:$apr1$hash", basicPerRoute.GetUsers().GetInlineString())

	apiKeyRoute := routesByPrefix["/apikey"]
	require.NotNil(t, apiKeyRoute)
	apiKeyPerRoute := &luav3.LuaPerRoute{}
	require.NoError(t, proto.Unmarshal(apiKeyRoute.GetTypedPerFilterConfig()[translation.APIKeyAuthFilterName].GetValue(), apiKeyPerRoute))
	require.Equal(t, "x-identity", apiKeyPerRoute.GetFilterContext().GetFields()["identity_header"].GetStringValue())

	oidcRoute := routesByPrefix["/oidc"]
	require.NotNil(t, oidcRoute)
	_, hasSelectedOIDCOverride := oidcRoute.GetTypedPerFilterConfig()["envoy.filters.http.oauth2/default/oidc"]
	require.False(t, hasSelectedOIDCOverride)

	jwtRoute := routesByPrefix["/jwt"]
	require.NotNil(t, jwtRoute)
	jwtPerRoute := &jwtauthnv3.PerRouteConfig{}
	require.NoError(t, proto.Unmarshal(jwtRoute.GetTypedPerFilterConfig()[translation.JWTAuthFilterName].GetValue(), jwtPerRoute))
	require.Equal(t, "default/jwt-authz", jwtPerRoute.GetRequirementName())
	rbacPerRoute := &rbacv3.RBACPerRoute{}
	require.NoError(t, proto.Unmarshal(jwtRoute.GetTypedPerFilterConfig()[translation.GatewayAuthorizationFilterName].GetValue(), rbacPerRoute))
	require.NotNil(t, rbacPerRoute.GetRbac())
	require.Contains(t, rbacPerRoute.GetRbac().GetRules().GetPolicies(), "rule-0")

	openRoute := routesByPrefix["/open"]
	require.NotNil(t, openRoute)
	openJWTPerRoute := &jwtauthnv3.PerRouteConfig{}
	require.NoError(t, proto.Unmarshal(openRoute.GetTypedPerFilterConfig()[translation.JWTAuthFilterName].GetValue(), openJWTPerRoute))
	require.True(t, openJWTPerRoute.GetDisabled())
	openRBACPerRoute := &rbacv3.RBACPerRoute{}
	require.NoError(t, proto.Unmarshal(openRoute.GetTypedPerFilterConfig()[translation.GatewayAuthorizationFilterName].GetValue(), openRBACPerRoute))
	require.Nil(t, openRBACPerRoute.GetRbac())

	oauth2Filter := &oauth2v3.OAuth2{}
	require.NoError(t, proto.Unmarshal(listener.GetHttpFilters()[4].GetTypedConfig().GetValue(), oauth2Filter))
	require.Equal(t, "client-id", oauth2Filter.GetConfig().GetCredentials().GetClientId())
}

func httpFilterNames(filters []*httpConnectionManagerv3.HttpFilter) []string {
	names := make([]string, 0, len(filters))
	for _, filter := range filters {
		names = append(names, filter.Name)
	}
	return names
}

func Test_translator_Translate_HostNetwork(t *testing.T) {
	tests := []struct {
		name              string
		nodeLabelSelector *slim_metav1.LabelSelector
		ipv4Enabled       bool
		ipv6Enabled       bool
		wantErr           bool
	}{
		{
			name:        "host_network/basic_http_listener",
			ipv4Enabled: true,
		},
		{
			name:        "host_network/basic_http_listener_with_different_port",
			ipv4Enabled: true,
		},
		{
			name:        "host_network/basic_http_listener_with_different_port_and_ipv_6",
			ipv4Enabled: false,
			ipv6Enabled: true,
		},
		{
			name:        "host_network/basic_http_listener_with_label_selector",
			ipv4Enabled: true,
			nodeLabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]slim_metav1.MatchLabelsValue{
					"a": "b",
				},
			},
		},
	}
	for _, tt := range tests {
		translatorCases := []struct {
			name string
			cfg  translation.Config
		}{
			{
				name: "without_external_traffic_policy",
				cfg: translation.Config{
					SecretsNamespace: "cilium-secrets",
					RouteConfig: translation.RouteConfig{
						HostNameSuffixMatch: true,
					},
					ListenerConfig: translation.ListenerConfig{
						StreamIdleTimeoutSeconds: 300,
					},
					ClusterConfig: translation.ClusterConfig{
						IdleTimeoutSeconds: 60,
					},
					HostNetworkConfig: translation.HostNetworkConfig{
						Enabled:           true,
						NodeLabelSelector: tt.nodeLabelSelector,
					},
					IPConfig: translation.IPConfig{
						IPv4Enabled: tt.ipv4Enabled,
						IPv6Enabled: tt.ipv6Enabled,
					},
					OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
						UseRemoteAddress:  true,
						XFFNumTrustedHops: 0,
					},
				},
			},
			{
				name: "with_external_traffic_policy",
				cfg: translation.Config{
					SecretsNamespace: "cilium-secrets",
					ServiceConfig: translation.ServiceConfig{
						ExternalTrafficPolicy: "Cluster",
					},
					RouteConfig: translation.RouteConfig{
						HostNameSuffixMatch: true,
					},
					ListenerConfig: translation.ListenerConfig{
						StreamIdleTimeoutSeconds: 300,
					},
					ClusterConfig: translation.ClusterConfig{
						IdleTimeoutSeconds: 60,
					},
					HostNetworkConfig: translation.HostNetworkConfig{
						Enabled:           true,
						NodeLabelSelector: tt.nodeLabelSelector,
					},
					IPConfig: translation.IPConfig{
						IPv4Enabled: tt.ipv4Enabled,
						IPv6Enabled: tt.ipv6Enabled,
					},
					OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
						UseRemoteAddress:  true,
						XFFNumTrustedHops: 0,
					},
				},
			},
		}

		t.Run(tt.name, func(t *testing.T) {
			for _, translatorCase := range translatorCases {
				t.Run(translatorCase.name, func(t *testing.T) {
					trans := &gatewayAPITranslator{
						cecTranslator: translation.NewCECTranslator(translatorCase.cfg),
						cfg:           translatorCase.cfg,
					}
					input := &model.Model{}
					readInput(t, fmt.Sprintf("testdata/%s/%s/input.yaml", tt.name, translatorCase.name), input)
					output := &ciliumv2.CiliumEnvoyConfig{}
					readOutput(t, fmt.Sprintf("testdata/%s/%s/cec-output.yaml", tt.name, translatorCase.name), output)
					expectedService := &corev1.Service{}
					readOutput(t, fmt.Sprintf("testdata/%s/%s/service-output.yaml", tt.name, translatorCase.name), expectedService)

					cec, svc, eps, err := trans.Translate(input)
					require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
					require.Equal(t, expectedService, svc, "Service mismatch")
					require.NotNil(t, eps)
					for i, ep := range eps {
						require.Equal(t, svc.Name, ep.Labels[discoveryv1.LabelServiceName], "EndpointSlice[%d] must carry the Service association label", i)
					}

					diffOutput := cmp.Diff(output, cec, protocmp.Transform())
					if len(diffOutput) != 0 {
						t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
					}
				})
			}
		})
	}
}

func Test_translator_Translate_WithXffNumTrustedHops(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "basic_http_listener_with_xff_num_trusted_hops"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := translation.Config{
				HostNetworkConfig: translation.HostNetworkConfig{
					Enabled: true,
				},
				OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
					UseRemoteAddress:  true,
					XFFNumTrustedHops: 2,
				},
				ListenerConfig: translation.ListenerConfig{
					StreamIdleTimeoutSeconds: 300,
				},
				ClusterConfig: translation.ClusterConfig{
					IdleTimeoutSeconds: 60,
				},
				IPConfig: translation.IPConfig{
					IPv4Enabled: true,
					IPv6Enabled: true,
				},
			}
			trans := &gatewayAPITranslator{
				cecTranslator: translation.NewCECTranslator(cfg),
				cfg:           cfg,
			}

			input := &model.Model{}
			readInput(t, fmt.Sprintf("testdata/%s/input.yaml", tt.name), input)
			output := &ciliumv2.CiliumEnvoyConfig{}
			readOutput(t, fmt.Sprintf("testdata/%s/cec-output.yaml", tt.name), output)
			expectedService := &corev1.Service{}
			readOutput(t, fmt.Sprintf("testdata/%s/service-output.yaml", tt.name), expectedService)

			cec, svc, ep, err := trans.Translate(input)
			require.Equal(t, tt.wantErr, err != nil, "Error mismatch")
			require.Equal(t, expectedService, svc, "Service mismatch")
			diffOutput := cmp.Diff(output, cec, protocmp.Transform())
			if len(diffOutput) != 0 {
				t.Errorf("CiliumEnvoyConfigs did not match:\n%s\n", diffOutput)
			}

			require.NotNil(t, svc)
			assert.Equal(t, corev1.ServiceTypeNodePort, svc.Spec.Type)

			require.NotNil(t, ep)
		})
	}
}

func Test_translator_Translate_L4Only(t *testing.T) {
	trans := &gatewayAPITranslator{
		cecTranslator: translation.NewCECTranslator(translation.Config{}),
	}
	source := model.FullyQualifiedResource{
		Name:      "test",
		Namespace: "default",
		Kind:      "Gateway",
		UID:       "uid",
	}
	input := &model.Model{
		L4: []model.L4Listener{
			{
				Name:     "tcp",
				Sources:  []model.FullyQualifiedResource{source},
				Port:     80,
				Protocol: model.L4ProtocolTCP,
			},
			{
				Name:     "udp",
				Sources:  []model.FullyQualifiedResource{source},
				Port:     53,
				Protocol: model.L4ProtocolUDP,
			},
		},
	}

	cec, svc, _, err := trans.Translate(input)
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.Nil(t, cec)
	assert.ElementsMatch(t, []corev1.ServicePort{
		{
			Name:     "port-80",
			Port:     80,
			Protocol: corev1.ProtocolTCP,
		},
		{
			Name:     "port-53-udp",
			Port:     53,
			Protocol: corev1.ProtocolUDP,
		},
	}, svc.Spec.Ports)
}

func Test_translator_Translate_L4MaglevWeightAnnotation(t *testing.T) {
	trans := &gatewayAPITranslator{
		cecTranslator: translation.NewCECTranslator(translation.Config{}),
	}
	source := model.FullyQualifiedResource{
		Name:      "test",
		Namespace: "default",
		Kind:      "Gateway",
		UID:       "uid",
	}
	l4 := func(backend model.Backend) []model.L4Listener {
		return []model.L4Listener{
			{
				Name:     "tcp",
				Sources:  []model.FullyQualifiedResource{source},
				Port:     80,
				Protocol: model.L4ProtocolTCP,
				Routes: []model.L4Route{
					{Backends: []model.Backend{backend}},
				},
			},
		}
	}

	// Weighted L4 backend -> maglev annotation set (datapath honors weights).
	input := &model.Model{L4: l4(model.Backend{
		Name: "echo", Namespace: "default",
		Port: &model.BackendPort{Port: 9090}, Weight: ptr.To(int32(50)),
	})}
	_, svc, eps, err := trans.Translate(input)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, lbAlgorithmMaglev, svc.Annotations[lbAlgorithmAnnotation])
	require.NotEmpty(t, eps, "weighted L4 backend must yield EndpointSlices")

	// No weights -> no maglev annotation.
	input = &model.Model{L4: l4(model.Backend{
		Name: "echo", Namespace: "default", Port: &model.BackendPort{Port: 9090},
	})}
	_, svc, _, err = trans.Translate(input)
	require.NoError(t, err)
	require.NotNil(t, svc)
	_, ok := svc.Annotations[lbAlgorithmAnnotation]
	assert.False(t, ok, "unweighted L4 backend must not set maglev annotation")
}

func Test_translator_toServicePorts_MixedProtocolsSamePort(t *testing.T) {
	trans := &gatewayAPITranslator{}
	listeners := []model.Listener{
		&model.L4Listener{
			Port:     80,
			Protocol: model.L4ProtocolUDP,
		},
		&model.HTTPListener{
			Port: 80,
		},
		&model.TLSPassthroughListener{
			Port: 53,
		},
		&model.L4Listener{
			Port:     53,
			Protocol: model.L4ProtocolUDP,
		},
	}

	servicePorts := trans.toServicePorts(listeners)
	assert.Equal(t, []corev1.ServicePort{
		{
			Name:     "port-53",
			Port:     53,
			Protocol: corev1.ProtocolTCP,
		},
		{
			Name:     "port-53-udp",
			Port:     53,
			Protocol: corev1.ProtocolUDP,
		},
		{
			Name:     "port-80",
			Port:     80,
			Protocol: corev1.ProtocolTCP,
		},
		{
			Name:     "port-80-udp",
			Port:     80,
			Protocol: corev1.ProtocolUDP,
		},
	}, servicePorts)
}

func Test_getService(t *testing.T) {
	type args struct {
		resource              *model.FullyQualifiedResource
		allPorts              []corev1.ServicePort
		labels                map[string]string
		annotations           map[string]string
		externalTrafficPolicy string
	}
	tests := []struct {
		name string
		args args
		want *corev1.Service
	}{
		{
			name: "long name - more than 64 characters",
			args: args{
				resource: &model.FullyQualifiedResource{
					Name:      "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
					Namespace: "default",
					Version:   "v1",
					Kind:      "Gateway",
					UID:       "57889650-380b-4c05-9a2e-3baee7fd5271",
				},
				allPorts: []corev1.ServicePort{
					{
						Name:     fmt.Sprintf("port-%d", 80),
						Port:     80,
						Protocol: corev1.ProtocolTCP,
					},
				},
				externalTrafficPolicy: "Cluster",
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-long-long-long-long-long-long-lo-8tfth549c6",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel:                       "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
						"gateway.networking.k8s.io/gateway-name": "test-long-long-long-long-long-long-long-long-long-lo-4bftbgh5ht",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-long-long-long-long-long-long-long-long-long-long-long-long-name",
							UID:        types.UID("57889650-380b-4c05-9a2e-3baee7fd5271"),
							Controller: ptr.To(true),
						},
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:     fmt.Sprintf("port-%d", 80),
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
					Type:                  corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyCluster,
				},
			},
		},
		{
			name: "externaltrafficpolicy set to local",
			args: args{
				resource: &model.FullyQualifiedResource{
					Name:      "test-externaltrafficpolicy-local",
					Namespace: "default",
					Version:   "v1",
					Kind:      "Gateway",
					UID:       "41b82697-2d8d-4776-81b6-44d0bbac7faa",
				},
				allPorts:              []corev1.ServicePort{{Name: "port-80", Port: 80, Protocol: corev1.ProtocolTCP}},
				externalTrafficPolicy: "Local",
			},
			want: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "cilium-gateway-test-externaltrafficpolicy-local",
					Namespace: "default",
					Labels: map[string]string{
						owningGatewayLabel:                       "test-externaltrafficpolicy-local",
						"gateway.networking.k8s.io/gateway-name": "test-externaltrafficpolicy-local",
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       "test-externaltrafficpolicy-local",
							UID:        types.UID("41b82697-2d8d-4776-81b6-44d0bbac7faa"),
							Controller: ptr.To(true),
						},
					},
				},
				Spec: corev1.ServiceSpec{
					Ports: []corev1.ServicePort{
						{
							Name:     fmt.Sprintf("port-%d", 80),
							Port:     80,
							Protocol: corev1.ProtocolTCP,
						},
					},
					Type:                  corev1.ServiceTypeLoadBalancer,
					ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trans := &gatewayAPITranslator{cfg: translation.Config{
				ServiceConfig: translation.ServiceConfig{
					ExternalTrafficPolicy: tt.args.externalTrafficPolicy,
				},
			}}
			got := trans.desiredService(nil, tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations)
			assert.Equalf(t, tt.want, got, "desiredService(%v, %v, %v, %v)", tt.args.resource, tt.args.allPorts, tt.args.labels, tt.args.annotations)
			assert.LessOrEqual(t, len(got.Name), 63, "Service name is too long")
		})
	}
}

func Test_desiredL7DummyEndpointSlice(t *testing.T) {
	trans := &gatewayAPITranslator{}
	owner := &model.FullyQualifiedResource{
		Name:      "dummy-gateway",
		Namespace: "dummy-namespace",
		Version:   "v1",
		Kind:      "Gateway",
		UID:       "57889650-380b-4c05-9a2e-3baee7fd5271",
	}

	got := trans.desiredL7DummyEndpointSlice(owner, nil, nil)

	require.Equal(t, []*discoveryv1.EndpointSlice{{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cilium-gateway-dummy-gateway",
			Namespace: "dummy-namespace",
			Labels: map[string]string{
				owningGatewayLabel:           "dummy-gateway",
				gatewayNameLabel:             "dummy-gateway",
				discoveryv1.LabelServiceName: "cilium-gateway-dummy-gateway",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: gatewayv1.GroupVersion.String(),
					Kind:       "Gateway",
					Name:       "dummy-gateway",
					UID:        types.UID("57889650-380b-4c05-9a2e-3baee7fd5271"),
					Controller: ptr.To(true),
				},
			},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{"192.192.192.192"},
				Conditions: discoveryv1.EndpointConditions{
					Ready: ptr.To(true),
				},
			},
		},
		Ports: []discoveryv1.EndpointPort{
			{Port: ptr.To[int32](9999)},
		},
	}}, got)
}

func Test_translator_Translate_ShortensCECName(t *testing.T) {
	trans := &gatewayAPITranslator{
		cecTranslator: translation.NewCECTranslator(translation.Config{}),
	}

	longName := "test-long-long-long-long-long-long-long-long-long-long-long-long-name"
	input := &model.Model{
		HTTP: []model.HTTPListener{
			{
				Name: "listener",
				Sources: []model.FullyQualifiedResource{
					{
						Name:      longName,
						Namespace: "default",
						Group:     gatewayv1.GroupVersion.Group,
						Version:   gatewayv1.GroupVersion.Version,
						Kind:      "Gateway",
						UID:       "57889650-380b-4c05-9a2e-3baee7fd5271",
					},
				},
				Port: 80,
			},
		},
	}

	cec, svc, ep, err := trans.Translate(input)
	require.NoError(t, err)
	require.NotNil(t, cec)
	require.NotNil(t, svc)
	require.NotNil(t, ep)
	require.Equal(t, shortener.ShortenK8sResourceName(CiliumGatewayPrefix+longName), cec.Name)
	require.Equal(t, svc.Name, cec.Name)
	require.LessOrEqual(t, len(cec.Name), 63, "CiliumEnvoyConfig name is too long")
}

func readInput(t *testing.T, file string, obj any) {
	inputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	require.NoError(t, k8syaml.Unmarshal(inputYaml, obj))
}

func readOutput(t *testing.T, file string, obj any) string {
	// unmarshal and marshal to prevent formatting diffs
	outputYaml, err := os.ReadFile(file)
	require.NoError(t, err)

	if strings.TrimSpace(string(outputYaml)) == "" {
		return strings.TrimSpace(string(outputYaml))
	}

	require.NoError(t, k8syaml.Unmarshal(outputYaml, obj))

	yamlText := toYaml(t, obj)

	return strings.TrimSpace(yamlText)
}

func toYaml(t *testing.T, obj any) string {
	yamlText, err := k8syaml.Marshal(obj)
	require.NoError(t, err)

	return strings.TrimSpace(string(yamlText))
}
