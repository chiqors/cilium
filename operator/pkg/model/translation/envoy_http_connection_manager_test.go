// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	envoy_config_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	basicauthv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/basic_auth/v3"
	httpCORSv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	oauth2v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_desiredHTTPConnectionManager(t *testing.T) {
	t.Run("no CORS filter enabled", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)

		require.NoError(t, err)

		require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
		require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
		}, httpConnectionManager.GetRouteSpecifier())

		require.Len(t, httpConnectionManager.GetHttpFilters(), 3)
		require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
		require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[2].Name)

		require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
		require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
	})
	t.Run("CORS filter enabled", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)

		require.NoError(t, err)

		require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
		require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
		}, httpConnectionManager.GetRouteSpecifier())

		require.Len(t, httpConnectionManager.GetHttpFilters(), 4)
		require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
		require.Equal(t, "envoy.filters.http.cors", httpConnectionManager.GetHttpFilters()[2].Name)
		require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[3].Name)

		require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
		require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
	})
	t.Run("access logs configured", func(t *testing.T) {
		i := &cecTranslator{}
		m := &model.Model{
			Telemetry: &model.Telemetry{
				AccessLogs: map[model.AccessLogsTarget][]model.AccessLogs{
					model.AccessLogsTargetHTTP: {
						{
							Format: model.AccessLogsFormatText,
							Text:   "%REQ(:METHOD)% %RESPONSE_CODE%",
						},
					},
				},
			},
		}
		res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
		require.NoError(t, err)

		httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
		err = proto.Unmarshal(res.Value, httpConnectionManager)
		require.NoError(t, err)

		require.Len(t, httpConnectionManager.GetAccessLog(), 1)
		require.Equal(t, "envoy.access_loggers.stdout", httpConnectionManager.GetAccessLog()[0].GetName())
	})
}

func Test_getHTTPConnectionManagerHttpFilters(t *testing.T) {
	t.Run("no CORS filter enabled", func(t *testing.T) {
		m := &model.Model{}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 3)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.router", res[2].Name)
	})
	t.Run("CORS filter enabled", func(t *testing.T) {
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, "envoy.filters.http.cors", res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)

	})

	t.Run("basic auth filters are inserted in authentication stage", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{{
					GatewayAuthPolicy: "default/basic",
				}},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source:    model.FullyQualifiedResource{Name: "basic", Namespace: "default"},
					BasicAuth: &model.GatewayBasicAuth{UsernameHeader: "x-auth-user"},
				}},
			},
		}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, basicAuthFilterName("username-header:x-auth-user"), res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)
	})

	t.Run("api key auth filter is inserted in authentication stage", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{{
					GatewayAuthPolicy: "default/api-key",
				}},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "api-key", Namespace: "default"},
					APIKeyAuth: &model.GatewayAPIKeyAuth{
						Sources:     []model.GatewayAPIKeySource{{Type: "Header", Name: "x-api-key"}},
						Credentials: []model.GatewayAPIKeyCredential{{Secret: model.GatewayAuthSecretRef{Found: true, Value: []byte("secret")}}},
					},
				}},
			},
		}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, APIKeyAuthFilterName, res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)

		luaFilter := &luav3.Lua{}
		require.NoError(t, proto.Unmarshal(res[2].GetTypedConfig().Value, luaFilter))
		require.Contains(t, luaFilter.GetDefaultSourceCode().GetInlineString(), "envoy_on_request")
	})

	t.Run("jwt auth filter is inserted in authentication stage", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{{
					GatewayAuthPolicy: "default/jwt",
				}},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "jwt", Namespace: "default"},
					JWT: &model.GatewayJWTAuth{
						Issuer:    "https://issuer.example.com",
						Audiences: []string{"aud-a"},
						LocalJWKS: &model.GatewayLocalJWKS{
							ConfigMap: &model.GatewayAuthConfigMapRef{Found: true, Value: []byte(`{"keys":[]}`)},
						},
						ClaimToHeaders: []model.GatewayClaimToHeader{{Claim: "sub", Header: "x-jwt-sub"}},
					},
				}},
			},
		}
		i := &cecTranslator{}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, "envoy.filters.http.grpc_web", res[0].Name)
		require.Equal(t, "envoy.filters.http.grpc_stats", res[1].Name)
		require.Equal(t, JWTAuthFilterName, res[2].Name)
		require.Equal(t, "envoy.filters.http.router", res[3].Name)

		jwtFilter := &jwtauthnv3.JwtAuthentication{}
		require.NoError(t, proto.Unmarshal(res[2].GetTypedConfig().Value, jwtFilter))
		require.Contains(t, jwtFilter.GetProviders(), "default/jwt")
		require.Contains(t, jwtFilter.GetRequirementMap(), "default/jwt")
		require.Equal(t, "https://issuer.example.com", jwtFilter.GetProviders()["default/jwt"].GetIssuer())
		require.Equal(t, []string{"aud-a"}, jwtFilter.GetProviders()["default/jwt"].GetAudiences())
		require.Equal(t, `{"keys":[]}`, jwtFilter.GetProviders()["default/jwt"].GetLocalJwks().GetInlineString())
		require.Equal(t, "x-jwt-sub", jwtFilter.GetProviders()["default/jwt"].GetClaimToHeaders()[0].GetHeaderName())
		require.Equal(t, "default/jwt", jwtFilter.GetProviders()["default/jwt"].GetPayloadInMetadata())
	})

	t.Run("oidc auth filter is inserted in authentication stage", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{{GatewayAuthPolicy: "default/oidc"}},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "oidc", Namespace: "default"},
					OIDC: &model.GatewayOIDCAuth{
						Issuer:       "https://issuer.example.com",
						ClientID:     "client-id",
						ClientSecret: model.GatewayAuthSecretRef{Name: "client", Key: "clientSecret", Found: true},
						CookieSecret: model.GatewayAuthSecretRef{Name: "cookie", Key: "cookieSecret", Found: true},
						Endpoints: &model.GatewayOIDCEndpoints{
							Authorization: "https://issuer.example.com/authorize",
							Token:         "https://issuer.example.com/token",
						},
					},
				}},
			},
		}
		i := &cecTranslator{Config: Config{SecretsNamespace: "cilium-secrets"}}
		res := i.getHTTPConnectionManagerHttpFilters(m)

		require.Len(t, res, 4)
		require.Equal(t, oidcFilterName(m.GatewayAuth.Policies[0]), res[2].Name)

		oauth2Filter := &oauth2v3.OAuth2{}
		require.NoError(t, proto.Unmarshal(res[2].GetTypedConfig().Value, oauth2Filter))
		require.Equal(t, "client-id", oauth2Filter.GetConfig().GetCredentials().GetClientId())
		require.Equal(t, "cilium-secrets/default-client-clientsecret", oauth2Filter.GetConfig().GetCredentials().GetTokenSecret().GetName())
		require.Equal(t, "cilium-secrets/default-cookie-cookiesecret", oauth2Filter.GetConfig().GetCredentials().GetHmacSecret().GetName())
		require.NotNil(t, oauth2Filter.GetConfig().GetCredentials().GetTokenSecret().GetSdsConfig())
		require.NotNil(t, oauth2Filter.GetConfig().GetCredentials().GetHmacSecret().GetSdsConfig())
		require.Equal(t, "https://issuer.example.com/token", oauth2Filter.GetConfig().GetTokenEndpoint().GetUri())
	})
}

func Test_getHTTPFilterStages(t *testing.T) {
	i := &cecTranslator{}

	t.Run("native auth stages empty until provider translators land", func(t *testing.T) {
		m := &model.Model{}
		require.Nil(t, i.getHTTPRouteMutationFilters(m))
		require.Nil(t, i.getHTTPAuthenticationFilters(m))
	})

	t.Run("authorization stage contains ext auth filters", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{
						ExternalAuth: &model.HTTPExternalAuthFilter{
							Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
							Protocol: model.ExternalAuthProtocolGRPC,
						},
					},
				},
			}},
		}

		res := i.getHTTPAuthorizationFilters(m)
		require.Len(t, res, 1)
		require.Contains(t, res[0].Name, "envoy.filters.http.ext_authz")
	})

	t.Run("authorization stage inserts gateway rbac before ext auth filters", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{
						GatewayAuthPolicy: "default/authz",
						ExternalAuth: &model.HTTPExternalAuthFilter{
							Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
							Protocol: model.ExternalAuthProtocolGRPC,
						},
					},
				},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "authz", Namespace: "default"},
					Authorization: &model.GatewayAuthorization{
						Rules: []model.GatewayAuthorizationRule{{Methods: []string{"GET"}}},
					},
				}},
			},
		}

		res := i.getHTTPAuthorizationFilters(m)
		require.Len(t, res, 2)
		require.Equal(t, GatewayAuthorizationFilterName, res[0].Name)
		require.Contains(t, res[1].Name, "envoy.filters.http.ext_authz")

		rbacFilter := &rbacv3.RBAC{}
		require.NoError(t, proto.Unmarshal(res[0].GetTypedConfig().Value, rbacFilter))
		require.Nil(t, rbacFilter.GetRules())
	})

	t.Run("terminal stage contains cors before router", func(t *testing.T) {
		m := &model.Model{HTTP: []model.HTTPListener{
			{
				Routes: []model.HTTPRoute{
					{
						CORS: &model.HTTPCORSFilter{AllowOrigins: []string{"*"}},
					},
				},
			},
		}}

		res := i.getHTTPTerminalFilters(m)
		require.Len(t, res, 2)
		require.Equal(t, "envoy.filters.http.cors", res[0].Name)
		require.Equal(t, "envoy.filters.http.router", res[1].Name)
	})
}

func Test_desiredHTTPConnectionManager_withExtAuthz(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTP: []model.HTTPListener{{
			Routes: []model.HTTPRoute{
				{
					ExternalAuth: &model.HTTPExternalAuthFilter{
						Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
						Protocol: model.ExternalAuthProtocolGRPC,
					},
				},
				{
					ExternalAuth: &model.HTTPExternalAuthFilter{
						Backend:    model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
						Protocol:   model.ExternalAuthProtocolHTTP,
						PathPrefix: "/auth",
					},
				},
			},
		}},
	}
	authFilters := i.getUniqueAuthFilters(m)
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	require.NoError(t, proto.Unmarshal(res.Value, hcm))

	// grpc_web, grpc_stats, ext_authz/grpc, ext_authz/http, router
	require.Len(t, hcm.GetHttpFilters(), 5)
	require.Equal(t, "envoy.filters.http.grpc_web", hcm.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", hcm.GetHttpFilters()[1].Name)
	require.Equal(t, ExtAuthzFilterName(extAuthzFilterKey(authFilters[0])), hcm.GetHttpFilters()[2].Name)
	require.Equal(t, ExtAuthzFilterName(extAuthzFilterKey(authFilters[1])), hcm.GetHttpFilters()[3].Name)
	require.Equal(t, "envoy.filters.http.router", hcm.GetHttpFilters()[4].Name)

	// Verify GRPC filter points to the right cluster
	grpcFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[2].GetTypedConfig().Value, grpcFilter))
	require.NotNil(t, grpcFilter.GetGrpcService())
	require.Equal(t, "grpc:default:grpc-authz:9000", grpcFilter.GetGrpcService().GetEnvoyGrpc().GetClusterName())

	// Verify HTTP filter has path prefix
	httpFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[3].GetTypedConfig().Value, httpFilter))
	require.NotNil(t, httpFilter.GetHttpService())
	require.Equal(t, "/auth", httpFilter.GetHttpService().GetPathPrefix())
	require.Equal(t, "http:default:http-authz:8080", httpFilter.GetHttpService().GetServerUri().GetCluster())
}

func Test_buildExtAuthzHTTPFilter_forwardBody(t *testing.T) {
	t.Run("forward body set on GRPC filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:    model.ExternalAuthProtocolGRPC,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 4096},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(4096), config.GetWithRequestBody().GetMaxRequestBytes())
		require.True(t, config.GetWithRequestBody().GetAllowPartialMessage())
	})

	t.Run("forward body set on HTTP filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    model.ExternalAuthProtocolHTTP,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 8192},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(8192), config.GetWithRequestBody().GetMaxRequestBytes())
		require.True(t, config.GetWithRequestBody().GetAllowPartialMessage())
	})

	t.Run("no forward body when nil", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol: model.ExternalAuthProtocolHTTP,
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})

	t.Run("no forward body when max size is zero", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    model.ExternalAuthProtocolHTTP,
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 0},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})
}

func Test_buildExtAuthzHTTPFilter_allowedRequestHeaders(t *testing.T) {
	// Per the Gateway API spec: if AllowedRequestHeaders is empty, all headers must be sent.
	// We achieve this by leaving AllowedHeaders unset; Envoy then forwards all headers by default.
	t.Run("GRPC empty list forwards all headers (spec: empty means send all)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:              model.ExternalAuthProtocolGRPC,
			AllowedRequestHeaders: []string{},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("GRPC nil list forwards all headers (spec: empty means send all)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol: model.ExternalAuthProtocolGRPC,
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("GRPC explicit headers forwarded", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:              model.ExternalAuthProtocolGRPC,
			AllowedRequestHeaders: []string{"X-Custom-Header", "X-Tenant-ID"},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetAllowedHeaders())
		require.Len(t, config.GetAllowedHeaders().GetPatterns(), 2)
		require.Equal(t, "X-Custom-Header", config.GetAllowedHeaders().GetPatterns()[0].GetExact())
		require.Equal(t, "X-Tenant-ID", config.GetAllowedHeaders().GetPatterns()[1].GetExact())
	})

	t.Run("HTTP empty list produces no AllowedHeaders (Envoy rejects empty matcher)", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:              model.ExternalAuthProtocolHTTP,
			AllowedRequestHeaders: []string{},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetAllowedHeaders())
	})

	t.Run("HTTP explicit headers forwarded", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:               model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:              model.ExternalAuthProtocolHTTP,
			AllowedRequestHeaders: []string{"X-Custom-Header"},
		}
		filter := buildExtAuthzHTTPFilter(af)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetAllowedHeaders())
		require.Len(t, config.GetAllowedHeaders().GetPatterns(), 1)
		require.Equal(t, "X-Custom-Header", config.GetAllowedHeaders().GetPatterns()[0].GetExact())
	})
}

func Test_getTypedPerFilterConfig(t *testing.T) {
	authFilters := []*model.HTTPExternalAuthFilter{
		{Backend: model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}, Protocol: model.ExternalAuthProtocolGRPC},
		{Backend: model.Backend{Name: "svc-b", Namespace: "ns", Port: &model.BackendPort{Port: 8080}}, Protocol: model.ExternalAuthProtocolHTTP},
	}

	t.Run("route without auth disables all filters", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, nil, authFilters, model.HTTPRoute{})
		require.Len(t, cfg, 2)
		for _, v := range cfg {
			perRoute := &extauthzv3.ExtAuthzPerRoute{}
			require.NoError(t, proto.Unmarshal(v.Value, perRoute))
			require.True(t, perRoute.GetDisabled())
		}
	})

	t.Run("route with auth enables its filter and disables others", func(t *testing.T) {
		routeAuth := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}},
			Protocol: model.ExternalAuthProtocolGRPC,
		}
		cfg := getTypedPerFilterConfig(nil, routeAuth, authFilters, model.HTTPRoute{})
		// Only svc-b should be disabled; svc-a has no entry (enabled by default)
		require.Len(t, cfg, 1)
		_, hasSvcA := cfg["envoy.filters.http.ext_authz/GRPC:ns:svc-a:9000"]
		require.False(t, hasSvcA, "active auth filter must not be explicitly disabled")
		disabledEntry, hasSvcB := cfg["envoy.filters.http.ext_authz/HTTP:ns:svc-b:8080"]
		require.True(t, hasSvcB)
		perRoute := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, proto.Unmarshal(disabledEntry.Value, perRoute))
		require.True(t, perRoute.GetDisabled())
	})

	t.Run("route with CORS filter", func(t *testing.T) {
		cfg := getTypedPerFilterConfig(nil, nil, nil, model.HTTPRoute{
			CORS: &model.HTTPCORSFilter{MaxAge: 42},
		})
		require.Len(t, cfg, 1)
		cors := &httpCORSv3.CorsPolicy{}
		require.NoError(t, proto.Unmarshal(cfg["envoy.filters.http.cors"].Value, cors))
	})

	t.Run("no auth filters returns nil", func(t *testing.T) {
		require.Nil(t, getTypedPerFilterConfig(nil, nil, nil, model.HTTPRoute{}))
	})

	t.Run("route with gateway basic auth enables its filter and disables others", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{GatewayAuthPolicy: "default/basic-a"},
					{GatewayAuthPolicy: "default/basic-b"},
				},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{
					{
						Source:    model.FullyQualifiedResource{Name: "basic-a", Namespace: "default"},
						BasicAuth: &model.GatewayBasicAuth{Secret: model.GatewayAuthSecretRef{Found: true, Value: []byte("alice:$apr1$hash")}},
					},
					{
						Source:    model.FullyQualifiedResource{Name: "basic-b", Namespace: "default"},
						BasicAuth: &model.GatewayBasicAuth{Secret: model.GatewayAuthSecretRef{Found: true, Value: []byte("bob:$apr1$hash")}, UsernameHeader: "x-auth-user"},
					},
				},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{GatewayAuthPolicy: "default/basic-b"})
		require.Len(t, cfg, 2)

		disabled := &envoy_config_route_v3.FilterConfig{}
		require.NoError(t, proto.Unmarshal(cfg[basicAuthFilterName("default")].Value, disabled))
		require.True(t, disabled.GetDisabled())

		perRoute := &basicauthv3.BasicAuthPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[basicAuthFilterName("username-header:x-auth-user")].Value, perRoute))
		require.Equal(t, "bob:$apr1$hash", perRoute.GetUsers().GetInlineString())
	})

	t.Run("route with gateway api key auth configures lua per-route context", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{GatewayAuthPolicy: "default/api-key"},
				},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{
					{
						Source: model.FullyQualifiedResource{Name: "api-key", Namespace: "default"},
						APIKeyAuth: &model.GatewayAPIKeyAuth{
							Sources: []model.GatewayAPIKeySource{
								{Type: "Header", Name: "x-api-key"},
								{Type: "Query", Name: "api_key"},
							},
							Credentials: []model.GatewayAPIKeyCredential{
								{Secret: model.GatewayAuthSecretRef{Found: true, Value: []byte("secret-a")}, Identity: "client-a"},
							},
							IdentityHeader:  "x-identity",
							StripCredential: true,
						},
					},
				},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{GatewayAuthPolicy: "default/api-key"})
		require.Len(t, cfg, 1)

		perRoute := &luav3.LuaPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[APIKeyAuthFilterName].Value, perRoute))
		require.False(t, perRoute.GetDisabled())
		require.Equal(t, "x-identity", perRoute.GetFilterContext().GetFields()["identity_header"].GetStringValue())
		require.True(t, perRoute.GetFilterContext().GetFields()["strip_credential"].GetBoolValue())
	})

	t.Run("route with gateway jwt auth configures per-route requirement", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{GatewayAuthPolicy: "default/jwt"},
					{},
				},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{
					{
						Source: model.FullyQualifiedResource{Name: "jwt", Namespace: "default"},
						JWT: &model.GatewayJWTAuth{
							Issuer:        "https://issuer.example.com",
							RemoteJWKSURI: "https://issuer.example.com/.well-known/jwks.json",
						},
					},
				},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{GatewayAuthPolicy: "default/jwt"})
		require.Len(t, cfg, 1)
		perRoute := &jwtauthnv3.PerRouteConfig{}
		require.NoError(t, proto.Unmarshal(cfg[JWTAuthFilterName].Value, perRoute))
		require.Equal(t, "default/jwt", perRoute.GetRequirementName())

		disabledCfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{})
		require.Len(t, disabledCfg, 1)
		disabled := &jwtauthnv3.PerRouteConfig{}
		require.NoError(t, proto.Unmarshal(disabledCfg[JWTAuthFilterName].Value, disabled))
		require.True(t, disabled.GetDisabled())
	})

	t.Run("oidc does not rely on per-route filter config", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{GatewayAuthPolicy: "default/oidc-a"}, {}}}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "oidc-a", Namespace: "default"},
					OIDC: &model.GatewayOIDCAuth{
						ClientID:     "client-a",
						ClientSecret: model.GatewayAuthSecretRef{Name: "client-a", Found: true},
						CookieSecret: model.GatewayAuthSecretRef{Name: "cookie-a", Found: true},
						Endpoints: &model.GatewayOIDCEndpoints{
							Authorization: "https://issuer.example.com/authorize",
							Token:         "https://issuer.example.com/token",
						},
					},
				}},
			},
		}

		require.Nil(t, getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{}))
	})

	t.Run("route with gateway authorization configures per-route rbac", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{GatewayAuthPolicy: "default/jwt-authz"},
					{},
				},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "jwt-authz", Namespace: "default"},
					JWT: &model.GatewayJWTAuth{
						Issuer:        "https://issuer.example.com",
						RemoteJWKSURI: "https://issuer.example.com/.well-known/jwks.json",
					},
					Authorization: &model.GatewayAuthorization{
						Rules: []model.GatewayAuthorizationRule{{
							Principals: []string{"alice"},
							Claims: []model.GatewayMatchAttribute{{
								Name:   "role",
								Values: []string{"admin"},
							}},
							Headers: []model.GatewayMatchAttribute{{
								Name:   "x-tenant",
								Values: []string{"team-a"},
							}},
							Methods: []string{"GET", "POST"},
							Paths:   []string{"/admin/*"},
							Hosts:   []string{"api.example.com"},
							CIDRs:   []string{"192.0.2.0/24"},
						}},
					},
				}},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{GatewayAuthPolicy: "default/jwt-authz"})
		require.Contains(t, cfg, GatewayAuthorizationFilterName)

		perRoute := &rbacv3.RBACPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[GatewayAuthorizationFilterName].Value, perRoute))
		require.NotNil(t, perRoute.GetRbac())
		require.Equal(t, envoy_config_rbac_v3.RBAC_ALLOW, perRoute.GetRbac().GetRules().GetAction())
		require.Len(t, perRoute.GetRbac().GetRules().GetPolicies(), 1)

		policy := perRoute.GetRbac().GetRules().GetPolicies()["rule-0"]
		require.NotNil(t, policy)
		require.Len(t, policy.GetPermissions(), 1)
		require.Len(t, policy.GetPrincipals(), 1)
		require.NotNil(t, policy.GetPermissions()[0].GetAndRules())
		require.NotNil(t, policy.GetPrincipals()[0].GetAndIds())

		claimPrincipal := policy.GetPrincipals()[0].GetAndIds().GetIds()[1]
		require.Equal(t, JWTAuthFilterName, claimPrincipal.GetMetadata().GetFilter())
		require.Equal(t, "default/jwt-authz", claimPrincipal.GetMetadata().GetPath()[0].GetKey())
		require.Equal(t, "role", claimPrincipal.GetMetadata().GetPath()[1].GetKey())
		require.Equal(t, "admin", claimPrincipal.GetMetadata().GetValue().GetStringMatch().GetExact())

		cidrPrincipal := policy.GetPrincipals()[0].GetAndIds().GetIds()[2]
		require.Equal(t, "192.0.2.0", cidrPrincipal.GetRemoteIp().GetAddressPrefix())
		require.Equal(t, uint32(24), cidrPrincipal.GetRemoteIp().GetPrefixLen().GetValue())
	})

	t.Run("route without gateway authorization keeps rbac disabled", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{}, {GatewayAuthPolicy: "default/authz"}}}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "authz", Namespace: "default"},
					Authorization: &model.GatewayAuthorization{
						Rules: []model.GatewayAuthorizationRule{{Methods: []string{"GET"}}},
					},
				}},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{})
		require.Contains(t, cfg, GatewayAuthorizationFilterName)

		perRoute := &rbacv3.RBACPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[GatewayAuthorizationFilterName].Value, perRoute))
		require.Nil(t, perRoute.GetRbac())
	})

	t.Run("route with unresolved basic auth fails closed via rbac", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{GatewayAuthPolicy: "default/basic"}}}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "basic", Namespace: "default"},
					BasicAuth: &model.GatewayBasicAuth{
						Secret: model.GatewayAuthSecretRef{Name: "basic", Key: "auth", Found: false},
					},
				}},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{GatewayAuthPolicy: "default/basic"})
		require.Contains(t, cfg, GatewayAuthorizationFilterName)

		perRoute := &rbacv3.RBACPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[GatewayAuthorizationFilterName].Value, perRoute))
		require.NotNil(t, perRoute.GetRbac())
		require.Empty(t, perRoute.GetRbac().GetRules().GetPolicies())
	})

	t.Run("route with malformed jwt provider fails closed via rbac", func(t *testing.T) {
		m := &model.Model{
			HTTP: []model.HTTPListener{{Routes: []model.HTTPRoute{{GatewayAuthPolicy: "default/jwt"}}}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "jwt", Namespace: "default"},
					JWT: &model.GatewayJWTAuth{
						Issuer:        "https://issuer.example.com",
						RemoteJWKSURI: "ftp://issuer.example.com/jwks",
					},
				}},
			},
		}

		cfg := getTypedPerFilterConfig(m, nil, nil, model.HTTPRoute{GatewayAuthPolicy: "default/jwt"})
		require.Contains(t, cfg, GatewayAuthorizationFilterName)

		perRoute := &rbacv3.RBACPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[GatewayAuthorizationFilterName].Value, perRoute))
		require.NotNil(t, perRoute.GetRbac())
		require.Empty(t, perRoute.GetRbac().GetRules().GetPolicies())
	})

	t.Run("external auth route remains enabled when gateway auth policy exists elsewhere", func(t *testing.T) {
		authFilters := []*model.HTTPExternalAuthFilter{
			{Backend: model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}, Protocol: model.ExternalAuthProtocolGRPC},
			{Backend: model.Backend{Name: "svc-b", Namespace: "ns", Port: &model.BackendPort{Port: 8080}}, Protocol: model.ExternalAuthProtocolHTTP},
		}
		m := &model.Model{
			HTTP: []model.HTTPListener{{
				Routes: []model.HTTPRoute{
					{
						ExternalAuth: authFilters[0],
					},
					{
						GatewayAuthPolicy: "default/authz",
					},
				},
			}},
			GatewayAuth: &model.GatewayAuthModel{
				Policies: []model.GatewayAuthPolicy{{
					Source: model.FullyQualifiedResource{Name: "authz", Namespace: "default"},
					Authorization: &model.GatewayAuthorization{
						Rules: []model.GatewayAuthorizationRule{{Methods: []string{"GET"}}},
					},
				}},
			},
		}

		cfg := getTypedPerFilterConfig(m, authFilters[0], authFilters, model.HTTPRoute{ExternalAuth: authFilters[0]})
		require.Contains(t, cfg, ExtAuthzFilterName(extAuthzFilterKey(authFilters[1])))
		require.NotContains(t, cfg, ExtAuthzFilterName(extAuthzFilterKey(authFilters[0])))

		perRoute := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[ExtAuthzFilterName(extAuthzFilterKey(authFilters[1]))].Value, perRoute))
		require.True(t, perRoute.GetDisabled())

		rbacPerRoute := &rbacv3.RBACPerRoute{}
		require.NoError(t, proto.Unmarshal(cfg[GatewayAuthorizationFilterName].Value, rbacPerRoute))
		require.Nil(t, rbacPerRoute.GetRbac())
	})
}

func Test_extAuthzFilterKey_sameBackendDifferentConfig(t *testing.T) {
	backend := model.Backend{Name: "authz", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}

	base := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP}
	withPrefix := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, PathPrefix: "/check"}
	withBody := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, ForwardBody: &model.ForwardBodyConfig{MaxSize: 1024}}
	withReqHeaders := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"X-Tenant"}}
	withRespHeaders := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedResponseHeaders: []string{"X-Authz-Status"}}

	keys := []string{
		extAuthzFilterKey(base),
		extAuthzFilterKey(withPrefix),
		extAuthzFilterKey(withBody),
		extAuthzFilterKey(withReqHeaders),
		extAuthzFilterKey(withRespHeaders),
	}
	// All five configs are distinct — each must produce a unique key.
	seen := map[string]struct{}{}
	for _, k := range keys {
		require.NotContains(t, seen, k, "duplicate key: %s", k)
		seen[k] = struct{}{}
	}

	// Identical configs must produce the same key (idempotency).
	require.Equal(t, extAuthzFilterKey(base), extAuthzFilterKey(&model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP}))
	// Header order must not affect the key.
	headersAB := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"A", "B"}}
	headersBA := &model.HTTPExternalAuthFilter{Backend: backend, Protocol: model.ExternalAuthProtocolHTTP, AllowedRequestHeaders: []string{"B", "A"}}
	require.Equal(t, extAuthzFilterKey(headersAB), extAuthzFilterKey(headersBA))
}

func Test_desiredHTTPConnectionManagerWithoutGRPCWebTranslation(t *testing.T) {
	i := &cecTranslator{}
	m := &model.Model{
		HTTPOptions: &model.HTTPOptions{
			GRPCWebTranslation: &model.GRPCWebTranslationConfig{
				Enabled: false,
			},
		},
	}
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", m)
	require.NoError(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)
	require.NoError(t, err)

	require.Len(t, httpConnectionManager.GetHttpFilters(), 2)
	require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[1].Name)
}
