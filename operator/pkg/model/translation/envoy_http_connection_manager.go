// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	mutation_rules_v3 "github.com/envoyproxy/go-control-plane/envoy/config/common/mutation_rules/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	basicauthv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/basic_auth/v3"
	httpCorsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/cors/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	grpcStatsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_stats/v3"
	grpcWebv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	jwtauthnv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/jwt_authn/v3"
	luav3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/lua/v3"
	oauth2v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/oauth2/v3"
	httpRouterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_config_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	gatewayhelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	// ExtAuthzFilterNamePrefix is the prefix for ext_authz filter instance names.
	// Full name: "<prefix>/<clusterName>". Used as the TypedPerFilterConfig key on routes.
	ExtAuthzFilterNamePrefix = "envoy.filters.http.ext_authz"
	// BasicAuthFilterNamePrefix is the prefix for native basic_auth filter
	// instances keyed by shared top-level configuration.
	BasicAuthFilterNamePrefix = "envoy.filters.http.basic_auth"
	// APIKeyAuthFilterName is the dedicated filter instance used for Gateway API
	// key authentication policies.
	APIKeyAuthFilterName = "envoy.filters.http.lua.cilium.gateway_api_key_auth"
	// JWTAuthFilterName is the dedicated filter instance used for Gateway JWT
	// authentication policies.
	JWTAuthFilterName = "envoy.filters.http.jwt_authn"
	// OIDCFilterNamePrefix is the prefix for OAuth2 filter instances used for
	// Gateway OIDC authentication policies.
	OIDCFilterNamePrefix = "envoy.filters.http.oauth2"
)

const apiKeyAuthLuaScript = `
local function url_decode(value)
  if value == nil then
    return nil
  end
  value = string.gsub(value, "+", " ")
  value = string.gsub(value, "%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
  return value
end

local function extract_query_value(path, name)
  if path == nil then
    return nil
  end
  local question = string.find(path, "?", 1, true)
  if question == nil then
    return nil
  end
  local query = string.sub(path, question + 1)
  for pair in string.gmatch(query, "([^&]+)") do
    local equals = string.find(pair, "=", 1, true)
    local key = pair
    local value = ""
    if equals ~= nil then
      key = string.sub(pair, 1, equals - 1)
      value = string.sub(pair, equals + 1)
    end
    if url_decode(key) == name then
      return url_decode(value)
    end
  end
  return nil
end

local function strip_query_value(path, name)
  if path == nil then
    return nil
  end
  local question = string.find(path, "?", 1, true)
  if question == nil then
    return path
  end
  local base = string.sub(path, 1, question - 1)
  local query = string.sub(path, question + 1)
  local kept = {}
  for pair in string.gmatch(query, "([^&]+)") do
    local equals = string.find(pair, "=", 1, true)
    local key = pair
    if equals ~= nil then
      key = string.sub(pair, 1, equals - 1)
    end
    if url_decode(key) ~= name then
      table.insert(kept, pair)
    end
  end
  if #kept == 0 then
    return base
  end
  return base .. "?" .. table.concat(kept, "&")
end

local function extract_cookie_value(cookie_header, name)
  if cookie_header == nil then
    return nil
  end
  for token in string.gmatch(cookie_header .. ";", "%s*([^;]+)%s*;") do
    local equals = string.find(token, "=", 1, true)
    if equals ~= nil then
      local key = string.sub(token, 1, equals - 1)
      local value = string.sub(token, equals + 1)
      if key == name then
        return value
      end
    end
  end
  return nil
end

local function strip_cookie_value(cookie_header, name)
  if cookie_header == nil then
    return nil
  end
  local kept = {}
  for token in string.gmatch(cookie_header .. ";", "%s*([^;]+)%s*;") do
    local equals = string.find(token, "=", 1, true)
    if equals ~= nil then
      local key = string.sub(token, 1, equals - 1)
      if key ~= name then
        table.insert(kept, token)
      end
    elseif token ~= "" then
      table.insert(kept, token)
    end
  end
  if #kept == 0 then
    return nil
  end
  return table.concat(kept, "; ")
end

function envoy_on_request(request_handle)
  local config = request_handle:filterContext()
  if config == nil then
    return
  end

  local headers = request_handle:headers()
  local matched_value = nil
  local matched_identity = nil
  local matched_source_type = nil
  local matched_source_name = nil
  local credentials = config["credentials"] or {}
  local sources = config["sources"] or {}

  for _, source in ipairs(sources) do
    local source_type = source["type"]
    local source_name = source["name"]
    local candidate = nil

    if source_type == "Header" then
      candidate = headers:get(source_name)
    elseif source_type == "Query" then
      candidate = extract_query_value(headers:get(":path"), source_name)
    elseif source_type == "Cookie" then
      candidate = extract_cookie_value(headers:get("cookie"), source_name)
    end

    if candidate ~= nil then
      local identity = credentials[candidate]
      if identity ~= nil then
        matched_value = candidate
        matched_identity = identity
        matched_source_type = source_type
        matched_source_name = source_name
        break
      end
    end
  end

  if matched_value == nil then
    request_handle:respond({[":status"] = "401"}, "Unauthorized")
    return
  end

  local identity_header = config["identity_header"]
  if identity_header ~= nil and identity_header ~= "" and matched_identity ~= nil and matched_identity ~= "" then
    headers:replace(identity_header, matched_identity)
  end

  if config["strip_credential"] == true then
    if matched_source_type == "Header" then
      headers:remove(matched_source_name)
    elseif matched_source_type == "Query" then
      headers:replace(":path", strip_query_value(headers:get(":path"), matched_source_name))
    elseif matched_source_type == "Cookie" then
      local updated = strip_cookie_value(headers:get("cookie"), matched_source_name)
      if updated == nil or updated == "" then
        headers:remove("cookie")
      else
        headers:replace("cookie", updated)
      end
    end
  end
end
`

// ExtAuthzFilterName returns the HCM filter instance name for a given ext_authz cluster.
func ExtAuthzFilterName(clusterName string) string {
	return fmt.Sprintf("%s/%s", ExtAuthzFilterNamePrefix, clusterName)
}

func basicAuthFilterName(key string) string {
	return fmt.Sprintf("%s/%s", BasicAuthFilterNamePrefix, key)
}

func basicAuthFilterKey(auth *model.GatewayBasicAuth) string {
	if auth == nil || auth.UsernameHeader == "" {
		return "default"
	}
	return "username-header:" + auth.UsernameHeader
}

// extAuthzFilterKey returns the unique key for an ext_authz filter instance.
// The key encodes all filter-level config fields so that two routes pointing to
// the same backend but with different configs produce distinct HCM filter instances
// rather than collapsing non-deterministically to one shared instance.
func extAuthzFilterKey(af *model.HTTPExternalAuthFilter) string {
	clusterName := getClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	parts := []string{string(af.Protocol), clusterName}

	if af.PathPrefix != "" {
		parts = append(parts, "pp:"+af.PathPrefix)
	}
	if af.ForwardBody != nil && af.ForwardBody.MaxSize > 0 {
		parts = append(parts, "fb:"+strconv.FormatUint(uint64(af.ForwardBody.MaxSize), 10))
	}
	if len(af.AllowedRequestHeaders) > 0 {
		sorted := append([]string(nil), af.AllowedRequestHeaders...)
		sort.Strings(sorted)
		parts = append(parts, "arh:"+strings.Join(sorted, ","))
	}
	if len(af.AllowedResponseHeaders) > 0 {
		sorted := append([]string(nil), af.AllowedResponseHeaders...)
		sort.Strings(sorted)
		parts = append(parts, "esh:"+strings.Join(sorted, ","))
	}

	return strings.Join(parts, ":")
}

type HttpConnectionManagerMutator func(*httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager

func WithInternalAddressConfig(enableIpv4, enableIpv6 bool) HttpConnectionManagerMutator {
	return func(hcm *httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager {
		hcm.InternalAddressConfig = &httpConnectionManagerv3.HttpConnectionManager_InternalAddressConfig{
			UnixSockets: false,
			CidrRanges:  envoy.GetInternalListenerCIDRs(enableIpv4, enableIpv6),
		}
		return hcm
	}
}

// httpConnectionManagerMutators returns a list of mutator functions for customizing the HTTP connection manager.
func (i *cecTranslator) httpConnectionManagerMutators() []HttpConnectionManagerMutator {
	return []HttpConnectionManagerMutator{
		WithInternalAddressConfig(i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled),
	}
}

func (i *cecTranslator) getHTTPConnectionManagerHttpFilters(m *model.Model) []*httpConnectionManagerv3.HttpFilter {
	hf := []*httpConnectionManagerv3.HttpFilter{}
	if m.GRPCWebTranslationEnabled() {
		hf = append(hf, &httpConnectionManagerv3.HttpFilter{
			Name: "envoy.filters.http.grpc_web",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&grpcWebv3.GrpcWeb{}),
			},
		})
	}

	hf = append(hf, &httpConnectionManagerv3.HttpFilter{
		Name: "envoy.filters.http.grpc_stats",
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&grpcStatsv3.FilterConfig{
				EmitFilterState:     true,
				EnableUpstreamStats: true,
			}),
		},
	})

	// Gateway auth filter ordering is fixed and conservative:
	// route mutation -> authentication -> authorization/RBAC -> terminal router.
	// Provider-specific native auth stages are introduced incrementally in later
	// tasks, but the stage boundaries and ordering are defined here so new auth
	// filters cannot accidentally drift relative to existing ExternalAuth.
	hf = append(hf, i.getHTTPRouteMutationFilters(m)...)
	hf = append(hf, i.getHTTPAuthenticationFilters(m)...)
	hf = append(hf, i.getHTTPAuthorizationFilters(m)...)
	hf = append(hf, i.getHTTPTerminalFilters(m)...)

	return hf
}

func (i *cecTranslator) getHTTPRouteMutationFilters(_ *model.Model) []*httpConnectionManagerv3.HttpFilter {
	// Native route-mutation auth filters are introduced in later tasks. Keep the
	// stage explicit so future mutating filters remain ahead of authn/authz.
	return nil
}

func (i *cecTranslator) getHTTPAuthenticationFilters(m *model.Model) []*httpConnectionManagerv3.HttpFilter {
	hf := make([]*httpConnectionManagerv3.HttpFilter, 0)
	for _, auth := range i.getUniqueGatewayBasicAuthFilters(m) {
		hf = append(hf, buildBasicAuthHTTPFilter(auth))
	}
	if hasGatewayAPIKeyAuth(m) {
		hf = append(hf, buildAPIKeyAuthHTTPFilter())
	}
	for _, policy := range getGatewayOIDCPolicies(m) {
		if filter := i.buildOIDCHTTPFilter(policy); filter != nil {
			hf = append(hf, filter)
		}
	}
	if hasGatewayJWTAuth(m) {
		hf = append(hf, buildJWTAuthHTTPFilter(m))
	}
	return hf
}

func (i *cecTranslator) getHTTPAuthorizationFilters(m *model.Model) []*httpConnectionManagerv3.HttpFilter {
	hf := make([]*httpConnectionManagerv3.HttpFilter, 0)
	if hasGatewayAuthorization(m) {
		hf = append(hf, &httpConnectionManagerv3.HttpFilter{
			Name: GatewayAuthorizationFilterName,
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(buildGatewayAuthorizationHTTPFilter()),
			},
		})
	}
	for _, af := range i.getUniqueAuthFilters(m) {
		hf = append(hf, buildExtAuthzHTTPFilter(af))
	}
	return hf
}

func (i *cecTranslator) getHTTPTerminalFilters(m *model.Model) []*httpConnectionManagerv3.HttpFilter {
	hf := make([]*httpConnectionManagerv3.HttpFilter, 0, 2)

	// HTTP filter order matters. When CORS is enabled,
	// the CORS filter must run before envoy.filters.http.router.
	if m.IsCORSFilterConfigured() {
		hf = append(hf, &httpConnectionManagerv3.HttpFilter{
			Name: "envoy.filters.http.cors",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&httpCorsv3.Cors{}),
			},
		})
	}

	hf = append(hf, &httpConnectionManagerv3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&httpRouterv3.Router{}),
		},
	})

	return hf
}

// desiredHTTPConnectionManager returns a new HTTP connection manager filter with the given name and route.
func (i *cecTranslator) desiredHTTPConnectionManager(name, routeName string, m *model.Model) (ciliumv2.XDSResource, error) {
	connectionManager := &httpConnectionManagerv3.HttpConnectionManager{
		StatPrefix: name,
		AccessLog:  getHTTPAccessLogs(m),
		RouteSpecifier: &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: routeName},
		},
		UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:    false,
		HttpFilters:      i.getHTTPConnectionManagerHttpFilters(m),
		UpgradeConfigs: []*httpConnectionManagerv3.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		},
		CommonHttpProtocolOptions: &envoy_config_core.HttpProtocolOptions{
			MaxStreamDuration: &durationpb.Duration{
				Seconds: 0,
			},
		},
	}

	// Apply mutation functions for customizing the connection manager.
	for _, fn := range i.httpConnectionManagerMutators() {
		connectionManager = fn(connectionManager)
	}

	return toXdsResource(connectionManager, envoy.HttpConnectionManagerTypeURL)
}

// buildExtAuthzHTTPFilter creates one named ext_authz HCM HttpFilter for a deduplicated
// external auth config. These filters are positioned before the terminal router filter so
// that per-route TypedPerFilterConfig can enable or disable each instance.
func buildExtAuthzHTTPFilter(af *model.HTTPExternalAuthFilter) *httpConnectionManagerv3.HttpFilter {
	var clusterName string
	if af.Protocol == model.ExternalAuthProtocolGRPC {
		clusterName = getGRPCExtAuthClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	} else {
		clusterName = getHTTPExtAuthClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	}
	filterName := ExtAuthzFilterName(extAuthzFilterKey(af))

	var config *extauthzv3.ExtAuthz
	if af.Protocol == model.ExternalAuthProtocolGRPC {
		config = &extauthzv3.ExtAuthz{
			Services: &extauthzv3.ExtAuthz_GrpcService{
				GrpcService: &envoy_config_core.GrpcService{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
							ClusterName: clusterName,
							// Authority overrides the :authority pseudo-header sent to the
							// auth server. Without this, Envoy uses the cluster name, which
							// after CEC namespace-qualification contains slashes
							// ("ns/cec/cluster") that are illegal in an HTTP/2 authority
							// and cause strict gRPC clients to reset
							// the connection before the handler runs.
							Authority: fmt.Sprintf("%s:%s", af.Backend.Name, af.Backend.Port.GetPort()),
						},
					},
				},
			},
			DecoderHeaderMutationRules: &mutation_rules_v3.HeaderMutationRules{
				DisallowExpression: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^(:authority|host)$",
				},
			},
		}
		// Per spec: empty/nil means forward all headers. Leave AllowedHeaders unset
		// so Envoy uses its default (forward all). Only restrict when entries are given.
		if len(af.AllowedRequestHeaders) > 0 {
			config.AllowedHeaders = toListStringMatcher(af.AllowedRequestHeaders)
		}
	} else {
		scheme := "http"
		if af.Backend.TLS != nil {
			scheme = "https"
		}
		httpSvc := &extauthzv3.HttpService{
			ServerUri: &envoy_config_core.HttpUri{
				Uri: fmt.Sprintf("%s://%s:%s", scheme, af.Backend.Name, af.Backend.Port.GetPort()),
				HttpUpstreamType: &envoy_config_core.HttpUri_Cluster{
					Cluster: clusterName,
				},
				Timeout: &durationpb.Duration{Seconds: 10},
			},
			PathPrefix: af.PathPrefix,
		}
		httpSvc.AuthorizationResponse = &extauthzv3.AuthorizationResponse{}
		if len(af.AllowedResponseHeaders) > 0 {
			// Explicit list: forward only those headers (replace semantics).
			httpSvc.AuthorizationResponse.AllowedUpstreamHeaders = toListStringMatcher(af.AllowedResponseHeaders)
		} else {
			// Empty list means forward all per Gateway API spec. Use AllowedUpstreamHeaders
			// (replace, not append) so that if the auth service returns a header that already
			// exists on the client request (e.g. Content-Length), the upstream request ends up
			// with exactly one value rather than a duplicate that would corrupt the request.
			httpSvc.AuthorizationResponse.AllowedUpstreamHeaders = allHeadersMatcher()
		}
		config = &extauthzv3.ExtAuthz{
			Services: &extauthzv3.ExtAuthz_HttpService{
				HttpService: httpSvc,
			},
			// Prevent the auth service from overriding routing-critical headers
			// regardless of what AllowedUpstreamHeaders matches.
			DecoderHeaderMutationRules: &mutation_rules_v3.HeaderMutationRules{
				DisallowExpression: &envoy_type_matcher_v3.RegexMatcher{
					Regex: "^(:authority|host)$",
				},
			},
		}
		if len(af.AllowedRequestHeaders) > 0 {
			config.AllowedHeaders = toListStringMatcher(af.AllowedRequestHeaders)
		}
	}

	if af.ForwardBody != nil && af.ForwardBody.MaxSize > 0 {
		config.WithRequestBody = &extauthzv3.BufferSettings{
			MaxRequestBytes:     af.ForwardBody.MaxSize,
			AllowPartialMessage: true,
		}
	}

	return &httpConnectionManagerv3.HttpFilter{
		Name: filterName,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(config),
		},
	}
}

func buildBasicAuthHTTPFilter(auth *model.GatewayBasicAuth) *httpConnectionManagerv3.HttpFilter {
	filter := &basicauthv3.BasicAuth{}
	if auth.UsernameHeader != "" {
		filter.ForwardUsernameHeader = auth.UsernameHeader
	}

	return &httpConnectionManagerv3.HttpFilter{
		Name: basicAuthFilterName(basicAuthFilterKey(auth)),
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(filter),
		},
	}
}

func buildAPIKeyAuthHTTPFilter() *httpConnectionManagerv3.HttpFilter {
	return &httpConnectionManagerv3.HttpFilter{
		Name: APIKeyAuthFilterName,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&luav3.Lua{
				DefaultSourceCode: &envoy_config_core.DataSource{
					Specifier: &envoy_config_core.DataSource_InlineString{
						InlineString: apiKeyAuthLuaScript,
					},
				},
			}),
		},
	}
}

func buildJWTAuthHTTPFilter(m *model.Model) *httpConnectionManagerv3.HttpFilter {
	providers := map[string]*jwtauthnv3.JwtProvider{}
	requirements := map[string]*jwtauthnv3.JwtRequirement{}

	for _, policy := range getGatewayJWTPolicies(m) {
		providerName := jwtRequirementName(policy)
		provider := buildJWTProvider(policy)
		if provider == nil {
			continue
		}
		providers[providerName] = provider
		requirements[providerName] = &jwtauthnv3.JwtRequirement{
			RequiresType: &jwtauthnv3.JwtRequirement_ProviderName{
				ProviderName: providerName,
			},
		}
	}

	return &httpConnectionManagerv3.HttpFilter{
		Name: JWTAuthFilterName,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&jwtauthnv3.JwtAuthentication{
				Providers:            providers,
				RequirementMap:       requirements,
				BypassCorsPreflight:  true,
				StripFailureResponse: true,
			}),
		},
	}
}

func buildJWTProvider(policy model.GatewayAuthPolicy) *jwtauthnv3.JwtProvider {
	if policy.JWT == nil {
		return nil
	}

	provider := &jwtauthnv3.JwtProvider{
		Issuer:            policy.JWT.Issuer,
		Audiences:         append([]string(nil), policy.JWT.Audiences...),
		PayloadInMetadata: jwtRequirementName(policy),
		ClearRouteCache:   true,
	}

	for _, claim := range policy.JWT.ClaimToHeaders {
		provider.ClaimToHeaders = append(provider.ClaimToHeaders, &jwtauthnv3.JwtClaimToHeader{
			HeaderName: claim.Header,
			ClaimName:  claim.Claim,
		})
	}

	switch {
	case policy.JWT.LocalJWKS != nil:
		inlineJWKS := getLocalJWKSValue(policy.JWT.LocalJWKS)
		if inlineJWKS == "" {
			return nil
		}
		provider.JwksSourceSpecifier = &jwtauthnv3.JwtProvider_LocalJwks{
			LocalJwks: &envoy_config_core.DataSource{
				Specifier: &envoy_config_core.DataSource_InlineString{
					InlineString: inlineJWKS,
				},
			},
		}
	case policy.JWT.RemoteJWKSURI != "":
		clusterName, err := getRemoteJWKSClusterName(policy.JWT.RemoteJWKSURI)
		if err != nil {
			return nil
		}
		provider.JwksSourceSpecifier = &jwtauthnv3.JwtProvider_RemoteJwks{
			RemoteJwks: &jwtauthnv3.RemoteJwks{
				HttpUri: &envoy_config_core.HttpUri{
					Uri: policy.JWT.RemoteJWKSURI,
					HttpUpstreamType: &envoy_config_core.HttpUri_Cluster{
						Cluster: clusterName,
					},
					Timeout: &durationpb.Duration{Seconds: 10},
				},
				CacheDuration: &durationpb.Duration{Seconds: 600},
			},
		}
	default:
		return nil
	}

	return provider
}

func oidcFilterName(policy model.GatewayAuthPolicy) string {
	return fmt.Sprintf("%s/%s/%s", OIDCFilterNamePrefix, policy.Source.Namespace, policy.Source.Name)
}

func oidcCallbackPath(policy model.GatewayAuthPolicy) string {
	return fmt.Sprintf("/cilium-gateway-auth/oidc/%s/%s/callback", policy.Source.Namespace, policy.Source.Name)
}

func oidcLogoutPath(policy model.GatewayAuthPolicy) string {
	return fmt.Sprintf("/cilium-gateway-auth/oidc/%s/%s/logout", policy.Source.Namespace, policy.Source.Name)
}

func (i *cecTranslator) buildOIDCHTTPFilter(policy model.GatewayAuthPolicy) *httpConnectionManagerv3.HttpFilter {
	if policy.OIDC == nil || policy.OIDC.Endpoints == nil || policy.OIDC.Endpoints.Authorization == "" || policy.OIDC.Endpoints.Token == "" {
		return nil
	}

	tokenClusterName, err := getOIDCTokenClusterName(policy.OIDC.Endpoints.Token)
	if err != nil {
		return nil
	}

	config := &oauth2v3.OAuth2{
		Config: &oauth2v3.OAuth2Config{
			TokenEndpoint: &envoy_config_core.HttpUri{
				Uri: policy.OIDC.Endpoints.Token,
				HttpUpstreamType: &envoy_config_core.HttpUri_Cluster{
					Cluster: tokenClusterName,
				},
				Timeout: &durationpb.Duration{Seconds: 10},
			},
			AuthorizationEndpoint: policy.OIDC.Endpoints.Authorization,
			EndSessionEndpoint:    policy.OIDC.Endpoints.EndSession,
			Credentials: &oauth2v3.OAuth2Credentials{
				ClientId: policy.OIDC.ClientID,
				TokenSecret: &envoy_config_tls_v3.SdsSecretConfig{
					Name: gatewayAuthSDSSecretName(i.Config.SecretsNamespace, policy.Source.Namespace, policy.OIDC.ClientSecret.Name, policy.OIDC.ClientSecret.Key),
				},
				TokenFormation: &oauth2v3.OAuth2Credentials_HmacSecret{
					HmacSecret: &envoy_config_tls_v3.SdsSecretConfig{
						Name: gatewayAuthSDSSecretName(i.Config.SecretsNamespace, policy.Source.Namespace, policy.OIDC.CookieSecret.Name, policy.OIDC.CookieSecret.Key),
					},
				},
			},
			RedirectUri:         "%REQ(:scheme)%://%REQ(:authority)%" + oidcCallbackPath(policy),
			RedirectPathMatcher: exactPathMatcher(oidcCallbackPath(policy)),
			SignoutPath:         exactPathMatcher(oidcLogoutPath(policy)),
			AuthScopes:          append([]string(nil), policy.OIDC.Scopes...),
			ForwardBearerToken:  true,
			StatPrefix:          fmt.Sprintf("%s.%s", policy.Source.Namespace, policy.Source.Name),
		},
	}

	return &httpConnectionManagerv3.HttpFilter{
		Name: oidcFilterName(policy),
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(config),
		},
	}
}

func (i *cecTranslator) getUniqueGatewayBasicAuthFilters(m *model.Model) []*model.GatewayBasicAuth {
	return getUniqueGatewayBasicAuthFilters(m)
}

func getUniqueGatewayBasicAuthFilters(m *model.Model) []*model.GatewayBasicAuth {
	if m == nil {
		return nil
	}
	seen := map[string]struct{}{}
	var result []*model.GatewayBasicAuth
	for _, listener := range m.HTTP {
		for _, route := range listener.Routes {
			policy := getGatewayAuthPolicyForRoute(m, route)
			if policy == nil || policy.BasicAuth == nil {
				continue
			}
			key := basicAuthFilterKey(policy.BasicAuth)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, policy.BasicAuth)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return basicAuthFilterKey(result[i]) < basicAuthFilterKey(result[j])
	})
	return result
}

func hasGatewayAPIKeyAuth(m *model.Model) bool {
	if m == nil {
		return false
	}
	for _, listener := range m.HTTP {
		for _, route := range listener.Routes {
			policy := getGatewayAuthPolicyForRoute(m, route)
			if policy != nil && policy.APIKeyAuth != nil {
				return true
			}
		}
	}
	return false
}

func hasGatewayJWTAuth(m *model.Model) bool {
	for _, policy := range getGatewayJWTPolicies(m) {
		if buildJWTProvider(policy) != nil {
			return true
		}
	}
	return false
}

func getGatewayOIDCPolicies(m *model.Model) []model.GatewayAuthPolicy {
	if m == nil || m.GatewayAuth == nil {
		return nil
	}

	policies := make([]model.GatewayAuthPolicy, 0, len(m.GatewayAuth.Policies))
	for _, policy := range m.GatewayAuth.Policies {
		if policy.OIDC != nil {
			policies = append(policies, policy)
		}
	}
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Source.Namespace != policies[j].Source.Namespace {
			return policies[i].Source.Namespace < policies[j].Source.Namespace
		}
		return policies[i].Source.Name < policies[j].Source.Name
	})
	return policies
}

func getGatewayJWTPolicies(m *model.Model) []model.GatewayAuthPolicy {
	if m == nil || m.GatewayAuth == nil {
		return nil
	}

	policies := make([]model.GatewayAuthPolicy, 0, len(m.GatewayAuth.Policies))
	for _, policy := range m.GatewayAuth.Policies {
		if policy.JWT != nil {
			policies = append(policies, policy)
		}
	}

	return policies
}

func getLocalJWKSValue(local *model.GatewayLocalJWKS) string {
	if local == nil {
		return ""
	}
	if local.Secret != nil && local.Secret.Found && len(local.Secret.Value) != 0 {
		return string(local.Secret.Value)
	}
	if local.ConfigMap != nil && local.ConfigMap.Found && len(local.ConfigMap.Value) != 0 {
		return string(local.ConfigMap.Value)
	}
	return ""
}

func jwtRequirementName(policy model.GatewayAuthPolicy) string {
	return fmt.Sprintf("%s/%s", policy.Source.Namespace, policy.Source.Name)
}

func getRemoteJWKSClusterName(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("jwks uri missing host")
	}

	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", fmt.Errorf("unsupported jwks uri scheme %q", parsed.Scheme)
		}
	}

	return fmt.Sprintf("jwt:%s:%s:%s", strings.ToLower(parsed.Scheme), host, port), nil
}

func getOIDCTokenClusterName(uri string) (string, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	host := parsed.Hostname()
	if host == "" {
		return "", fmt.Errorf("oidc token uri missing host")
	}

	port := parsed.Port()
	if port == "" {
		switch strings.ToLower(parsed.Scheme) {
		case "https":
			port = "443"
		case "http":
			port = "80"
		default:
			return "", fmt.Errorf("unsupported oidc token uri scheme %q", parsed.Scheme)
		}
	}

	return fmt.Sprintf("oidc:%s:%s:%s", strings.ToLower(parsed.Scheme), host, port), nil
}

func gatewayAuthSDSSecretName(secretsNamespace, namespace, name, key string) string {
	return fmt.Sprintf("%s/%s", secretsNamespace, gatewayhelpers.SyncedSecretKeyName(namespace, name, key))
}

func exactPathMatcher(path string) *envoy_type_matcher_v3.PathMatcher {
	return &envoy_type_matcher_v3.PathMatcher{
		Rule: &envoy_type_matcher_v3.PathMatcher_Path{
			Path: &envoy_type_matcher_v3.StringMatcher{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
					Exact: path,
				},
			},
		},
	}
}

func getGatewayAuthPolicyForRoute(m *model.Model, route model.HTTPRoute) *model.GatewayAuthPolicy {
	if m == nil || m.GatewayAuth == nil || route.GatewayAuthPolicy == "" {
		return nil
	}
	for i := range m.GatewayAuth.Policies {
		if typespacedName := fmt.Sprintf("%s/%s", m.GatewayAuth.Policies[i].Source.Namespace, m.GatewayAuth.Policies[i].Source.Name); typespacedName == route.GatewayAuthPolicy {
			return &m.GatewayAuth.Policies[i]
		}
	}
	return nil
}

// allHeadersMatcher returns a ListStringMatcher that matches every header name.
func allHeadersMatcher() *envoy_type_matcher_v3.ListStringMatcher {
	return &envoy_type_matcher_v3.ListStringMatcher{
		Patterns: []*envoy_type_matcher_v3.StringMatcher{
			{
				MatchPattern: &envoy_type_matcher_v3.StringMatcher_SafeRegex{
					SafeRegex: &envoy_type_matcher_v3.RegexMatcher{Regex: ".*"},
				},
			},
		},
	}
}

// toListStringMatcher converts a list of exact header names into an Envoy ListStringMatcher.
func toListStringMatcher(headers []string) *envoy_type_matcher_v3.ListStringMatcher {
	if headers == nil {
		return nil
	}
	patterns := make([]*envoy_type_matcher_v3.StringMatcher, 0, len(headers))
	for _, h := range headers {
		patterns = append(patterns, &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: h,
			},
			IgnoreCase: true,
		})
	}
	return &envoy_type_matcher_v3.ListStringMatcher{Patterns: patterns}
}
