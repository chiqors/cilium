// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	envoy_config_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_rbac_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/operator/pkg/model"
)

const GatewayAuthorizationFilterName = "envoy.filters.http.rbac"

func buildGatewayAuthorizationHTTPFilter() *envoy_extensions_filters_http_rbac_v3.RBAC {
	return &envoy_extensions_filters_http_rbac_v3.RBAC{}
}

func buildGatewayFailClosedPerRoute(policy *model.GatewayAuthPolicy) *envoy_extensions_filters_http_rbac_v3.RBACPerRoute {
	if policy == nil {
		return nil
	}

	return &envoy_extensions_filters_http_rbac_v3.RBACPerRoute{
		Rbac: &envoy_extensions_filters_http_rbac_v3.RBAC{
			Rules: &envoy_config_rbac_v3.RBAC{
				Action:   envoy_config_rbac_v3.RBAC_ALLOW,
				Policies: map[string]*envoy_config_rbac_v3.Policy{},
			},
			RulesStatPrefix: policy.Source.Namespace + "." + policy.Source.Name + ".fail_closed",
		},
	}
}

func hasGatewayAuthorization(m *model.Model) bool {
	if m == nil {
		return false
	}
	for _, listener := range m.HTTP {
		for _, route := range listener.Routes {
			policy := getGatewayAuthPolicyForRoute(m, route)
			if policy != nil && (policy.Authorization != nil || gatewayAuthPolicyRequiresFailClosed(policy)) {
				return true
			}
		}
	}
	return false
}

func gatewayAuthPolicyRequiresFailClosed(policy *model.GatewayAuthPolicy) bool {
	if policy == nil {
		return false
	}

	if policy.BasicAuth != nil && (!policy.BasicAuth.Secret.Found || len(policy.BasicAuth.Secret.Value) == 0) {
		return true
	}
	if policy.APIKeyAuth != nil {
		for _, credential := range policy.APIKeyAuth.Credentials {
			if !credential.Secret.Found {
				return true
			}
		}
	}
	if policy.JWT != nil && buildJWTProvider(*policy) == nil {
		return true
	}
	if policy.OIDC != nil && !gatewayOIDCPolicyTranslatable(policy) {
		return true
	}

	return false
}

func gatewayOIDCPolicyTranslatable(policy *model.GatewayAuthPolicy) bool {
	if policy == nil || policy.OIDC == nil {
		return false
	}
	if !policy.OIDC.ClientSecret.Found || len(policy.OIDC.ClientSecret.Value) == 0 {
		return false
	}
	if !policy.OIDC.CookieSecret.Found || len(policy.OIDC.CookieSecret.Value) == 0 {
		return false
	}
	if policy.OIDC.Endpoints == nil || policy.OIDC.Endpoints.Authorization == "" || policy.OIDC.Endpoints.Token == "" {
		return false
	}
	_, err := getOIDCTokenClusterName(policy.OIDC.Endpoints.Token)
	return err == nil
}

func buildGatewayAuthorizationPerRoute(policy *model.GatewayAuthPolicy) *envoy_extensions_filters_http_rbac_v3.RBACPerRoute {
	if policy == nil || policy.Authorization == nil {
		return nil
	}

	policies := make(map[string]*envoy_config_rbac_v3.Policy, len(policy.Authorization.Rules))
	for idx, rule := range policy.Authorization.Rules {
		policies[authorizationPolicyName(idx)] = buildGatewayAuthorizationPolicy(policy, rule)
	}

	return &envoy_extensions_filters_http_rbac_v3.RBACPerRoute{
		Rbac: &envoy_extensions_filters_http_rbac_v3.RBAC{
			Rules: &envoy_config_rbac_v3.RBAC{
				Action:   envoy_config_rbac_v3.RBAC_ALLOW,
				Policies: policies,
			},
			RulesStatPrefix: policy.Source.Namespace + "." + policy.Source.Name,
		},
	}
}

func authorizationPolicyName(idx int) string {
	return "rule-" + strconvItoa(idx)
}

func buildGatewayAuthorizationPolicy(policy *model.GatewayAuthPolicy, rule model.GatewayAuthorizationRule) *envoy_config_rbac_v3.Policy {
	return &envoy_config_rbac_v3.Policy{
		Permissions: []*envoy_config_rbac_v3.Permission{buildGatewayAuthorizationPermission(rule)},
		Principals:  []*envoy_config_rbac_v3.Principal{buildGatewayAuthorizationPrincipal(policy, rule)},
	}
}

func buildGatewayAuthorizationPermission(rule model.GatewayAuthorizationRule) *envoy_config_rbac_v3.Permission {
	var rules []*envoy_config_rbac_v3.Permission

	if permission := buildHeaderORPermission(":method", rule.Methods); permission != nil {
		rules = append(rules, permission)
	}
	if permission := buildPathORPermission(rule.Paths); permission != nil {
		rules = append(rules, permission)
	}
	if permission := buildHeaderORPermission(":authority", rule.Hosts); permission != nil {
		rules = append(rules, permission)
	}
	if permission := buildNamedAttributePermissions(rule.Headers); permission != nil {
		rules = append(rules, permission...)
	}

	return combinePermissionsWithAND(rules)
}

func buildGatewayAuthorizationPrincipal(policy *model.GatewayAuthPolicy, rule model.GatewayAuthorizationRule) *envoy_config_rbac_v3.Principal {
	var ids []*envoy_config_rbac_v3.Principal

	if principal := buildJWTPrincipalORMatcher(policy, "sub", rule.Principals); principal != nil {
		ids = append(ids, principal)
	}
	if principals := buildJWTClaimPrincipals(policy, rule.Claims); principals != nil {
		ids = append(ids, principals...)
	}
	if principal := buildCIDRORPrincipal(rule.CIDRs); principal != nil {
		ids = append(ids, principal)
	}

	return combinePrincipalsWithAND(ids)
}

func combinePermissionsWithAND(rules []*envoy_config_rbac_v3.Permission) *envoy_config_rbac_v3.Permission {
	switch len(rules) {
	case 0:
		return &envoy_config_rbac_v3.Permission{
			Rule: &envoy_config_rbac_v3.Permission_Any{Any: true},
		}
	case 1:
		return rules[0]
	default:
		return &envoy_config_rbac_v3.Permission{
			Rule: &envoy_config_rbac_v3.Permission_AndRules{
				AndRules: &envoy_config_rbac_v3.Permission_Set{
					Rules: rules,
				},
			},
		}
	}
}

func combinePrincipalsWithAND(ids []*envoy_config_rbac_v3.Principal) *envoy_config_rbac_v3.Principal {
	switch len(ids) {
	case 0:
		return &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_Any{Any: true},
		}
	case 1:
		return ids[0]
	default:
		return &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_AndIds{
				AndIds: &envoy_config_rbac_v3.Principal_Set{
					Ids: ids,
				},
			},
		}
	}
}

func buildHeaderORPermission(name string, values []string) *envoy_config_rbac_v3.Permission {
	matchers := make([]*envoy_config_rbac_v3.Permission, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		matchers = append(matchers, &envoy_config_rbac_v3.Permission{
			Rule: &envoy_config_rbac_v3.Permission_Header{
				Header: &envoy_config_route_v3.HeaderMatcher{
					Name:                 name,
					HeaderMatchSpecifier: &envoy_config_route_v3.HeaderMatcher_StringMatch{StringMatch: stringMatcherForAuthorizationValue(value, name == ":authority")},
				},
			},
		})
	}
	return combinePermissionOR(matchers)
}

func buildPathORPermission(paths []string) *envoy_config_rbac_v3.Permission {
	matchers := make([]*envoy_config_rbac_v3.Permission, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		matchers = append(matchers, &envoy_config_rbac_v3.Permission{
			Rule: &envoy_config_rbac_v3.Permission_UrlPath{
				UrlPath: &envoy_type_matcher_v3.PathMatcher{
					Rule: &envoy_type_matcher_v3.PathMatcher_Path{
						Path: stringMatcherForAuthorizationValue(path, false),
					},
				},
			},
		})
	}
	return combinePermissionOR(matchers)
}

func buildNamedAttributePermissions(attrs []model.GatewayMatchAttribute) []*envoy_config_rbac_v3.Permission {
	if len(attrs) == 0 {
		return nil
	}
	result := make([]*envoy_config_rbac_v3.Permission, 0, len(attrs))
	for _, attr := range attrs {
		if attr.Name == "" {
			continue
		}
		if permission := buildHeaderORPermission(attr.Name, attr.Values); permission != nil {
			result = append(result, permission)
		}
	}
	return result
}

func buildJWTPrincipalORMatcher(policy *model.GatewayAuthPolicy, claim string, values []string) *envoy_config_rbac_v3.Principal {
	if policy == nil || policy.JWT == nil {
		return nil
	}

	matchers := make([]*envoy_config_rbac_v3.Principal, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		matchers = append(matchers, &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_Metadata{
				Metadata: metadataMatcherForJWTClaim(jwtRequirementName(*policy), claim, value),
			},
		})
	}
	return combinePrincipalOR(matchers)
}

func buildJWTClaimPrincipals(policy *model.GatewayAuthPolicy, claims []model.GatewayMatchAttribute) []*envoy_config_rbac_v3.Principal {
	if policy == nil || policy.JWT == nil || len(claims) == 0 {
		return nil
	}

	result := make([]*envoy_config_rbac_v3.Principal, 0, len(claims))
	for _, claim := range claims {
		if claim.Name == "" {
			continue
		}
		if principal := buildJWTPrincipalORMatcher(policy, claim.Name, claim.Values); principal != nil {
			result = append(result, principal)
		}
	}
	return result
}

func buildCIDRORPrincipal(cidrs []string) *envoy_config_rbac_v3.Principal {
	matchers := make([]*envoy_config_rbac_v3.Principal, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		addr := prefix.Addr()
		matchers = append(matchers, &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_RemoteIp{
				RemoteIp: &envoy_config_core_v3.CidrRange{
					AddressPrefix: addr.String(),
					PrefixLen:     wrapperspbUInt32(uint32(prefix.Bits())),
				},
			},
		})
	}
	return combinePrincipalOR(matchers)
}

func combinePermissionOR(rules []*envoy_config_rbac_v3.Permission) *envoy_config_rbac_v3.Permission {
	switch len(rules) {
	case 0:
		return nil
	case 1:
		return rules[0]
	default:
		return &envoy_config_rbac_v3.Permission{
			Rule: &envoy_config_rbac_v3.Permission_OrRules{
				OrRules: &envoy_config_rbac_v3.Permission_Set{
					Rules: rules,
				},
			},
		}
	}
}

func combinePrincipalOR(ids []*envoy_config_rbac_v3.Principal) *envoy_config_rbac_v3.Principal {
	switch len(ids) {
	case 0:
		return nil
	case 1:
		return ids[0]
	default:
		return &envoy_config_rbac_v3.Principal{
			Identifier: &envoy_config_rbac_v3.Principal_OrIds{
				OrIds: &envoy_config_rbac_v3.Principal_Set{
					Ids: ids,
				},
			},
		}
	}
}

func metadataMatcherForJWTClaim(metadataKey, claim, value string) *envoy_type_matcher_v3.MetadataMatcher {
	return &envoy_type_matcher_v3.MetadataMatcher{
		Filter: JWTAuthFilterName,
		Path: []*envoy_type_matcher_v3.MetadataMatcher_PathSegment{
			metadataPathSegment(metadataKey),
			metadataPathSegment(claim),
		},
		Value: &envoy_type_matcher_v3.ValueMatcher{
			MatchPattern: &envoy_type_matcher_v3.ValueMatcher_StringMatch{
				StringMatch: stringMatcherForAuthorizationValue(value, false),
			},
		},
	}
}

func metadataPathSegment(key string) *envoy_type_matcher_v3.MetadataMatcher_PathSegment {
	return &envoy_type_matcher_v3.MetadataMatcher_PathSegment{
		Segment: &envoy_type_matcher_v3.MetadataMatcher_PathSegment_Key{
			Key: key,
		},
	}
}

func stringMatcherForAuthorizationValue(value string, ignoreCase bool) *envoy_type_matcher_v3.StringMatcher {
	matcher := &envoy_type_matcher_v3.StringMatcher{IgnoreCase: ignoreCase}
	if strings.Contains(value, "*") {
		matcher.MatchPattern = &envoy_type_matcher_v3.StringMatcher_SafeRegex{
			SafeRegex: &envoy_type_matcher_v3.RegexMatcher{
				Regex: "^" + regexp.QuoteMeta(value) + "$",
			},
		}
		matcher.GetSafeRegex().Regex = strings.ReplaceAll(matcher.GetSafeRegex().Regex, "\\*", ".*")
		return matcher
	}
	matcher.MatchPattern = &envoy_type_matcher_v3.StringMatcher_Exact{Exact: value}
	return matcher
}

func wrapperspbUInt32(v uint32) *wrapperspb.UInt32Value {
	return &wrapperspb.UInt32Value{Value: v}
}

func strconvItoa(v int) string {
	return fmt.Sprintf("%d", v)
}
