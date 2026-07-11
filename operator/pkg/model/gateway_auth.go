// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"time"

	"k8s.io/apimachinery/pkg/types"
)

type GatewayAuthAttachmentLevel string

const (
	GatewayAuthAttachmentLevelGateway       GatewayAuthAttachmentLevel = "Gateway"
	GatewayAuthAttachmentLevelListener      GatewayAuthAttachmentLevel = "Listener"
	GatewayAuthAttachmentLevelHTTPRoute     GatewayAuthAttachmentLevel = "HTTPRoute"
	GatewayAuthAttachmentLevelHTTPRule      GatewayAuthAttachmentLevel = "HTTPRouteRule"
	GatewayAuthAttachmentLevelGRPCRoute     GatewayAuthAttachmentLevel = "GRPCRoute"
	GatewayAuthAttachmentLevelGRPCRouteRule GatewayAuthAttachmentLevel = "GRPCRouteRule"
)

type GatewayAuthModel struct {
	Policies  []GatewayAuthPolicy   `json:"policies,omitempty"`
	Bindings  []GatewayAuthBinding  `json:"bindings,omitempty"`
	Conflicts []GatewayAuthConflict `json:"conflicts,omitempty"`
}

type GatewayAuthPolicy struct {
	Source            FullyQualifiedResource `json:"source"`
	Target            GatewayAuthTarget      `json:"target"`
	Attachment        GatewayAuthAttachment  `json:"attachment"`
	CreationTimestamp time.Time              `json:"creation_timestamp,omitempty"`
	BasicAuth         *GatewayBasicAuth      `json:"basic_auth,omitempty"`
	APIKeyAuth        *GatewayAPIKeyAuth     `json:"api_key_auth,omitempty"`
	JWT               *GatewayJWTAuth        `json:"jwt,omitempty"`
	OIDC              *GatewayOIDCAuth       `json:"oidc,omitempty"`
	Authorization     *GatewayAuthorization  `json:"authorization,omitempty"`
}

type GatewayAuthTarget struct {
	Kind        string `json:"kind,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Name        string `json:"name,omitempty"`
	SectionName string `json:"section_name,omitempty"`
}

type GatewayAuthAttachment struct {
	Level        GatewayAuthAttachmentLevel `json:"level,omitempty"`
	ListenerName string                     `json:"listener_name,omitempty"`
	Route        *types.NamespacedName      `json:"route,omitempty"`
	RouteRule    string                     `json:"route_rule,omitempty"`
}

type GatewayAuthBinding struct {
	Scope  GatewayAuthAttachment  `json:"scope"`
	Policy FullyQualifiedResource `json:"policy"`
}

type GatewayAuthConflict struct {
	Scope  GatewayAuthAttachment  `json:"scope"`
	Winner FullyQualifiedResource `json:"winner"`
	Loser  FullyQualifiedResource `json:"loser"`
}

type GatewayAuthSecretRef struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Key       string `json:"key,omitempty"`
	Value     []byte `json:"value,omitempty"`
	Found     bool   `json:"found"`
}

type GatewayAuthConfigMapRef struct {
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name,omitempty"`
	Key       string `json:"key,omitempty"`
	Value     []byte `json:"value,omitempty"`
	Found     bool   `json:"found"`
}

type GatewayBasicAuth struct {
	Secret         GatewayAuthSecretRef `json:"secret"`
	UsernameHeader string               `json:"username_header,omitempty"`
}

type GatewayAPIKeyAuth struct {
	Sources         []GatewayAPIKeySource     `json:"sources,omitempty"`
	Credentials     []GatewayAPIKeyCredential `json:"credentials,omitempty"`
	IdentityHeader  string                    `json:"identity_header,omitempty"`
	StripCredential bool                      `json:"strip_credential,omitempty"`
}

type GatewayAPIKeySource struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

type GatewayAPIKeyCredential struct {
	Secret   GatewayAuthSecretRef `json:"secret"`
	Identity string               `json:"identity,omitempty"`
}

type GatewayJWTAuth struct {
	Issuer         string                 `json:"issuer,omitempty"`
	Audiences      []string               `json:"audiences,omitempty"`
	RemoteJWKSURI  string                 `json:"remote_jwks_uri,omitempty"`
	LocalJWKS      *GatewayLocalJWKS      `json:"local_jwks,omitempty"`
	ClaimToHeaders []GatewayClaimToHeader `json:"claim_to_headers,omitempty"`
}

type GatewayLocalJWKS struct {
	Secret    *GatewayAuthSecretRef    `json:"secret,omitempty"`
	ConfigMap *GatewayAuthConfigMapRef `json:"config_map,omitempty"`
}

type GatewayClaimToHeader struct {
	Claim  string `json:"claim,omitempty"`
	Header string `json:"header,omitempty"`
}

type GatewayOIDCAuth struct {
	Issuer         string                 `json:"issuer,omitempty"`
	ClientID       string                 `json:"client_id,omitempty"`
	ClientSecret   GatewayAuthSecretRef   `json:"client_secret"`
	CookieSecret   GatewayAuthSecretRef   `json:"cookie_secret"`
	Scopes         []string               `json:"scopes,omitempty"`
	Endpoints      *GatewayOIDCEndpoints  `json:"endpoints,omitempty"`
	ClaimToHeaders []GatewayClaimToHeader `json:"claim_to_headers,omitempty"`
}

type GatewayOIDCEndpoints struct {
	Authorization string `json:"authorization,omitempty"`
	Token         string `json:"token,omitempty"`
	UserInfo      string `json:"user_info,omitempty"`
	JWKS          string `json:"jwks,omitempty"`
	EndSession    string `json:"end_session,omitempty"`
}

func (e *GatewayOIDCEndpoints) Merge(overrides *GatewayOIDCEndpoints) *GatewayOIDCEndpoints {
	if e == nil && overrides == nil {
		return nil
	}

	result := &GatewayOIDCEndpoints{}
	if e != nil {
		*result = *e
	}
	if overrides == nil {
		return result
	}
	if overrides.Authorization != "" {
		result.Authorization = overrides.Authorization
	}
	if overrides.Token != "" {
		result.Token = overrides.Token
	}
	if overrides.UserInfo != "" {
		result.UserInfo = overrides.UserInfo
	}
	if overrides.JWKS != "" {
		result.JWKS = overrides.JWKS
	}
	if overrides.EndSession != "" {
		result.EndSession = overrides.EndSession
	}
	return result
}

type GatewayAuthorization struct {
	Rules []GatewayAuthorizationRule `json:"rules,omitempty"`
}

type GatewayAuthorizationRule struct {
	Principals []string                `json:"principals,omitempty"`
	Claims     []GatewayMatchAttribute `json:"claims,omitempty"`
	Headers    []GatewayMatchAttribute `json:"headers,omitempty"`
	Methods    []string                `json:"methods,omitempty"`
	Paths      []string                `json:"paths,omitempty"`
	Hosts      []string                `json:"hosts,omitempty"`
	CIDRs      []string                `json:"cidrs,omitempty"`
}

type GatewayMatchAttribute struct {
	Name   string   `json:"name,omitempty"`
	Values []string `json:"values,omitempty"`
}
