// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumgatewayauthpolicy",path="ciliumgatewayauthpolicies",scope="Namespaced",shortName={cgap}
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=Direct"
// +deepequal-gen=false

// CiliumGatewayAuthPolicy is a direct-attached Gateway API policy for native,
// Cilium-managed authentication and authorization behavior.
type CiliumGatewayAuthPolicy struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of CiliumGatewayAuthPolicy.
	//
	// +kubebuilder:validation:Required
	Spec CiliumGatewayAuthPolicySpec `json:"spec"`

	// Status defines the current state of CiliumGatewayAuthPolicy.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:Optional
	Status gatewayv1.PolicyStatus `json:"status,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumGatewayAuthPolicyList is a list of CiliumGatewayAuthPolicy objects.
type CiliumGatewayAuthPolicyList struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []CiliumGatewayAuthPolicy `json:"items"`
}

// +kubebuilder:validation:XValidation:message="at least one provider or authorization block must be specified",rule="has(self.basicAuth) || has(self.apiKeyAuth) || has(self.jwt) || has(self.oidc) || has(self.authorization)"
// +kubebuilder:validation:XValidation:message="targetRefs must reference gateway.networking.k8s.io Gateway, HTTPRoute, or GRPCRoute resources",rule="self.targetRefs.all(t, t.group == 'gateway.networking.k8s.io' && (t.kind == 'Gateway' || t.kind == 'HTTPRoute' || t.kind == 'GRPCRoute')))"
// +kubebuilder:validation:XValidation:message="basicAuth may not be combined with apiKeyAuth, jwt, or oidc",rule="!has(self.basicAuth) || (!has(self.apiKeyAuth) && !has(self.jwt) && !has(self.oidc))"
// +kubebuilder:validation:XValidation:message="apiKeyAuth may not be combined with jwt or oidc",rule="!has(self.apiKeyAuth) || (!has(self.jwt) && !has(self.oidc))"
// +kubebuilder:validation:XValidation:message="jwt and oidc may not both be specified",rule="!has(self.jwt) || !has(self.oidc)"

// CiliumGatewayAuthPolicySpec specifies the policy configuration.
type CiliumGatewayAuthPolicySpec struct {
	// TargetRefs identifies Gateway API resources this policy applies to.
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	TargetRefs []gatewayv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`

	// BasicAuth configures native HTTP Basic authentication.
	BasicAuth *CiliumGatewayBasicAuth `json:"basicAuth,omitempty"`

	// APIKeyAuth configures native API key authentication.
	APIKeyAuth *CiliumGatewayAPIKeyAuth `json:"apiKeyAuth,omitempty"`

	// JWT configures native JWT validation.
	JWT *CiliumGatewayJWTAuth `json:"jwt,omitempty"`

	// OIDC configures native OIDC login handling.
	OIDC *CiliumGatewayOIDCAuth `json:"oidc,omitempty"`

	// Authorization configures native authorization rules.
	Authorization *CiliumGatewayAuthorizationPolicy `json:"authorization,omitempty"`
}

// CiliumGatewayBasicAuth configures Basic authentication.
type CiliumGatewayBasicAuth struct {
	// Secret references a Secret containing htpasswd-formatted credential data.
	Secret CiliumGatewaySecretKeyRef `json:"secret"`

	// UsernameHeader forwards the authenticated username to the upstream
	// request using the provided header name.
	UsernameHeader *string `json:"usernameHeader,omitempty"`
}

// CiliumGatewayAPIKeyAuth configures API key authentication.
type CiliumGatewayAPIKeyAuth struct {
	// Sources defines where to extract API keys from the request.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Sources []CiliumGatewayAPIKeySource `json:"sources"`

	// Credentials defines the accepted API key values.
	//
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=32
	// +listType=atomic
	Credentials []CiliumGatewayAPIKeyCredentialRef `json:"credentials"`

	// IdentityHeader forwards the matched credential identity to the upstream
	// request using the provided header name.
	IdentityHeader *string `json:"identityHeader,omitempty"`

	// StripCredential removes the extracted credential from the upstream
	// request after successful authentication.
	StripCredential *bool `json:"stripCredential,omitempty"`
}

// +kubebuilder:validation:Enum=Header;Query;Cookie
type CiliumGatewayAPIKeySourceType string

const (
	CiliumGatewayAPIKeySourceHeader CiliumGatewayAPIKeySourceType = "Header"
	CiliumGatewayAPIKeySourceQuery  CiliumGatewayAPIKeySourceType = "Query"
	CiliumGatewayAPIKeySourceCookie CiliumGatewayAPIKeySourceType = "Cookie"
)

// CiliumGatewayAPIKeySource defines a request lookup location for API keys.
type CiliumGatewayAPIKeySource struct {
	// Type is the extraction location.
	Type CiliumGatewayAPIKeySourceType `json:"type"`

	// Name is the header, query parameter, or cookie name.
	Name string `json:"name"`
}

// CiliumGatewayAPIKeyCredentialRef identifies an API key stored in a Secret.
type CiliumGatewayAPIKeyCredentialRef struct {
	// Secret locates the credential value.
	Secret CiliumGatewaySecretKeyRef `json:"secret"`

	// Identity is an optional logical identity associated with this key.
	Identity *string `json:"identity,omitempty"`
}

// +kubebuilder:validation:XValidation:message="exactly one of localJWKS or remoteJWKS must be specified",rule="has(self.localJWKS) != has(self.remoteJWKS)"

// CiliumGatewayJWTAuth configures JWT validation.
type CiliumGatewayJWTAuth struct {
	// Issuer is the required token issuer.
	Issuer string `json:"issuer"`

	// Audiences lists accepted audiences.
	//
	// +listType=atomic
	Audiences []string `json:"audiences,omitempty"`

	// RemoteJWKS configures remote JWKS resolution.
	RemoteJWKS *CiliumGatewayRemoteJWKS `json:"remoteJWKS,omitempty"`

	// LocalJWKS configures local JWKS sourcing from Kubernetes objects.
	LocalJWKS *CiliumGatewayLocalJWKS `json:"localJWKS,omitempty"`

	// ClaimToHeaders forwards validated claims into upstream headers.
	//
	// +listType=atomic
	ClaimToHeaders []CiliumGatewayClaimToHeader `json:"claimToHeaders,omitempty"`
}

// CiliumGatewayRemoteJWKS configures remote JWKS resolution.
type CiliumGatewayRemoteJWKS struct {
	URI string `json:"uri"`
}

// CiliumGatewayLocalJWKS configures local JWKS sourcing.
// +kubebuilder:validation:XValidation:message="exactly one of secret or configMap must be specified",rule="has(self.secret) != has(self.configMap)"
type CiliumGatewayLocalJWKS struct {
	// Secret references a Secret key containing JWKS data.
	Secret *CiliumGatewaySecretKeyRef `json:"secret,omitempty"`

	// ConfigMap references a ConfigMap key containing JWKS data.
	ConfigMap *CiliumGatewayConfigMapKeyRef `json:"configMap,omitempty"`
}

// CiliumGatewayClaimToHeader maps a JWT/OIDC claim to a forwarded header.
type CiliumGatewayClaimToHeader struct {
	Claim  string `json:"claim"`
	Header string `json:"header"`
}

// CiliumGatewayOIDCAuth configures OIDC login handling.
type CiliumGatewayOIDCAuth struct {
	// Issuer is the discovery issuer URL.
	Issuer string `json:"issuer"`

	// ClientID is the OAuth client identifier.
	ClientID string `json:"clientID"`

	// ClientSecret references the client secret used for token exchange.
	ClientSecret CiliumGatewaySecretKeyRef `json:"clientSecret"`

	// CookieSecret references the secret used to protect session state.
	CookieSecret CiliumGatewaySecretKeyRef `json:"cookieSecret"`

	// Scopes lists requested scopes.
	//
	// +listType=atomic
	Scopes []string `json:"scopes,omitempty"`

	// Endpoints overrides discovery-provided endpoints when needed.
	Endpoints *CiliumGatewayOIDCEndpoints `json:"endpoints,omitempty"`

	// ClaimToHeaders forwards validated claims into upstream headers.
	//
	// +listType=atomic
	ClaimToHeaders []CiliumGatewayClaimToHeader `json:"claimToHeaders,omitempty"`
}

// CiliumGatewayOIDCEndpoints provides explicit endpoint overrides.
type CiliumGatewayOIDCEndpoints struct {
	Authorization *string `json:"authorization,omitempty"`
	Token         *string `json:"token,omitempty"`
	UserInfo      *string `json:"userInfo,omitempty"`
	JWKS          *string `json:"jwks,omitempty"`
	EndSession    *string `json:"endSession,omitempty"`
}

// CiliumGatewayAuthorizationPolicy configures native authorization rules.
type CiliumGatewayAuthorizationPolicy struct {
	// Rules lists allow rules. If this block is present, unmatched traffic is denied.
	//
	// +listType=atomic
	Rules []CiliumGatewayAuthorizationRule `json:"rules,omitempty"`
}

// CiliumGatewayAuthorizationRule defines one authorization allow rule.
type CiliumGatewayAuthorizationRule struct {
	// Principals matches authenticated principal identifiers.
	//
	// +listType=atomic
	Principals []string `json:"principals,omitempty"`

	// Claims matches claim values.
	//
	// +listType=atomic
	Claims []CiliumGatewayMatchAttribute `json:"claims,omitempty"`

	// Headers matches request headers.
	//
	// +listType=atomic
	Headers []CiliumGatewayMatchAttribute `json:"headers,omitempty"`

	// Methods matches HTTP methods.
	//
	// +listType=atomic
	Methods []string `json:"methods,omitempty"`

	// Paths matches request paths.
	//
	// +listType=atomic
	Paths []string `json:"paths,omitempty"`

	// Hosts matches request hosts.
	//
	// +listType=atomic
	Hosts []string `json:"hosts,omitempty"`

	// CIDRs matches source IP CIDR ranges.
	//
	// +listType=atomic
	CIDRs []string `json:"cidrs,omitempty"`
}

// CiliumGatewayMatchAttribute matches a named attribute with one or more values.
type CiliumGatewayMatchAttribute struct {
	Name string `json:"name"`

	// Values lists accepted values for the named attribute.
	//
	// +listType=atomic
	Values []string `json:"values,omitempty"`
}

// CiliumGatewaySecretKeyRef identifies a Secret data entry.
type CiliumGatewaySecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

// CiliumGatewayConfigMapKeyRef identifies a ConfigMap data entry.
type CiliumGatewayConfigMapKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}
