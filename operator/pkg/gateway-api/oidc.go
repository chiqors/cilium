// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/operator/pkg/model"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	oidcDiscoveryTimeout  = 5 * time.Second
	oidcDiscoveryCacheTTL = 10 * time.Minute
)

type oidcDiscoveryCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	entries map[string]oidcDiscoveryCacheEntry
}

type oidcDiscoveryCacheEntry struct {
	endpoints model.GatewayOIDCEndpoints
	expiresAt time.Time
}

type oidcDiscoveryDocument struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

func newOIDCDiscoveryCache(ttl time.Duration) *oidcDiscoveryCache {
	return &oidcDiscoveryCache{
		ttl:     ttl,
		entries: map[string]oidcDiscoveryCacheEntry{},
	}
}

func (c *oidcDiscoveryCache) get(issuer string, now time.Time) (model.GatewayOIDCEndpoints, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[issuer]
	if !ok {
		return model.GatewayOIDCEndpoints{}, false
	}
	if now.After(entry.expiresAt) {
		delete(c.entries, issuer)
		return model.GatewayOIDCEndpoints{}, false
	}
	return entry.endpoints, true
}

func (c *oidcDiscoveryCache) put(issuer string, endpoints model.GatewayOIDCEndpoints, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[issuer] = oidcDiscoveryCacheEntry{
		endpoints: endpoints,
		expiresAt: now.Add(c.ttl),
	}
}

func (r *gatewayReconciler) resolveGatewayAuthPolicyOIDCMetadata(
	ctx context.Context,
	policies []ciliumv2alpha1.CiliumGatewayAuthPolicy,
) (map[types.NamespacedName]model.GatewayOIDCEndpoints, error) {
	if len(policies) == 0 {
		return nil, nil
	}

	result := map[types.NamespacedName]model.GatewayOIDCEndpoints{}
	for i := range policies {
		policy := &policies[i]
		if policy.Spec.OIDC == nil {
			continue
		}

		endpoints, err := r.resolveOIDCEndpoints(ctx, policy.Spec.OIDC)
		if err != nil {
			continue
		}
		if endpoints != nil {
			result[types.NamespacedName{Namespace: policy.Namespace, Name: policy.Name}] = *endpoints
		}
	}

	return result, nil
}

func (r *gatewayReconciler) resolveOIDCEndpoints(
	ctx context.Context,
	auth *ciliumv2alpha1.CiliumGatewayOIDCAuth,
) (*model.GatewayOIDCEndpoints, error) {
	if auth == nil {
		return nil, nil
	}

	var discovered *model.GatewayOIDCEndpoints
	if auth.Issuer != "" {
		metadata, err := r.getOIDCDiscoveryMetadata(ctx, auth.Issuer)
		if err != nil {
			return nil, err
		}
		discovered = metadata
	}

	overrides := &model.GatewayOIDCEndpoints{}
	if auth.Endpoints != nil {
		overrides.Authorization = valueOrEmpty(auth.Endpoints.Authorization)
		overrides.Token = valueOrEmpty(auth.Endpoints.Token)
		overrides.UserInfo = valueOrEmpty(auth.Endpoints.UserInfo)
		overrides.JWKS = valueOrEmpty(auth.Endpoints.JWKS)
		overrides.EndSession = valueOrEmpty(auth.Endpoints.EndSession)
	}

	return discovered.Merge(overrides), nil
}

func (r *gatewayReconciler) getOIDCDiscoveryMetadata(ctx context.Context, issuer string) (*model.GatewayOIDCEndpoints, error) {
	now := time.Now()
	if cached, ok := r.oidcDiscoveryCache.get(issuer, now); ok {
		return &cached, nil
	}

	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	reqCtx, cancel := context.WithTimeout(ctx, oidcDiscoveryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := r.oidcDiscoveryClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("oidc discovery %q returned status %d", issuer, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var document oidcDiscoveryDocument
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, err
	}

	endpoints := model.GatewayOIDCEndpoints{
		Authorization: document.AuthorizationEndpoint,
		Token:         document.TokenEndpoint,
		UserInfo:      document.UserInfoEndpoint,
		JWKS:          document.JWKSURI,
		EndSession:    document.EndSessionEndpoint,
	}
	r.oidcDiscoveryCache.put(issuer, endpoints, now)

	return &endpoints, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
