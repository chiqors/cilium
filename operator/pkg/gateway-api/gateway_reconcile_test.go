// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	"github.com/cilium/cilium/operator/pkg/model/translation"
	gatewayApiTranslation "github.com/cilium/cilium/operator/pkg/model/translation/gateway-api"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/shortener"
)

var (
	gatewayv1APIVersion = gatewayv1.GroupVersion.Group + "/" + gatewayv1.GroupVersion.Version
	gatewayTypeMeta     = metav1.TypeMeta{
		Kind:       "Gateway",
		APIVersion: gatewayv1APIVersion,
	}
	httpRouteTypeMeta = metav1.TypeMeta{
		Kind:       "HTTPRoute",
		APIVersion: gatewayv1APIVersion,
	}
	grpcRouteTypeMeta = metav1.TypeMeta{
		Kind:       "GRPCRoute",
		APIVersion: gatewayv1APIVersion,
	}
	tlsRouteTypeMeta = metav1.TypeMeta{
		Kind:       "TLSRoute",
		APIVersion: gatewayv1APIVersion,
	}
	backendTLSPolicyTypeMeta = metav1.TypeMeta{
		Kind:       "BackendTLSPolicy",
		APIVersion: gatewayv1APIVersion,
	}
	tcpRouteTypeMeta = metav1.TypeMeta{
		Kind:       "TCPRoute",
		APIVersion: gatewayv1APIVersion,
	}
	udpRouteTypeMeta = metav1.TypeMeta{
		Kind:       "UDPRoute",
		APIVersion: gatewayv1APIVersion,
	}
	listenerSetTypeMeta = metav1.TypeMeta{
		Kind:       "ListenerSet",
		APIVersion: gatewayv1APIVersion,
	}
	endpointSliceTypeMeta = metav1.TypeMeta{
		Kind:       "EndpointSlice",
		APIVersion: discoveryv1.SchemeGroupVersion.String(),
	}
)

func Test_Conformance(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))
	cecTranslator := translation.NewCECTranslator(translation.Config{
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
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})
	gatewayAPITranslator := gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
		ServiceConfig: translation.ServiceConfig{
			ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
		},
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})

	type gwDetails struct {
		FullName types.NamespacedName
		wantErr  bool
		skipCEC  bool
	}

	var (
		gatewaySameNamespace          = gwDetails{FullName: types.NamespacedName{Name: "same-namespace", Namespace: "gateway-conformance-infra"}}
		gatewaySameNamespaceWithHTTPS = gwDetails{FullName: types.NamespacedName{Name: "same-namespace-with-https-listener", Namespace: "gateway-conformance-infra"}}
		gatewayBackendNamespace       = gwDetails{FullName: types.NamespacedName{Name: "backend-namespaces", Namespace: "gateway-conformance-infra"}}
	)

	tests := []struct {
		name                 string
		gateway              []gwDetails
		disableServiceImport bool
		disableTCPRoute      bool
		disableUDPRoute      bool
		skipCEC              bool
		wantErr              bool
		hostNetwork          bool
	}{
		{
			name: "gateway-http-listener-isolation",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "http-listener-isolation", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "http-listener-isolation-with-hostname-intersection", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name:    "gateway-infrastructure",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-with-infrastructure-metadata", Namespace: "gateway-conformance-infra"}}},
		},
		{
			name: "gateway-invalid-parameters-ref",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-invalid-parameters-ref", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-invalid-route-kind",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-only-invalid-route-kind", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-supported-and-invalid-route-kind", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-invalid-tls-configuration",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-certificate-nonexistent-secret", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-certificate-unsupported-group", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-certificate-unsupported-kind", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-certificate-malformed-secret", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-modify-listeners",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-add-listener", Namespace: "gateway-conformance-infra"}, wantErr: true},
				{FullName: types.NamespacedName{Name: "gateway-remove-listener", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-observed-generation-bump",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-observed-generation-bump", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-secret-invalid-reference-grant",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-invalid-reference-grant", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-secret-missing-reference-grant",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-missing-reference-grant", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		// gateway-secret-reference-grant-all-in-namespace
		{
			name: "gateway-secret-reference-grant-all-in-namespace",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-reference-grant-all-in-namespace", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-secret-reference-grant-specific",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-secret-reference-grant-specific", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-static-addresses",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-static-addresses", Namespace: "gateway-conformance-infra"}},
			},
		},
		{
			name: "gateway-static-addresses",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-static-addresses-invalid", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-with-attached-routes",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "gateway-with-one-attached-route", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "gateway-with-two-attached-routes", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "unresolved-gateway-with-one-attached-unresolved-route", Namespace: "gateway-conformance-infra"}, wantErr: true},
			},
		},
		{
			name: "gateway-multiple-listeners",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{
					Name:      "gateway-multiple-listeners",
					Namespace: "gateway-conformance-infra",
				}},
			},
		},
		{
			name: "gateway-omit-sectionName-listeners",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{
					Name:      "gateway-omit-sectionName-listeners",
					Namespace: "gateway-conformance-infra-label",
				}},
			},
		},
		{name: "grpcroute-exact-method-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "grpcroute-header-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "grpcroute-listener-hostname-matching", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "grpcroute-listener-hostname-matching", Namespace: "gateway-conformance-infra"}}}},
		{name: "httproute-backend-protocol-h2c", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backend-protocol-websocket", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-cors", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-cross-namespace", gateway: []gwDetails{gatewayBackendNamespace}},
		{
			name:    "httproute-allowed-kind-by-section-name",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "kind-restricted-multi-listener", Namespace: "gateway-conformance-infra"}}},
		},
		{
			name:    "httproute-disallowed-kind",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "tlsroutes-only", Namespace: "gateway-conformance-infra"}}},
		},
		{name: "httproute-exact-path-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-header-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{
			name: "httproute-hostname-intersection",
			gateway: []gwDetails{
				{FullName: types.NamespacedName{Name: "httproute-hostname-intersection", Namespace: "gateway-conformance-infra"}},
				{FullName: types.NamespacedName{Name: "httproute-hostname-intersection-all", Namespace: "gateway-conformance-infra"}},
			},
		},
		{name: "httproute-https-listener", gateway: []gwDetails{gatewaySameNamespaceWithHTTPS}},
		{name: "httproute-invalid-backendref-unknown-kind", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-backendref-missing-service-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-backendref-missing-serviceimport-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-cross-namespace-backend-ref", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-cross-namespace-parent-ref", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-nonexistent-backendref", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-not-matching-listener-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-not-matching-section-name", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-section-name-not-matching-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-reference-grant", gateway: []gwDetails{gatewaySameNamespace}},
		{
			name:    "httproute-listener-hostname-matching",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "httproute-listener-hostname-matching", Namespace: "gateway-conformance-infra"}}},
		},
		{
			name:    "httproute-listener-port-matching",
			gateway: []gwDetails{{FullName: types.NamespacedName{Name: "httproute-listener-port-matching", Namespace: "gateway-conformance-infra"}}},
		},
		{name: "httproute-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-matching-across-routes", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-method-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-observed-generation-bump", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-partially-invalid-via-invalid-reference-grant", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-path-match-order", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-query-param-matching", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-host-and-status", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-path", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-port", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-port-and-scheme", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-redirect-scheme", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-reference-grant", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-header-modifier", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-header-modifier-backend-weights", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-mirror", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-multiple-mirrors", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-request-percentage-mirror", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-response-header-modifier", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-timeout-backend-request", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-timeout-request", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-weight", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-service-types", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-invalid-parentref-types", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-simple-same-namespace", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-serviceimport-backend", gateway: []gwDetails{gatewaySameNamespace}},
		{
			name: "httproute-invalid-serviceimport-no-crd", gateway: []gwDetails{gatewaySameNamespace},
			disableServiceImport: true,
		},
		{name: "httproute-backendtlspolicy-valid", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backendtlspolicy-reencrypt", gateway: []gwDetails{gatewaySameNamespaceWithHTTPS}},
		{name: "httproute-backendtlspolicy-multiparent", gateway: []gwDetails{gatewaySameNamespace, gatewaySameNamespaceWithHTTPS}},
		{name: "httproute-backendtlspolicy-conflict-resolution", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backendtlspolicy-invalid-ca-cert", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "httproute-backendtlspolicy-invalid-kind", gateway: []gwDetails{gatewaySameNamespace}},
		{name: "gateway-multi-port-https", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "multi-port-https", Namespace: "gateway-conformance-infra"}}}},
		{name: "tcproute-invalid-reference-grant", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tcproute-referencegrant", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		{name: "tcproute-simple-same-namespace", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tcproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		{name: "udproute-invalid-reference-grant", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-udproute-referencegrant", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		{name: "udproute-simple-same-namespace", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-udproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}},
		// A single Gateway mixing an L7 (HTTP) and an L4 (TCP) listener: the
		// L7 path produces a CiliumEnvoyConfig while the L4 path produces a
		// managed EndpointSlice for the TCP backend (no dummy slice is added
		// because a real L4 slice already exists).
		{name: "gateway-mixed-http-tcp", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-mixed", Namespace: "gateway-conformance-infra"}}}},
		{name: "tcproute-crd-not-installed", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tcproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}, disableTCPRoute: true},
		{name: "udproute-crd-not-installed", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-udproute", Namespace: "gateway-conformance-infra"}, skipCEC: true}}, disableUDPRoute: true},
		{name: "tlsroute-invalid-reference-grant", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tlsroute-referencegrant", Namespace: "gateway-conformance-infra"}}}},
		{name: "tlsroute-simple-same-namespace", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "gateway-tlsroute", Namespace: "gateway-conformance-infra"}}}},
		{name: "tlsroute-hostname-intersection", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "gw-tlsroute-empty-hostname-x-4", Namespace: "gateway-conformance-infra"}},
			{FullName: types.NamespacedName{Name: "gw-tlsroute-exact-hostname-x-1", Namespace: "gateway-conformance-infra"}},
			{FullName: types.NamespacedName{Name: "gw-tlsroute-less-specific-wc-hostname-x-3", Namespace: "gateway-conformance-infra"}},
			{FullName: types.NamespacedName{Name: "gw-tlsroute-more-specific-wc-hostname-x-2", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "tlsroute-invalid-no-matching-listener", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-http-only", Namespace: "gateway-conformance-infra"}, wantErr: false},
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-https-only", Namespace: "gateway-conformance-infra"}, wantErr: false},
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-tls-passthrough-only", Namespace: "gateway-conformance-infra"}, wantErr: false},
		}},
		{name: "tlsroute-mixed-protocol-listeners", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "gateway-tlsroute-mixed", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "gateway-multi-port-tls-passthrough", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "multi-port-tls-passthrough", Namespace: "gateway-conformance-infra"}}}},
		{name: "gateway-multi-port-https-with-multi-port-tls-passthrough", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "multi-port-https-with-multi-port-tls-passthrough", Namespace: "gateway-conformance-infra"}}}},
		{name: "gateway-cross-protocol-same-hostname", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "cross-protocol-same-hostname", Namespace: "gateway-conformance-infra"}}}},
		{name: "gateway-cross-protocol-same-port-same-hostname", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "cross-protocol-same-port-same-hostname", Namespace: "gateway-conformance-infra"}, wantErr: true}}},
		{name: "gateway-ns-restricted-same-hostname", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "ns-restricted-same-hostname", Namespace: "gateway-conformance-infra"}}}},
		{name: "hostNetwork-enabled-valid", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "hostnetwork-enabled", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "hostNetwork-enabled-exceed-max-address", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "hostnetwork-enabled", Namespace: "gateway-conformance-infra"}}}, hostNetwork: true},
		{name: "gatewayclassconfig-nodeport", gateway: []gwDetails{{FullName: types.NamespacedName{Name: "nodeport-gateway", Namespace: "gateway-conformance-infra"}}}},
		// ListenerSet tests
		{name: "listenerset-default-not-allowed", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "default-not-allowed", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-namespace-none", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-namespace-none", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-namespace-same", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-namespace-same", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-namespace-selector", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-namespace-selector", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-protocol-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "protocol-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-hostname-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "hostname-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-cross-listenerset-hostname-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "cross-listenerset-hostname-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-cross-listenerset-protocol-conflict", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "cross-listenerset-protocol-conflict", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-allowed-routes-kinds", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "allowed-route-kinds", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-route-hostname-independence", gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "route-hostname-independence", Namespace: "gateway-conformance-infra"}},
		}},
		{name: "listenerset-valid-with-invalid-gateway-listener", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "valid-listenerset-only", Namespace: "gateway-conformance-infra"}, wantErr: true},
		}},
		// A Route that targets the Gateway must not leak into a ListenerSet's
		// L4 listeners, even when the Route lives in a namespace the ListenerSet
		// listener would otherwise allow.
		{name: "listenerset-l4-namespace-isolation", skipCEC: true, gateway: []gwDetails{
			{FullName: types.NamespacedName{Name: "l4-namespace-isolation", Namespace: "gateway-conformance-infra"}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := readInputDir(t, "testdata/gateway/base")
			input := readInputDir(t, fmt.Sprintf("testdata/gateway/%s/input", tt.name))
			clientBuilder := fake.NewClientBuilder().
				WithObjects(append(base, input...)...).
				WithStatusSubresource(&corev1.Service{}).
				WithStatusSubresource(&corev1.Namespace{}).
				WithStatusSubresource(&gatewayv1.GRPCRoute{}).
				WithStatusSubresource(&gatewayv1.HTTPRoute{}).
				WithStatusSubresource(&gatewayv1.TLSRoute{}).
				WithStatusSubresource(&gatewayv1.Gateway{}).
				WithStatusSubresource(&gatewayv1.GatewayClass{}).
				WithStatusSubresource(&gatewayv1.BackendTLSPolicy{}).
				WithStatusSubresource(&gatewayv1.ListenerSet{})

			disabledKinds := map[string]bool{
				helpers.ServiceImportKind: tt.disableServiceImport,
				helpers.TCPRouteKind:      tt.disableTCPRoute,
				helpers.UDPRouteKind:      tt.disableUDPRoute,
			}
			optionalKinds := make([]schema.GroupVersionKind, 0, len(helpers.AllOptionalKinds))
			for _, k := range helpers.AllOptionalKinds {
				if disabledKinds[k.Kind] {
					continue
				}
				optionalKinds = append(optionalKinds, k)
			}
			clientBuilder.WithScheme(helpers.TestScheme(optionalKinds))

			// Add any required indexes here
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, fakeIndexHTTPRouteByBackendService)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway)
			clientBuilder.WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)
			// TCPRoute/UDPRoute types are only registered in the scheme when their
			// CRDs are installed, so only set their status subresource and index then.
			if !tt.disableTCPRoute {
				clientBuilder.WithStatusSubresource(&gatewayv1.TCPRoute{})
				clientBuilder.WithIndex(&gatewayv1.TCPRoute{}, indexers.GatewayTCPRouteIndex, indexers.IndexTCPRouteByGateway)
				clientBuilder.WithIndex(&gatewayv1.TCPRoute{}, indexers.TCPRouteListenerSetIndex, indexers.IndexTCPRouteByListenerSet)
			}
			if !tt.disableUDPRoute {
				clientBuilder.WithStatusSubresource(&gatewayv1.UDPRoute{})
				clientBuilder.WithIndex(&gatewayv1.UDPRoute{}, indexers.GatewayUDPRouteIndex, indexers.IndexUDPRouteByGateway)
				clientBuilder.WithIndex(&gatewayv1.UDPRoute{}, indexers.UDPRouteListenerSetIndex, indexers.IndexUDPRouteByListenerSet)
			}
			clientBuilder.WithIndex(&gatewayv1.ListenerSet{}, indexers.ListenerSetGatewayIndex, indexers.IndexListenerSetByGateway)
			clientBuilder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.HTTPRouteListenerSetIndex, indexers.IndexHTTPRouteByListenerSet)
			clientBuilder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GRPCRouteListenerSetIndex, indexers.IndexGRPCRouteByListenerSet)
			clientBuilder.WithIndex(&gatewayv1.TLSRoute{}, indexers.TLSRouteListenerSetIndex, indexers.IndexTLSRouteByListenerSet)

			c := clientBuilder.Build()
			if tt.hostNetwork {
				gatewayAPITranslator = gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{
					ServiceConfig: translation.ServiceConfig{
						ExternalTrafficPolicy: string(corev1.ServiceExternalTrafficPolicyCluster),
					},
					OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
						UseRemoteAddress: true,
					},
					HostNetworkConfig: translation.HostNetworkConfig{
						Enabled: true,
					},
				})
			}
			r := &gatewayReconciler{
				Client:         c,
				translator:     gatewayAPITranslator,
				logger:         logger,
				controllerName: defaultControllerName,
			}

			// Reconcile all related HTTPRoute objects
			hrList := &gatewayv1.HTTPRouteList{}
			err := c.List(t.Context(), hrList)
			require.NoError(t, err)

			// Reconcile all related TLSRoute objects
			tlsrList := &gatewayv1.TLSRouteList{}
			err = c.List(t.Context(), tlsrList)
			require.NoError(t, err)

			// Reconcile all related GRPCRoute objects
			grpcrList := &gatewayv1.GRPCRouteList{}
			err = c.List(t.Context(), grpcrList)
			require.NoError(t, err)

			// Reconcile all BackendTLSPolicy objects
			btlspList := &gatewayv1.BackendTLSPolicyList{}
			err = c.List(t.Context(), btlspList)
			require.NoError(t, err)

			// Reconcile all TCPRoute objects
			tcprList := &gatewayv1.TCPRouteList{}
			if !tt.disableTCPRoute {
				err = c.List(t.Context(), tcprList)
				require.NoError(t, err)
			}

			// Reconcile all UDPRoute objects
			udprList := &gatewayv1.UDPRouteList{}
			if !tt.disableUDPRoute {
				err = c.List(t.Context(), udprList)
				require.NoError(t, err)
			}

			for _, gwDetail := range tt.gateway {
				// Reconcile the gateway under test
				result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: gwDetail.FullName})
				require.Equal(t, gwDetail.wantErr, err != nil, "Got an unexpected reconciliation error for Gateway %s. want: %t, got: %t", gwDetail.FullName.Name, gwDetail.wantErr, err != nil)
				require.Equal(t, ctrl.Result{}, result)
				// Checking the output for Gateway
				actualGateway := &gatewayv1.Gateway{}
				err = c.Get(t.Context(), gwDetail.FullName, actualGateway)
				// TODO(youngnick): controller-runtime has broken something with the fake client
				// Bypass for now
				actualGateway.TypeMeta = gatewayTypeMeta
				require.NoError(t, err)
				expectedGateway := &gatewayv1.Gateway{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/%s.yaml", tt.name, gwDetail.FullName.Name), expectedGateway)
				require.Empty(t, cmp.Diff(expectedGateway, actualGateway, cmpIgnoreFields...))
				if !gwDetail.wantErr && !gwDetail.skipCEC && !tt.skipCEC {
					// Checking the output for CiliumEnvoyConfig
					actualCEC := &ciliumv2.CiliumEnvoyConfig{}
					err = c.Get(t.Context(), client.ObjectKey{
						Namespace: gwDetail.FullName.Namespace,
						Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gwDetail.FullName.Name),
					}, actualCEC)
					require.NoError(t, err, "Could not get CiliumEnvoyConfig and wasn't expecting a reconciliation error")
					expectedCEC := &ciliumv2.CiliumEnvoyConfig{}
					readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/cec-%s.yaml", tt.name, gwDetail.FullName.Name), expectedCEC)
					require.NoError(t, err)
					require.Empty(t, cmp.Diff(expectedCEC, actualCEC, protocmp.Transform()))
				}

			}

			// Checking the output for EndpointSlices
			epsList := &discoveryv1.EndpointSliceList{}
			err = c.List(t.Context(), epsList, client.MatchingLabels{
				gatewayApiTranslation.EndpointSliceManagedByLabel: gatewayApiTranslation.EndpointSliceManagedByValue,
			})
			require.NoError(t, err)
			for _, eps := range epsList.Items {
				actualEPS := &discoveryv1.EndpointSlice{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&eps), actualEPS)
				actualEPS.TypeMeta = endpointSliceTypeMeta
				require.NoError(t, err, "error getting EndpointSlice %s/%s: %v", eps.Namespace, eps.Name, err)
				expectedEPS := &discoveryv1.EndpointSlice{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/endpointslice-%s.yaml", tt.name, eps.Name), expectedEPS)
				require.Empty(t, cmp.Diff(expectedEPS, actualEPS, cmpIgnoreFields...))
			}

			// Checking the output for related HTTPRoute objects
			for _, hr := range hrList.Items {
				actualHR := &gatewayv1.HTTPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&hr), actualHR)
				// TODO(youngnick): controller-runtime has broken something with the fake client
				// Bypass for now
				actualHR.TypeMeta = httpRouteTypeMeta
				require.NoError(t, err, "error getting HTTPRoute %s/%s: %v", hr.Namespace, hr.Name, err)
				expectedHR := &gatewayv1.HTTPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/httproute-%s.yaml", tt.name, hr.Name), expectedHR)
				require.Empty(t, cmp.Diff(expectedHR, actualHR, cmpIgnoreFields...))
			}

			for _, tlsr := range tlsrList.Items {
				actualTLSR := &gatewayv1.TLSRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tlsr), actualTLSR)
				actualTLSR.TypeMeta = tlsRouteTypeMeta
				require.NoError(t, err, "error getting TLSRoute %s/%s: %v", tlsr.Namespace, tlsr.Name, err)
				expectedTLSR := &gatewayv1.TLSRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tlsroute-%s.yaml", tt.name, tlsr.Name), expectedTLSR)
				require.Empty(t, cmp.Diff(expectedTLSR, actualTLSR, cmpIgnoreFields...))
			}

			for _, grpcr := range grpcrList.Items {
				actualGRPCR := &gatewayv1.GRPCRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&grpcr), actualGRPCR)
				actualGRPCR.TypeMeta = grpcRouteTypeMeta
				require.NoError(t, err, "error getting GRPCRoute %s/%s: %v", grpcr.Namespace, grpcr.Name, err)
				expectedGRPCR := &gatewayv1.GRPCRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/grpcroute-%s.yaml", tt.name, grpcr.Name), expectedGRPCR)
				require.Empty(t, cmp.Diff(expectedGRPCR, actualGRPCR, cmpIgnoreFields...))
			}

			for _, btlsp := range btlspList.Items {
				actualBTLSP := &gatewayv1.BackendTLSPolicy{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&btlsp), actualBTLSP)
				actualBTLSP.TypeMeta = backendTLSPolicyTypeMeta
				require.NoError(t, err, "error getting BackendTLSPolicy %s/%s: %v", btlsp.Namespace, btlsp.Name, err)
				expectedBTLSP := &gatewayv1.BackendTLSPolicy{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/backendtlspolicy-%s.yaml", tt.name, btlsp.Name), expectedBTLSP)
				require.Empty(t, cmp.Diff(expectedBTLSP, actualBTLSP, cmpIgnoreFields...))
			}

			for _, tcpr := range tcprList.Items {
				actualTCPR := &gatewayv1.TCPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&tcpr), actualTCPR)
				actualTCPR.TypeMeta = tcpRouteTypeMeta
				require.NoError(t, err, "error getting TCPRoute %s/%s: %v", tcpr.Namespace, tcpr.Name, err)
				expectedTCPR := &gatewayv1.TCPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/tcproute-%s.yaml", tt.name, tcpr.Name), expectedTCPR)
				require.Empty(t, cmp.Diff(expectedTCPR, actualTCPR, cmpIgnoreFields...))
			}

			for _, udpr := range udprList.Items {
				actualUDPR := &gatewayv1.UDPRoute{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&udpr), actualUDPR)
				actualUDPR.TypeMeta = udpRouteTypeMeta
				require.NoError(t, err, "error getting UDPRoute %s/%s: %v", udpr.Namespace, udpr.Name, err)
				expectedUDPR := &gatewayv1.UDPRoute{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/udproute-%s.yaml", tt.name, udpr.Name), expectedUDPR)
				require.Empty(t, cmp.Diff(expectedUDPR, actualUDPR, cmpIgnoreFields...))
			}

			lsList := &gatewayv1.ListenerSetList{}
			err = c.List(t.Context(), lsList)
			require.NoError(t, err)
			for _, ls := range lsList.Items {
				actualLS := &gatewayv1.ListenerSet{}
				err = c.Get(t.Context(), client.ObjectKeyFromObject(&ls), actualLS)
				actualLS.TypeMeta = listenerSetTypeMeta
				require.NoError(t, err, "error getting ListenerSet %s/%s: %v", ls.Namespace, ls.Name, err)
				expectedLS := &gatewayv1.ListenerSet{}
				readOutput(t, fmt.Sprintf("testdata/gateway/%s/output/listenerset-%s.yaml", tt.name, ls.Name), expectedLS)
				require.Empty(t, cmp.Diff(expectedLS, actualLS, cmpIgnoreFields...))
			}
		})
	}
}

func Test_grpcWebTranslationEnabled(t *testing.T) {
	tests := []struct {
		name   string
		config *v2alpha1.CiliumGatewayClassConfig
		want   bool
	}{
		{
			name: "nil config",
			want: true,
		},
		{
			name:   "empty config",
			config: &v2alpha1.CiliumGatewayClassConfig{},
			want:   true,
		},
		{
			name: "nil enabled",
			config: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					HTTPOptions: &v2alpha1.HTTPOptions{
						GRPCWebTranslation: &v2alpha1.GRPCWebTranslationConfig{},
					},
				},
			},
			want: true,
		},
		{
			name: "explicitly enabled",
			config: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					HTTPOptions: &v2alpha1.HTTPOptions{
						GRPCWebTranslation: &v2alpha1.GRPCWebTranslationConfig{
							Enabled: ptr.To(true),
						},
					},
				},
			},
			want: true,
		},
		{
			name: "disabled",
			config: &v2alpha1.CiliumGatewayClassConfig{
				Spec: v2alpha1.CiliumGatewayClassConfigSpec{
					HTTPOptions: &v2alpha1.HTTPOptions{
						GRPCWebTranslation: &v2alpha1.GRPCWebTranslationConfig{
							Enabled: ptr.To(false),
						},
					},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.GRPCWebTranslationEnabled())
		})
	}
}

func Test_isAccessLogsConfigured(t *testing.T) {
	tests := []struct {
		name   string
		config *v2alpha1.Telemetry
		want   bool
	}{
		{
			name: "nil config",
			want: false,
		},
		{
			name:   "empty config",
			config: &v2alpha1.Telemetry{},
			want:   false,
		},
		{
			name:   "telemetry without access logs",
			config: &v2alpha1.Telemetry{},
			want:   false,
		},
		{
			name: "empty access logs",
			config: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{},
			},
			want: false,
		},
		{
			name: "access logs",
			config: &v2alpha1.Telemetry{
				AccessLogs: []v2alpha1.AccessLogs{
					{
						Format: v2alpha1.AccessLogsFormatText,
						Text:   "%REQ(:METHOD)%",
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.IsAccessLogsConfigured())
		})
	}
}

func Test_gatewayReconciler_Reconcile_cleansUpResourcesOnHandoff(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		gatewayClass string
		objects      []client.Object
	}{
		{
			name:         "gatewayclass missing",
			gatewayClass: "missing",
		},
		{
			name:         "gatewayclass controller no longer matches",
			gatewayClass: "other",
			objects: []client.Object{
				&gatewayv1.GatewayClass{
					ObjectMeta: metav1.ObjectMeta{Name: "other"},
					Spec: gatewayv1.GatewayClassSpec{
						ControllerName: "example.com/other-controller",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "handoff-gateway",
					Namespace: "default",
					UID:       types.UID("gateway-uid"),
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: gatewayv1.ObjectName(tc.gatewayClass),
					// Ensure handoff cleanup takes precedence over Gateway validation.
					Infrastructure: &gatewayv1.GatewayInfrastructure{
						ParametersRef: &gatewayv1.LocalParametersReference{
							Group: gatewayv1.Group("invalid.io"),
							Kind:  gatewayv1.Kind("InvalidParameters"),
							Name:  "invalid",
						},
					},
				},
			}

			serviceName := shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name)
			shortGatewayName := shortener.ShortenK8sResourceName(gw.Name)
			svc := &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{
					Name:      serviceName,
					Namespace: gw.Namespace,
					Labels: map[string]string{
						owningGatewayLabel:                       shortGatewayName,
						"gateway.networking.k8s.io/gateway-name": shortGatewayName,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       gw.Name,
							UID:        gw.UID,
							Controller: ptr.To(true),
						},
					},
				},
			}
			cec := &ciliumv2.CiliumEnvoyConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
					Namespace: gw.Namespace,
					Labels: map[string]string{
						"gateway.networking.k8s.io/gateway-name": shortGatewayName,
					},
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: gatewayv1.GroupVersion.String(),
							Kind:       "Gateway",
							Name:       gw.Name,
							UID:        gw.UID,
							Controller: ptr.To(true),
						},
					},
				},
			}

			objects := append([]client.Object{gw, svc, cec}, tc.objects...)
			c := fake.NewClientBuilder().
				WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
				WithObjects(objects...).
				Build()

			r := &gatewayReconciler{
				Client:         c,
				logger:         hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
				controllerName: defaultControllerName,
			}

			result, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
			require.NoError(t, err)
			require.Equal(t, ctrl.Result{}, result)

			err = c.Get(t.Context(), client.ObjectKeyFromObject(svc), &corev1.Service{})
			require.ErrorContains(t, err, "not found")

			err = c.Get(t.Context(), client.ObjectKeyFromObject(cec), &ciliumv2.CiliumEnvoyConfig{})
			require.ErrorContains(t, err, "not found")

			actualGateway := &gatewayv1.Gateway{}
			require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(gw), actualGateway))
		})
	}
}

// Test_gatewayReconciler_ensureEnvoyConfig_deletesStaleCEC verifies that a
// CiliumEnvoyConfig left over from a previous HTTP/TLS state is cleaned up when
// the Gateway no longer needs Envoy (e.g. it switches to pure L4 TCP/UDP
// Routes, so the translator returns a nil desired CEC).
func Test_gatewayReconciler_ensureEnvoyConfig_deletesStaleCEC(t *testing.T) {
	t.Parallel()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "l4-gateway",
			Namespace: "default",
			UID:       types.UID("gateway-uid"),
		},
	}

	cecKey := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}

	ownedCEC := func() *ciliumv2.CiliumEnvoyConfig {
		return &ciliumv2.CiliumEnvoyConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cecKey.Name,
				Namespace: cecKey.Namespace,
				OwnerReferences: []metav1.OwnerReference{
					{
						APIVersion: gatewayv1.GroupVersion.String(),
						Kind:       "Gateway",
						Name:       gw.Name,
						UID:        gw.UID,
						Controller: ptr.To(true),
					},
				},
			},
		}
	}

	t.Run("deletes owned stale CEC when desired is nil", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(gw, ownedCEC()).
			Build()
		r := &gatewayReconciler{
			Client: c,
			logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		}

		require.NoError(t, r.ensureEnvoyConfig(t.Context(), gw, nil))

		err := c.Get(t.Context(), cecKey, &ciliumv2.CiliumEnvoyConfig{})
		require.ErrorContains(t, err, "not found")
	})

	t.Run("keeps CEC not owned by the Gateway", func(t *testing.T) {
		foreign := ownedCEC()
		foreign.OwnerReferences[0].UID = types.UID("other-uid")
		foreign.OwnerReferences[0].Name = "other-gateway"
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(gw, foreign).
			Build()
		r := &gatewayReconciler{
			Client: c,
			logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		}

		require.NoError(t, r.ensureEnvoyConfig(t.Context(), gw, nil))

		require.NoError(t, c.Get(t.Context(), cecKey, &ciliumv2.CiliumEnvoyConfig{}))
	})

	t.Run("no error when no CEC exists", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(gw).
			Build()
		r := &gatewayReconciler{
			Client: c,
			logger: hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		}

		require.NoError(t, r.ensureEnvoyConfig(t.Context(), gw, nil))
	})
}

func Test_gatewayReconciler_setListenerStatus(t *testing.T) {
	tests := []struct {
		name          string
		listeners     []gatewayv1.Listener
		wantStatus    ListenersStatus
		wantListeners map[gatewayv1.SectionName]metav1.Condition
	}{
		{
			name: "all listeners valid",
			listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "https",
					Port:     443,
					Protocol: gatewayv1.HTTPSProtocolType,
					TLS: &gatewayv1.ListenerTLSConfig{
						Mode: ptr.To(gatewayv1.TLSModeTerminate),
					},
				},
			},
			wantStatus: ListenersStatusAllValid,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"http": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
				"https": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
			},
		},
		{
			name: "only unsupported protocol",
			listeners: []gatewayv1.Listener{{
				Name:     "invalid",
				Port:     1111,
				Protocol: gatewayv1.ProtocolType("INVALID"),
			}},
			wantStatus: ListenersStatusNoneValid,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"invalid": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonUnsupportedProtocol),
				},
			},
		},
		{
			name: "valid listener with unsupported protocol listener",
			listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "invalid",
					Port:     1111,
					Protocol: gatewayv1.ProtocolType("INVALID"),
				},
			},
			wantStatus: ListenersStatusValidWithUnsupportedProtocol,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"http": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
				"invalid": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonUnsupportedProtocol),
				},
			},
		},
		{
			name: "valid listener with invalid route kind listener",
			listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Port:     80,
					Protocol: gatewayv1.HTTPProtocolType,
				},
				{
					Name:     "invalid-route-kind",
					Port:     81,
					Protocol: gatewayv1.HTTPProtocolType,
					AllowedRoutes: &gatewayv1.AllowedRoutes{
						Kinds: []gatewayv1.RouteGroupKind{{
							Kind: "InvalidRouteKind",
						}},
					},
				},
			},
			wantStatus: ListenersStatusSomeInvalid,
			wantListeners: map[gatewayv1.SectionName]metav1.Condition{
				"http": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionTrue,
					Reason: string(gatewayv1.ListenerReasonAccepted),
				},
				"invalid-route-kind": {
					Type:   string(gatewayv1.ListenerConditionAccepted),
					Status: metav1.ConditionFalse,
					Reason: string(gatewayv1.ListenerReasonInvalid),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{
					Name:       "gateway",
					Namespace:  "gateway-conformance-infra",
					Generation: 1,
				},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "cilium",
					Listeners:        tt.listeners,
				},
			}

			r := &gatewayReconciler{
				Client: fake.NewClientBuilder().
					WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
					Build(),
			}

			gotStatus, err := r.setListenerStatus(
				t.Context(),
				gw,
				&gatewayv1.HTTPRouteList{},
				&gatewayv1.TLSRouteList{},
				&gatewayv1.GRPCRouteList{},
				&gatewayv1.TCPRouteList{},
				&gatewayv1.UDPRouteList{},
				helpers.NewNamespaceLabelIndex(nil),
			)
			require.NoError(t, err)
			require.Equal(t, tt.wantStatus, gotStatus)

			for name, wantCond := range tt.wantListeners {
				gotCond := listenerStatusCondition(t, gw.Status.Listeners, name, string(gatewayv1.ListenerConditionAccepted))
				require.Equal(t, wantCond.Status, gotCond.Status)
				require.Equal(t, wantCond.Reason, gotCond.Reason)
			}
		})
	}
}

func Test_gatewayReconciler_Reconcile_gatewayAuthPolicyProvidersUpdatesAndRotation(t *testing.T) {
	t.Parallel()

	oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{
			"authorization_endpoint":"` + oidcServerURLPlaceholder + `/authorize",
			"token_endpoint":"` + oidcServerURLPlaceholder + `/token",
			"userinfo_endpoint":"` + oidcServerURLPlaceholder + `/userinfo",
			"jwks_uri":"` + oidcServerURLPlaceholder + `/jwks.json"
		}`))
	}))
	defer oidcServer.Close()

	discoveryBody := strings.ReplaceAll(`{
		"authorization_endpoint":"`+oidcServerURLPlaceholder+`/authorize",
		"token_endpoint":"`+oidcServerURLPlaceholder+`/token",
		"userinfo_endpoint":"`+oidcServerURLPlaceholder+`/userinfo",
		"jwks_uri":"`+oidcServerURLPlaceholder+`/jwks.json"
	}`, oidcServerURLPlaceholder, oidcServer.URL)
	oidcServer.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(discoveryBody))
	})

	gwClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec: gatewayv1.GatewayClassSpec{
			ControllerName: gatewayv1.GatewayController(defaultControllerName),
		},
	}
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "auth-gateway",
			Namespace: "default",
			UID:       types.UID("auth-gateway"),
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{{
				Name:     "http",
				Port:     80,
				Protocol: gatewayv1.HTTPProtocolType,
			}},
		},
	}
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}

	httpRoute := func(name, path string) *gatewayv1.HTTPRoute {
		return &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: "default",
			},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{{Name: gatewayv1.ObjectName(gw.Name)}},
				},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptr.To(gatewayv1.PathMatchPathPrefix),
							Value: ptr.To(path),
						},
					}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: gatewayv1.ObjectName(service.Name),
								Port: ptr.To(gatewayv1.PortNumber(8080)),
							},
						},
					}},
				}},
			},
		}
	}

	basicRoute := httpRoute("basic-route", "/basic")
	apiKeyRoute := httpRoute("apikey-route", "/apikey")
	jwtRoute := httpRoute("jwt-route", "/jwt")
	oidcRoute := httpRoute("oidc-route", "/oidc")
	authzRoute := httpRoute("authz-route", "/authz")

	basicSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "basic-secret", Namespace: "default"},
		Data:       map[string][]byte{"auth": []byte("alice:$apr1$hash")},
	}
	apiKeySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "api-key-secret", Namespace: "default"},
		Data:       map[string][]byte{"token": []byte("secret-a")},
	}
	oidcClientSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-client", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("client-secret")},
	}
	oidcCookieSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-cookie", Namespace: "default"},
		Data:       map[string][]byte{"secret": []byte("cookie-secret")},
	}
	jwksConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "jwt-jwks", Namespace: "default"},
		Data: map[string]string{
			"jwks.json": `{"keys":[{"kty":"RSA","kid":"1","n":"abc","e":"AQAB"}]}`,
		},
	}

	targetRoute := func(routeName string) []gatewayv1.LocalPolicyTargetReferenceWithSectionName {
		return []gatewayv1.LocalPolicyTargetReferenceWithSectionName{{
			LocalPolicyTargetReference: gatewayv1.LocalPolicyTargetReference{
				Group: gatewayv1.Group(gatewayv1.GroupName),
				Kind:  gatewayv1.Kind("HTTPRoute"),
				Name:  gatewayv1.ObjectName(routeName),
			},
		}}
	}

	basicPolicy := &v2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "basic-policy", Namespace: "default"},
		Spec: v2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: targetRoute(basicRoute.Name),
			BasicAuth: &v2alpha1.CiliumGatewayBasicAuth{
				Secret: v2alpha1.CiliumGatewaySecretKeyRef{Name: basicSecret.Name, Key: "auth"},
			},
		},
	}
	apiKeyPolicy := &v2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "apikey-policy", Namespace: "default"},
		Spec: v2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: targetRoute(apiKeyRoute.Name),
			APIKeyAuth: &v2alpha1.CiliumGatewayAPIKeyAuth{
				Sources: []v2alpha1.CiliumGatewayAPIKeySource{{
					Type: v2alpha1.CiliumGatewayAPIKeySourceHeader,
					Name: "x-api-key",
				}},
				Credentials: []v2alpha1.CiliumGatewayAPIKeyCredentialRef{{
					Secret:   v2alpha1.CiliumGatewaySecretKeyRef{Name: apiKeySecret.Name, Key: "token"},
					Identity: ptr.To("client-a"),
				}},
				IdentityHeader:  ptr.To("x-identity"),
				StripCredential: ptr.To(true),
			},
		},
	}
	jwtPolicy := &v2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "jwt-policy", Namespace: "default"},
		Spec: v2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: targetRoute(jwtRoute.Name),
			JWT: &v2alpha1.CiliumGatewayJWTAuth{
				Issuer:    "https://issuer.example.com",
				Audiences: []string{"aud-a"},
				LocalJWKS: &v2alpha1.CiliumGatewayLocalJWKS{
					ConfigMap: &v2alpha1.CiliumGatewayConfigMapKeyRef{Name: jwksConfigMap.Name, Key: "jwks.json"},
				},
			},
		},
	}
	oidcPolicy := &v2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-policy", Namespace: "default"},
		Spec: v2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: targetRoute(oidcRoute.Name),
			OIDC: &v2alpha1.CiliumGatewayOIDCAuth{
				Issuer:       oidcServer.URL,
				ClientID:     "client-id",
				ClientSecret: v2alpha1.CiliumGatewaySecretKeyRef{Name: oidcClientSecret.Name, Key: "secret"},
				CookieSecret: v2alpha1.CiliumGatewaySecretKeyRef{Name: oidcCookieSecret.Name, Key: "secret"},
				Scopes:       []string{"openid"},
			},
		},
	}
	authzPolicy := &v2alpha1.CiliumGatewayAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "authz-policy", Namespace: "default"},
		Spec: v2alpha1.CiliumGatewayAuthPolicySpec{
			TargetRefs: targetRoute(authzRoute.Name),
			Authorization: &v2alpha1.CiliumGatewayAuthorizationPolicy{
				Rules: []v2alpha1.CiliumGatewayAuthorizationRule{{
					Methods: []string{"GET"},
					Paths:   []string{"/authz"},
					Headers: []v2alpha1.CiliumGatewayMatchAttribute{{
						Name:   "x-role",
						Values: []string{"admin"},
					}},
				}},
			},
		},
	}

	r, c := gatewayAuthPolicyTestReconciler(t, oidcServer.Client(),
		gwClass,
		gw,
		service,
		basicRoute,
		apiKeyRoute,
		jwtRoute,
		oidcRoute,
		authzRoute,
		basicSecret,
		apiKeySecret,
		oidcClientSecret,
		oidcCookieSecret,
		jwksConfigMap,
		basicPolicy,
		apiKeyPolicy,
		jwtPolicy,
		oidcPolicy,
		authzPolicy,
	)

	_, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	cec := &ciliumv2.CiliumEnvoyConfig{}
	cecKey := types.NamespacedName{
		Namespace: gw.Namespace,
		Name:      shortener.ShortenK8sResourceName(gatewayApiTranslation.CiliumGatewayPrefix + gw.Name),
	}
	require.NoError(t, c.Get(t.Context(), cecKey, cec))

	listener, routeConfig, clusters := gatewayAuthResourcesFromCEC(t, cec)
	require.Equal(t, []string{
		"envoy.filters.http.grpc_web",
		"envoy.filters.http.grpc_stats",
		"envoy.filters.http.basic_auth/default",
		translation.APIKeyAuthFilterName,
		"envoy.filters.http.oauth2/default/oidc-policy",
		translation.JWTAuthFilterName,
		translation.GatewayAuthorizationFilterName,
		"envoy.filters.http.router",
	}, httpFilterNames(listener.GetHttpFilters()))
	require.Contains(t, clusters, "default:echo:8080")
	require.Contains(t, clusters, "oidc:"+strings.TrimPrefix(oidcServer.URL, "http://")+":80")

	routesByPrefix := gatewayAuthRoutesByPrefix(routeConfig)

	basicRouteConfig := routesByPrefix["/basic"]
	require.NotNil(t, basicRouteConfig)
	basicPerRoute := &basicauthv3.BasicAuthPerRoute{}
	require.NoError(t, proto.Unmarshal(basicRouteConfig.GetTypedPerFilterConfig()["envoy.filters.http.basic_auth/default"].GetValue(), basicPerRoute))
	require.Equal(t, "alice:$apr1$hash", basicPerRoute.GetUsers().GetInlineString())

	apiKeyRouteConfig := routesByPrefix["/apikey"]
	require.NotNil(t, apiKeyRouteConfig)
	apiKeyPerRoute := &luav3.LuaPerRoute{}
	require.NoError(t, proto.Unmarshal(apiKeyRouteConfig.GetTypedPerFilterConfig()[translation.APIKeyAuthFilterName].GetValue(), apiKeyPerRoute))
	require.Equal(t, "x-identity", apiKeyPerRoute.GetFilterContext().GetFields()["identity_header"].GetStringValue())

	jwtRouteConfig := routesByPrefix["/jwt"]
	require.NotNil(t, jwtRouteConfig)
	jwtPerRoute := &jwtauthnv3.PerRouteConfig{}
	require.NoError(t, proto.Unmarshal(jwtRouteConfig.GetTypedPerFilterConfig()[translation.JWTAuthFilterName].GetValue(), jwtPerRoute))
	require.Equal(t, "default/jwt-policy", jwtPerRoute.GetRequirementName())

	oidcRouteConfig := routesByPrefix["/oidc"]
	require.NotNil(t, oidcRouteConfig)
	_, hasOIDCOverride := oidcRouteConfig.GetTypedPerFilterConfig()["envoy.filters.http.oauth2/default/oidc-policy"]
	require.False(t, hasOIDCOverride)
	oauth2Filter := &oauth2v3.OAuth2{}
	require.NoError(t, proto.Unmarshal(listener.GetHttpFilters()[4].GetTypedConfig().GetValue(), oauth2Filter))
	require.Equal(t, "client-id", oauth2Filter.GetConfig().GetCredentials().GetClientId())

	authzRouteConfig := routesByPrefix["/authz"]
	require.NotNil(t, authzRouteConfig)
	authzPerRoute := &rbacv3.RBACPerRoute{}
	require.NoError(t, proto.Unmarshal(authzRouteConfig.GetTypedPerFilterConfig()[translation.GatewayAuthorizationFilterName].GetValue(), authzPerRoute))
	require.NotNil(t, authzPerRoute.GetRbac())
	require.Contains(t, authzPerRoute.GetRbac().GetRules().GetPolicies(), "rule-0")

	for _, key := range []types.NamespacedName{
		client.ObjectKeyFromObject(basicPolicy),
		client.ObjectKeyFromObject(apiKeyPolicy),
		client.ObjectKeyFromObject(jwtPolicy),
		client.ObjectKeyFromObject(oidcPolicy),
		client.ObjectKeyFromObject(authzPolicy),
	} {
		assertGatewayAuthPolicyConditions(t, c, key, metav1.ConditionTrue, metav1.ConditionTrue)
	}

	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(basicSecret), basicSecret))
	basicSecret.Data["auth"] = []byte{}
	require.NoError(t, c.Update(t.Context(), basicSecret))

	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	require.NoError(t, c.Get(t.Context(), cecKey, cec))
	_, routeConfig, _ = gatewayAuthResourcesFromCEC(t, cec)
	routesByPrefix = gatewayAuthRoutesByPrefix(routeConfig)

	basicFailClosed := &rbacv3.RBACPerRoute{}
	require.NoError(t, proto.Unmarshal(routesByPrefix["/basic"].GetTypedPerFilterConfig()[translation.GatewayAuthorizationFilterName].GetValue(), basicFailClosed))
	require.NotNil(t, basicFailClosed.GetRbac())
	require.Empty(t, basicFailClosed.GetRbac().GetRules().GetPolicies())
	assertGatewayAuthPolicyConditions(t, c, client.ObjectKeyFromObject(basicPolicy), metav1.ConditionTrue, metav1.ConditionFalse)

	require.NoError(t, c.Get(t.Context(), client.ObjectKeyFromObject(basicPolicy), basicPolicy))
	basicPolicy.Spec.BasicAuth = nil
	basicPolicy.Spec.JWT = &v2alpha1.CiliumGatewayJWTAuth{
		Issuer: "https://issuer.example.com",
		LocalJWKS: &v2alpha1.CiliumGatewayLocalJWKS{
			ConfigMap: &v2alpha1.CiliumGatewayConfigMapKeyRef{Name: jwksConfigMap.Name, Key: "jwks.json"},
		},
	}
	require.NoError(t, c.Update(t.Context(), basicPolicy))

	_, err = r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(gw)})
	require.NoError(t, err)

	require.NoError(t, c.Get(t.Context(), cecKey, cec))
	_, routeConfig, _ = gatewayAuthResourcesFromCEC(t, cec)
	routesByPrefix = gatewayAuthRoutesByPrefix(routeConfig)

	updatedBasicRoute := routesByPrefix["/basic"]
	_, hasBasicAuth := updatedBasicRoute.GetTypedPerFilterConfig()["envoy.filters.http.basic_auth/default"]
	require.False(t, hasBasicAuth)
	updatedJWTPerRoute := &jwtauthnv3.PerRouteConfig{}
	require.NoError(t, proto.Unmarshal(updatedBasicRoute.GetTypedPerFilterConfig()[translation.JWTAuthFilterName].GetValue(), updatedJWTPerRoute))
	require.Equal(t, "default/basic-policy", updatedJWTPerRoute.GetRequirementName())
	assertGatewayAuthPolicyConditions(t, c, client.ObjectKeyFromObject(basicPolicy), metav1.ConditionTrue, metav1.ConditionTrue)
}

const oidcServerURLPlaceholder = "__OIDC_SERVER__"

func gatewayAuthPolicyTestReconciler(t *testing.T, oidcClient *http.Client, objects ...client.Object) (*gatewayReconciler, client.WithWatch) {
	t.Helper()

	builder := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(nil)).
		WithObjects(objects...).
		WithStatusSubresource(&gatewayv1.Gateway{}).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}).
		WithStatusSubresource(&gatewayv1.GRPCRoute{}).
		WithStatusSubresource(&gatewayv1.TLSRoute{}).
		WithStatusSubresource(&v2alpha1.CiliumGatewayAuthPolicy{})

	builder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.GatewayHTTPRouteIndex, indexers.IndexHTTPRouteByGateway)
	builder.WithIndex(&gatewayv1.HTTPRoute{}, indexers.BackendServiceHTTPRouteIndex, fakeIndexHTTPRouteByBackendService)
	builder.WithIndex(&gatewayv1.GRPCRoute{}, indexers.GatewayGRPCRouteIndex, indexers.IndexGRPCRouteByGateway)
	builder.WithIndex(&gatewayv1.TLSRoute{}, indexers.GatewayTLSRouteIndex, indexers.IndexTLSRouteByGateway)
	builder.WithIndex(&v2alpha1.CiliumGatewayAuthPolicy{}, indexers.GatewayAuthPolicyGatewayTargetIndex, indexers.IndexCiliumGatewayAuthPolicyByGateway)
	builder.WithIndex(&v2alpha1.CiliumGatewayAuthPolicy{}, indexers.GatewayAuthPolicyHTTPRouteTargetIndex, indexers.IndexCiliumGatewayAuthPolicyByHTTPRoute)
	builder.WithIndex(&v2alpha1.CiliumGatewayAuthPolicy{}, indexers.GatewayAuthPolicyGRPCRouteTargetIndex, indexers.IndexCiliumGatewayAuthPolicyByGRPCRoute)

	c := builder.Build()
	cecTranslator := translation.NewCECTranslator(translation.Config{
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
		OriginalIPDetectionConfig: translation.OriginalIPDetectionConfig{
			UseRemoteAddress: true,
		},
	})
	return &gatewayReconciler{
		Client:                     c,
		translator:                 gatewayApiTranslation.NewTranslator(cecTranslator, translation.Config{}),
		logger:                     hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)),
		controllerName:             defaultControllerName,
		enableGatewayAPIAuthPolicy: true,
		oidcDiscoveryClient:        oidcClient,
		oidcDiscoveryCache:         newOIDCDiscoveryCache(oidcDiscoveryCacheTTL),
	}, c
}

func gatewayAuthResourcesFromCEC(t *testing.T, cec *ciliumv2.CiliumEnvoyConfig) (*httpConnectionManagerv3.HttpConnectionManager, *envoy_config_route_v3.RouteConfiguration, map[string]struct{}) {
	t.Helper()

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
	return listener, routeConfig, clusterNames
}

func gatewayAuthRoutesByPrefix(routeConfig *envoy_config_route_v3.RouteConfiguration) map[string]*envoy_config_route_v3.Route {
	routesByPrefix := map[string]*envoy_config_route_v3.Route{}
	for _, virtualHost := range routeConfig.GetVirtualHosts() {
		for _, route := range virtualHost.GetRoutes() {
			routesByPrefix[route.GetMatch().GetPathSeparatedPrefix()] = route
		}
	}
	return routesByPrefix
}

func httpFilterNames(filters []*httpConnectionManagerv3.HttpFilter) []string {
	names := make([]string, 0, len(filters))
	for _, filter := range filters {
		names = append(names, filter.Name)
	}
	return names
}

func assertGatewayAuthPolicyConditions(t *testing.T, c client.Client, key types.NamespacedName, wantAccepted, wantResolved metav1.ConditionStatus) {
	t.Helper()

	policy := &v2alpha1.CiliumGatewayAuthPolicy{}
	require.NoError(t, c.Get(t.Context(), key, policy))
	require.NotEmpty(t, policy.Status.Ancestors)

	var acceptedStatus, resolvedStatus metav1.ConditionStatus
	for _, condition := range policy.Status.Ancestors[0].Conditions {
		switch condition.Type {
		case string(gatewayv1.PolicyConditionAccepted):
			acceptedStatus = condition.Status
		case string(gatewayv1.RouteConditionResolvedRefs):
			resolvedStatus = condition.Status
		}
	}

	require.Equal(t, wantAccepted, acceptedStatus)
	require.Equal(t, wantResolved, resolvedStatus)
}

func listenerStatusCondition(t *testing.T, listeners []gatewayv1.ListenerStatus, name gatewayv1.SectionName, conditionType string) metav1.Condition {
	t.Helper()

	for _, listener := range listeners {
		if listener.Name != name {
			continue
		}
		for _, cond := range listener.Conditions {
			if cond.Type == conditionType {
				return cond
			}
		}
		require.Failf(t, "missing listener condition", "listener %q condition %q not found", name, conditionType)
	}

	require.Failf(t, "missing listener status", "listener %q not found", name)
	return metav1.Condition{}
}

func filterHTTPRoute(hrList *gatewayv1.HTTPRouteList, gatewayName string, namespace string) []gatewayv1.HTTPRoute {
	var filterList []gatewayv1.HTTPRoute
	for _, hr := range hrList.Items {
		if len(hr.Spec.CommonRouteSpec.ParentRefs) > 0 {
			for _, parentRef := range hr.Spec.CommonRouteSpec.ParentRefs {
				if string(parentRef.Name) == gatewayName &&
					((parentRef.Namespace == nil && hr.Namespace == namespace) || string(*parentRef.Namespace) == namespace) {
					filterList = append(filterList, hr)
					break
				}
			}
		}
	}
	return filterList
}

func filterGRPCRoute(hrList *gatewayv1.GRPCRouteList, gatewayName string, namespace string) []gatewayv1.GRPCRoute {
	var filterList []gatewayv1.GRPCRoute
	for _, grpcr := range hrList.Items {
		if len(grpcr.Spec.CommonRouteSpec.ParentRefs) > 0 {
			for _, parentRef := range grpcr.Spec.CommonRouteSpec.ParentRefs {
				if string(parentRef.Name) == gatewayName &&
					((parentRef.Namespace == nil && grpcr.Namespace == namespace) || string(*parentRef.Namespace) == namespace) {
					filterList = append(filterList, grpcr)
					break
				}
			}
		}
	}
	return filterList
}

func Test_sectionNameMatched(t *testing.T) {
	httpListener := &gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	httpNoMatchListener := &gatewayv1.Listener{
		Name:     "http-no-match",
		Port:     8080,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	gw := &gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				*httpListener,
				*httpNoMatchListener,
			},
		},
	}
	type args struct {
		routeNamespace string
		listener       *gatewayv1.Listener
		refs           []gatewayv1.ParentReference
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Matching Section name",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					},
				},
			},
			want: true,
		},
		{
			name: "Not matching Section name",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					},
				},
			},
			want: false,
		},
		{
			name: "Matching Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
						Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: true,
		},
		{
			name: "No matching Port number",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
						Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: false,
		},
		{
			name: "Matching both Section name and Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name:        "valid-gateway",
						SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
						Port:        (*gatewayv1.PortNumber)(ptr.To[int32](80)),
					},
				},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpListener)",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
					},
				},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpNoMatchListener)",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
						Name: "valid-gateway",
					},
				},
			},
			want: true,
		},
		{
			name: "GAMMA Service with same name as Gateway should not match",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{
					{
						Kind:  (*gatewayv1.Kind)(ptr.To("Service")),
						Group: (*gatewayv1.Group)(ptr.To("")),
						Name:  "valid-gateway",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, parentRefMatched(gw, tt.args.listener, nil, "default", tt.args.refs), "parentRefMatched(%v, %v, %v, %v)", gw, tt.args.listener, tt.args.routeNamespace, tt.args.refs)
		})
	}
}

// fakeIndexHTTPRouteByBackendService is a client.IndexerFunc that takes a single HTTPRoute and
// returns all referenced backend service full names (`namespace/name`) to add to the relevant index.
//
// The actual indexer does some dereferencing lookups in order to handle some ServiceImport
// behaviors correctly. This one is what that indexer used to look like before we added ServiceImport
// support.
func fakeIndexHTTPRouteByBackendService(rawObj client.Object) []string {
	route, ok := rawObj.(*gatewayv1.HTTPRoute)
	if !ok {
		return nil
	}
	var backendServices []string

	for _, rule := range route.Spec.Rules {
		for _, backend := range rule.BackendRefs {
			if !helpers.IsService(backend.BackendObjectReference) {
				continue
			}
			namespace := helpers.NamespaceDerefOr(backend.Namespace, route.Namespace)
			backendServices = append(
				backendServices,
				types.NamespacedName{
					Namespace: namespace,
					Name:      string(backend.Name),
				}.String(),
			)
		}
	}
	return backendServices
}

func testReconciler(t *testing.T, obj ...client.Object) (*gatewayReconciler, client.WithWatch) {
	t.Helper()

	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	fakeClient := fake.NewClientBuilder().
		WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
		WithObjects(obj...).
		WithStatusSubresource(&gatewayv1.HTTPRoute{}, &gatewayv1.GRPCRoute{}).
		Build()

	reconciler := &gatewayReconciler{
		Client:         fakeClient,
		logger:         logger,
		controllerName: defaultControllerName,
	}

	return reconciler, fakeClient
}

func findRouteAcceptedCondition(conds []metav1.Condition) *metav1.Condition {
	for _, cond := range conds {
		if cond.Type == string(gatewayv1.RouteConditionAccepted) {
			return &cond
		}
	}
	return nil
}

func TestGatewayReconciler_statuses(t *testing.T) {
	ciliumGWClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: gatewayv1.GatewayController(defaultControllerName)},
	}
	otherGWClass := &gatewayv1.GatewayClass{
		ObjectMeta: metav1.ObjectMeta{Name: "other"},
		Spec:       gatewayv1.GatewayClassSpec{ControllerName: "example.com/other-controller"},
	}

	listener := gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Protocol: gatewayv1.HTTPProtocolType,
		AllowedRoutes: &gatewayv1.AllowedRoutes{
			Namespaces: &gatewayv1.RouteNamespaces{From: new(gatewayv1.NamespacesFromAll)},
		},
	}

	ciliumGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "cilium-gw", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "cilium", Listeners: []gatewayv1.Listener{listener}},
	}
	otherGW := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "other-gw", Namespace: "default"},
		Spec:       gatewayv1.GatewaySpec{GatewayClassName: "other", Listeners: []gatewayv1.Listener{listener}},
	}

	t.Run("setHTTPRouteStatuses sets related parent statuses", func(t *testing.T) {
		ctx := t.Context()

		validRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  new(gatewayv1.PathMatchRegularExpression),
							Value: new("^/api/v1$"),
						},
					}},
				}},
			},
		}

		invalidRoute := &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid-route", Namespace: "default"},
			Spec: gatewayv1.HTTPRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.HTTPRouteRule{{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  new(gatewayv1.PathMatchRegularExpression),
							Value: new("[invalid"),
						},
					}},
				}},
			},
		}

		r, c := testReconciler(t, ciliumGWClass, ciliumGW, otherGWClass, otherGW, validRoute, invalidRoute)

		hrList := &gatewayv1.HTTPRouteList{}
		require.NoError(t, c.List(ctx, hrList))
		require.NoError(t, r.setHTTPRouteStatuses(r.logger, ctx, hrList, &gatewayv1.ReferenceGrantList{}))

		var updatedValidRoute, updatedInvalidRoute gatewayv1.HTTPRoute
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: validRoute.Name, Namespace: validRoute.Namespace}, &updatedValidRoute))
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: invalidRoute.Name, Namespace: invalidRoute.Namespace}, &updatedInvalidRoute))

		require.Len(t, updatedValidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedValidRoute.Status.Parents[0].ControllerName)

		validAcceptedCond := findRouteAcceptedCondition(updatedValidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, validAcceptedCond)
		assert.Equal(t, metav1.ConditionTrue, validAcceptedCond.Status)

		require.Len(t, updatedInvalidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedInvalidRoute.Status.Parents[0].ControllerName)

		invalidAcceptedCond := findRouteAcceptedCondition(updatedInvalidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, invalidAcceptedCond)
		assert.Equal(t, metav1.ConditionFalse, invalidAcceptedCond.Status)
	})

	t.Run("setGRPCRouteStatuses sets related parent statuses", func(t *testing.T) {
		ctx := t.Context()

		validRoute := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "route", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.GRPCRouteRule{{
					Matches: []gatewayv1.GRPCRouteMatch{{
						Method: &gatewayv1.GRPCMethodMatch{
							Type:    new(gatewayv1.GRPCMethodMatchRegularExpression),
							Service: new("^ordersV[12]$"),
						},
					}},
				}},
			},
		}

		invalidRoute := &gatewayv1.GRPCRoute{
			ObjectMeta: metav1.ObjectMeta{Name: "invalid-route", Namespace: "default"},
			Spec: gatewayv1.GRPCRouteSpec{
				CommonRouteSpec: gatewayv1.CommonRouteSpec{
					ParentRefs: []gatewayv1.ParentReference{
						{Name: gatewayv1.ObjectName(ciliumGW.Name)},
						{Name: gatewayv1.ObjectName(otherGW.Name)},
					},
				},
				Rules: []gatewayv1.GRPCRouteRule{{
					Matches: []gatewayv1.GRPCRouteMatch{{
						Method: &gatewayv1.GRPCMethodMatch{
							Type:    new(gatewayv1.GRPCMethodMatchRegularExpression),
							Service: new("(unclosed"),
						},
					}},
				}},
			},
		}

		r, c := testReconciler(t, ciliumGWClass, ciliumGW, otherGWClass, otherGW, validRoute, invalidRoute)

		hrList := &gatewayv1.GRPCRouteList{}
		require.NoError(t, c.List(ctx, hrList))
		require.NoError(t, r.setGRPCRouteStatuses(r.logger, ctx, hrList, &gatewayv1.ReferenceGrantList{}))

		var updatedValidRoute, updatedInvalidRoute gatewayv1.GRPCRoute
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: validRoute.Name, Namespace: validRoute.Namespace}, &updatedValidRoute))
		require.NoError(t, c.Get(ctx, types.NamespacedName{Name: invalidRoute.Name, Namespace: invalidRoute.Namespace}, &updatedInvalidRoute))

		require.Len(t, updatedValidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedValidRoute.Status.Parents[0].ControllerName)

		validAcceptedCond := findRouteAcceptedCondition(updatedValidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, validAcceptedCond)
		assert.Equal(t, metav1.ConditionTrue, validAcceptedCond.Status)

		require.Len(t, updatedInvalidRoute.Status.Parents, 1, "Should not set status of unrelated parent")
		assert.EqualValues(t, defaultControllerName, updatedInvalidRoute.Status.Parents[0].ControllerName)

		invalidAcceptedCond := findRouteAcceptedCondition(updatedInvalidRoute.Status.Parents[0].Conditions)
		assert.NotNil(t, invalidAcceptedCond)
		assert.Equal(t, metav1.ConditionFalse, invalidAcceptedCond.Status)
	})
}
