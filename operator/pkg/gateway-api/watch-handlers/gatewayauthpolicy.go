// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchhandlers

import (
	"context"
	"log/slog"
	"maps"
	"slices"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// EnqueueRequestForCiliumGatewayAuthPolicy returns reconcile requests for all
// relevant Gateways touched by a CiliumGatewayAuthPolicy targetRef.
func EnqueueRequestForCiliumGatewayAuthPolicy(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-ciliumgatewayauthpolicy")

		policy, ok := o.(*ciliumv2alpha1.CiliumGatewayAuthPolicy)
		if !ok {
			return nil
		}

		allCiliumGatewaysSet, err := getAllCiliumGatewaysSet(ctx, c)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		reconcileRequests := make(map[reconcile.Request]struct{})
		updateReconcileRequestsForCiliumGatewayAuthPolicy(ctx, c, scopedLog, allCiliumGatewaysSet, reconcileRequests, policy)

		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("CiliumGatewayAuthPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return recs
	})
}

// EnqueueRequestForCiliumGatewayAuthPolicySecret returns reconcile requests for
// Gateways affected by Secret changes referenced from CiliumGatewayAuthPolicies.
func EnqueueRequestForCiliumGatewayAuthPolicySecret(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-ciliumgatewayauthpolicy-secret")

		secret, ok := o.(*corev1.Secret)
		if !ok {
			return []reconcile.Request{}
		}

		policyList := &ciliumv2alpha1.CiliumGatewayAuthPolicyList{}
		if err := c.List(ctx, policyList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayAuthPolicySecretIndex, client.ObjectKeyFromObject(secret).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related CiliumGatewayAuthPolicies for Secret", logfields.Error, err)
			return []reconcile.Request{}
		}
		if len(policyList.Items) == 0 {
			return []reconcile.Request{}
		}

		allCiliumGatewaysSet, err := getAllCiliumGatewaysSet(ctx, c)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		reconcileRequests := make(map[reconcile.Request]struct{})
		for i := range policyList.Items {
			updateReconcileRequestsForCiliumGatewayAuthPolicy(ctx, c, scopedLog, allCiliumGatewaysSet, reconcileRequests, &policyList.Items[i])
		}

		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("Secret in CiliumGatewayAuthPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return recs
	})
}

// EnqueueRequestForCiliumGatewayAuthPolicyConfigMap returns reconcile requests
// for Gateways affected by ConfigMap changes referenced from CiliumGatewayAuthPolicies.
func EnqueueRequestForCiliumGatewayAuthPolicyConfigMap(c client.Client, logger *slog.Logger) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(ctx context.Context, o client.Object) []reconcile.Request {
		scopedLog := logger.With(logfields.LogSubsys, "queue-gw-from-ciliumgatewayauthpolicy-configmap")

		cfgMap, ok := o.(*corev1.ConfigMap)
		if !ok {
			return []reconcile.Request{}
		}

		policyList := &ciliumv2alpha1.CiliumGatewayAuthPolicyList{}
		if err := c.List(ctx, policyList, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayAuthPolicyConfigMapIndex, client.ObjectKeyFromObject(cfgMap).String()),
		}); err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get related CiliumGatewayAuthPolicies for ConfigMap", logfields.Error, err)
			return []reconcile.Request{}
		}
		if len(policyList.Items) == 0 {
			return []reconcile.Request{}
		}

		allCiliumGatewaysSet, err := getAllCiliumGatewaysSet(ctx, c)
		if err != nil {
			scopedLog.ErrorContext(ctx, "Failed to get Cilium Gateways", logfields.Error, err)
			return []reconcile.Request{}
		}

		reconcileRequests := make(map[reconcile.Request]struct{})
		for i := range policyList.Items {
			updateReconcileRequestsForCiliumGatewayAuthPolicy(ctx, c, scopedLog, allCiliumGatewaysSet, reconcileRequests, &policyList.Items[i])
		}

		recs := slices.Collect(maps.Keys(reconcileRequests))
		if len(recs) > 0 {
			scopedLog.Debug("ConfigMap in CiliumGatewayAuthPolicy relevant to Gateways",
				logfields.Resource, client.ObjectKeyFromObject(o).String(),
				logfields.Gateway, recs)
		}
		return recs
	})
}

func updateReconcileRequestsForCiliumGatewayAuthPolicy(
	ctx context.Context,
	c client.Client,
	scopedLog *slog.Logger,
	allGatewaysSet map[string]struct{},
	rrSet map[reconcile.Request]struct{},
	policy *ciliumv2alpha1.CiliumGatewayAuthPolicy,
) {
	for _, target := range policy.Spec.TargetRefs {
		targetName := types.NamespacedName{
			Namespace: policy.GetNamespace(),
			Name:      string(target.Name),
		}

		switch target.Kind {
		case "Gateway":
			if _, found := allGatewaysSet[targetName.String()]; found {
				rrSet[reconcile.Request{NamespacedName: targetName}] = struct{}{}
			}
		case "HTTPRoute":
			route := &gatewayv1.HTTPRoute{}
			if err := c.Get(ctx, targetName, route); err != nil {
				if !errors.IsNotFound(err) {
					scopedLog.ErrorContext(ctx, "Failed to get HTTPRoute for CiliumGatewayAuthPolicy", logfields.Error, err)
				}
				continue
			}
			updateReconcileRequestsForParentRefs(ctx, c, route.Spec.ParentRefs, route.Namespace, allGatewaysSet, rrSet)
		case "GRPCRoute":
			route := &gatewayv1.GRPCRoute{}
			if err := c.Get(ctx, targetName, route); err != nil {
				if !errors.IsNotFound(err) {
					scopedLog.ErrorContext(ctx, "Failed to get GRPCRoute for CiliumGatewayAuthPolicy", logfields.Error, err)
				}
				continue
			}
			updateReconcileRequestsForParentRefs(ctx, c, route.Spec.ParentRefs, route.Namespace, allGatewaysSet, rrSet)
		}
	}
}
