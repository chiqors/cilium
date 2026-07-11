// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package predicates

import (
	"context"
	"log/slog"

	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/operator/pkg/gateway-api/indexers"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

func SecretUsedInGatewayFn(c client.Client, controllerName string, logger *slog.Logger) func(obj client.Object) bool {
	return func(obj client.Object) bool {
		return len(helpers.GetGatewaysForSecret(context.Background(), c, obj, controllerName, logger)) > 0
	}
}

func SecretReferencedByCiliumGatewayAuthPolicyFn(c client.Client, logger *slog.Logger) func(obj client.Object) bool {
	return func(obj client.Object) bool {
		list := &ciliumv2alpha1.CiliumGatewayAuthPolicyList{}
		if err := c.List(context.Background(), list, &client.ListOptions{
			FieldSelector: fields.OneTermEqualSelector(indexers.GatewayAuthPolicySecretIndex, client.ObjectKeyFromObject(obj).String()),
		}); err != nil {
			logger.ErrorContext(context.Background(), "Failed to list CiliumGatewayAuthPolicies for Secret predicate", "error", err)
			return false
		}
		return len(list.Items) > 0
	}
}
