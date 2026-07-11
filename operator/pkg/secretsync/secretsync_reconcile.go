// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package secretsync

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	controllerruntime "github.com/cilium/cilium/operator/pkg/controller-runtime"
	gatewayhelpers "github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.12.2/pkg/reconcile
func (r *secretSyncer) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	scopedLog := r.logger.With(
		logfields.Resource, req.NamespacedName,
	)
	scopedLog.DebugContext(ctx, "Reconciling secret")

	original := &corev1.Secret{}
	if err := r.client.Get(ctx, req.NamespacedName, original); err != nil {
		if k8serrors.IsNotFound(err) {
			scopedLog.DebugContext(ctx, "Unable to get Secret - either deleted or not yet available", logfields.Error, err)

			synced := false
			// Check whether synced secret needs to be deleted from the registered secret namespaces.
			for _, ns := range r.secretNamespaces {
				// Check if there's an existing synced secret for the deleted Secret
				deleted, err := r.cleanupSyncedSecret(ctx, req, scopedLog, ns)
				if err != nil {
					return controllerruntime.Fail(err)
				}

				synced = synced || deleted
			}

			scopedLog.DebugContext(ctx, "Successfully reconciled Secret", logfields.Action, action(synced))
			return controllerruntime.Success()
		}

		return controllerruntime.Fail(err)
	}

	cleanupNamespaces := map[string]struct{}{}
	for _, ns := range r.secretNamespaces {
		cleanupNamespaces[ns] = struct{}{}
	}

	synced := false
	for _, reg := range r.registrations {
		if reg.RefObjectCheckFunc(ctx, r.client, r.logger, original) || reg.IsDefaultSecret(original) {
			desiredSyncs := desiredSyncSecrets(reg.SecretsNamespace, original)

			scopedLog.DebugContext(ctx, "Syncing secret", logfields.K8sNamespace, reg.SecretsNamespace)
			desiredNames := make(map[string]struct{}, len(desiredSyncs))
			for _, desiredSync := range desiredSyncs {
				if err := r.ensureSyncedSecret(ctx, desiredSync); err != nil {
					return controllerruntime.Fail(err)
				}
				desiredNames[desiredSync.Name] = struct{}{}
			}
			if err := r.cleanupStaleSyncedSecrets(ctx, original.Namespace, original.Name, reg.SecretsNamespace, desiredNames); err != nil {
				return controllerruntime.Fail(err)
			}

			synced = true
			delete(cleanupNamespaces, reg.SecretsNamespace)
		}
	}

	changed := synced

	// Check whether synced secret needs to be deleted from the secret namespaces
	// where the secret is no longer referenced by any registration.
	for ns := range cleanupNamespaces {
		// Check if there's an existing synced secret that should be deleted
		deleted, err := r.cleanupSyncedSecret(ctx, req, scopedLog, ns)
		if err != nil {
			return controllerruntime.Fail(err)
		}
		changed = changed || deleted
	}

	if synced {
		resync := r.getJitteredResyncInterval()
		scopedLog.DebugContext(ctx, "Successfully reconciled Secret with resync",
			logfields.Action, action(synced),
			logfields.SyncInterval, resync)
		return ctrl.Result{RequeueAfter: resync}, nil
	}

	// If the object wasn't deleted, setup a resync.
	scopedLog.DebugContext(ctx, "Successfully reconciled Secret",
		logfields.Action, action(changed))
	return ctrl.Result{}, nil
}

func (r *secretSyncer) getJitteredResyncInterval() time.Duration {
	// We use the global rand source, as we don't need strong randomness.
	maxJitter := time.Duration(float64(r.resyncInterval) * float64(r.jitterAmount))
	randomJitter := time.Duration(rand.Float64() * float64(maxJitter))
	randomSign := rand.IntN(2)
	if randomSign > 1 {
		return r.resyncInterval + randomJitter
	}

	return r.resyncInterval - randomJitter
}

func action(synced bool) string {
	action := "ignored"
	if synced {
		action = "synced"
	}

	return action
}

func (r *secretSyncer) cleanupSyncedSecret(ctx context.Context, req reconcile.Request, scopedLog *slog.Logger, ns string) (bool, error) {
	secrets := &corev1.SecretList{}
	if err := r.client.List(ctx, secrets, client.InNamespace(ns), client.MatchingLabels{
		OwningSecretNamespace: req.Namespace,
		OwningSecretName:      req.Name,
	}); err != nil {
		return false, err
	}

	deleted := false
	for i := range secrets.Items {
		scopedLog.DebugContext(ctx, "Delete synced secret", logfields.K8sNamespace, ns, logfields.Secret, secrets.Items[i].Name)
		if err := r.client.Delete(ctx, &secrets.Items[i]); err != nil {
			return true, err
		}
		deleted = true
	}

	return deleted, nil
}

func desiredSyncSecret(secretsNamespace string, original *corev1.Secret, name string) *corev1.Secret {
	s := &corev1.Secret{}
	s.SetNamespace(secretsNamespace)
	s.SetName(name)
	s.SetAnnotations(original.GetAnnotations())
	s.SetLabels(original.GetLabels())
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	s.Labels[OwningSecretNamespace] = original.Namespace
	s.Labels[OwningSecretName] = original.Name
	s.Immutable = original.Immutable
	s.Data = original.Data
	s.StringData = original.StringData
	s.Type = original.Type

	return s
}

func desiredSyncSecrets(secretsNamespace string, original *corev1.Secret) []*corev1.Secret {
	desired := []*corev1.Secret{
		desiredSyncSecret(secretsNamespace, original, gatewayhelpers.SyncedSecretName(original.Namespace, original.Name)),
	}

	if original.Type != corev1.SecretTypeOpaque || len(original.Data) <= 1 {
		return desired
	}

	keys := make([]string, 0, len(original.Data))
	for key := range original.Data {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		perKey := desiredSyncSecret(secretsNamespace, original, gatewayhelpers.SyncedSecretKeyName(original.Namespace, original.Name, key))
		perKey.Data = map[string][]byte{
			"generic": original.Data[key],
		}
		perKey.StringData = nil
		desired = append(desired, perKey)
	}

	return desired
}

func (r *secretSyncer) ensureSyncedSecret(ctx context.Context, desired *corev1.Secret) error {
	existing := &corev1.Secret{}
	if err := r.client.Get(ctx, client.ObjectKeyFromObject(desired), existing); err != nil {
		if k8serrors.IsNotFound(err) {
			return r.client.Create(ctx, desired)
		}
		return err
	}

	if existing.Type != desired.Type {
		if err := r.client.Delete(ctx, existing); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
		return r.client.Create(ctx, desired)
	}

	temp := existing.DeepCopy()
	temp.SetAnnotations(desired.GetAnnotations())
	temp.SetLabels(desired.GetLabels())
	temp.Immutable = desired.Immutable
	temp.Data = desired.Data
	temp.StringData = desired.StringData
	temp.Type = desired.Type

	return r.client.Patch(ctx, temp, client.MergeFrom(existing))
}

func (r *secretSyncer) cleanupStaleSyncedSecrets(ctx context.Context, sourceNamespace, sourceName, syncedNamespace string, desiredNames map[string]struct{}) error {
	secrets := &corev1.SecretList{}
	if err := r.client.List(ctx, secrets, client.InNamespace(syncedNamespace), client.MatchingLabels{
		OwningSecretNamespace: sourceNamespace,
		OwningSecretName:      sourceName,
	}); err != nil {
		return err
	}

	for i := range secrets.Items {
		if _, ok := desiredNames[secrets.Items[i].Name]; ok {
			continue
		}
		if err := r.client.Delete(ctx, &secrets.Items[i]); err != nil && !k8serrors.IsNotFound(err) {
			return err
		}
	}

	return nil
}
