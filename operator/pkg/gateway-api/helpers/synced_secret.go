// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/shortener"
)

// SyncedSecretName returns the mirrored secret name used in the sync namespace.
func SyncedSecretName(namespace, name string) string {
	return fmt.Sprintf("%s-%s", namespace, name)
}

// SyncedSecretKeyName returns the mirrored secret name for a specific source key.
func SyncedSecretKeyName(namespace, name, key string) string {
	if key == "" {
		return SyncedSecretName(namespace, name)
	}
	return shortener.ShortenK8sResourceName(fmt.Sprintf("%s-%s-%s", namespace, name, sanitizeSecretKeyForName(key)))
}

func sanitizeSecretKeyForName(key string) string {
	key = strings.ToLower(key)
	var b strings.Builder
	b.Grow(len(key))
	lastDash := false

	for _, r := range key {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '.'
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}

	sanitized := strings.Trim(b.String(), "-.")
	if sanitized == "" {
		return "key"
	}
	return sanitized
}
