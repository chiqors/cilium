Gateway API auth policy (alpha)
###############################

``CiliumGatewayAuthPolicy`` is an alpha Cilium policy surface for native
authentication and authorization on Gateway API traffic.

Enablement
**********

This feature is disabled by default. Enable both Gateway API support and the
auth policy controller before creating ``CiliumGatewayAuthPolicy`` resources.

Helm:

.. code-block:: yaml

   gatewayAPI:
     enabled: true
     authPolicy:
       enabled: true

CLI flags:

* ``--enable-gateway-api-auth-policy``
* ``--enable-gateway-api``

Supported attachments
*********************

``CiliumGatewayAuthPolicy`` can attach to these Gateway API resources:

* ``Gateway``
* ``HTTPRoute``
* ``GRPCRoute``

``sectionName`` targeting is supported where the target resource exposes a
matching listener or rule section.

Supported providers
*******************

The first alpha supports these native provider blocks:

* Basic authentication backed by Kubernetes Secrets containing htpasswd data
* API key authentication backed by Kubernetes Secrets
* JWT validation with local or remote JWKS
* OIDC login flows with operator-resolved discovery metadata
* Authorization rules over principal, claims, headers, method, path, host, and CIDR attributes

Alpha limitations and caveats
*****************************

* This feature is alpha and may change in API shape, validation, and generated Envoy details.
* ``CiliumGatewayAuthPolicy`` is Cilium-specific and is not a portable upstream Gateway API policy.
* Provider combinations are intentionally limited. For example, BasicAuth cannot be combined with API key, JWT, or OIDC in the same policy.
* Invalid references, malformed provider inputs, or unresolved discovery data fail closed for the affected route scope.
* OIDC discovery and remote JWKS add runtime dependency on external HTTPS endpoints.

Secret handling
***************

Credential material remains rooted in Kubernetes Secrets and ConfigMaps, but
some providers require resolved values to be rendered into generated Envoy
configuration.

Keep these boundaries in mind:

* Restrict read access to policy-referenced Secrets and ConfigMaps.
* Treat the Gateway API secrets namespace and generated CEC access as sensitive operational surfaces.
* Rotate referenced credentials carefully and monitor policy ``ResolvedRefs`` conditions during rollout.
* For OIDC and JWT local JWKS, ensure referenced Secret or ConfigMap keys stay populated during updates to avoid fail-closed traffic denial.

Rollout guidance
****************

Start with a narrow blast radius:

* Enable the feature in a non-production or canary environment first.
* Attach policies to a single route before expanding to shared Gateway listeners.
* Watch ``Accepted`` and ``ResolvedRefs`` conditions on ``CiliumGatewayAuthPolicy`` objects during rollout.
* Confirm that referenced Secrets, ConfigMaps, and OIDC discovery endpoints are reachable before widening scope.
* Plan for fail-closed behavior during secret rotation, policy edits, or upstream identity provider outages.
