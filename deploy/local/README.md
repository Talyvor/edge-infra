# Local standup (`deploy/local/`)

Reproducible, scripted standup of the **full edge-infra stack** on a local
[kind](https://kind.sigs.k8s.io/) cluster, ending at a **routable gateway serving
two tenant backends** with `ext_authz` **ON** (the chart default). This is the
infra foundation the security proofs build on.

```
git clone … && cd edge-infra
make kind-e2e             # ONE command: create cluster, run every phase, delete cluster
make release-e2e          # the same, on the registry images the charts pin (nothing built)
make kind-cutover         # the CFG-1 launch-day cutover, in order, on its own cluster
make kind-rollback        # the ext_authz rollback, from the cutover state, on its own cluster
deploy/local/up.sh        # stand everything up (idempotent, re-runnable)
deploy/local/down.sh      # tear the cluster down
```

`make kind-e2e` (`deploy/local/e2e.sh`) creates its own cluster (`edge-e2e`), runs all of
`up.sh`, and deletes the cluster whether the run passed or failed (`KEEP_CLUSTER=1` keeps it
for debugging). CI runs it on every change to a chart, `k8s/` or this
directory (`.github/workflows/kind-e2e.yaml`). Which self-host page claim each phase proves:
[docs/self-host-claims.md](../../docs/self-host-claims.md).

`make release-e2e` runs the same phases on a release instead of the working tree: it builds
nothing, and pulls every first-party image at the one tag the charts pin — so pin them first,
`bash deploy/hack/release-pin.sh <tag>` (and `docker login ghcr.io`: two of the eight packages
are private). `.github/workflows/release.yaml` does exactly that every night: it builds and
pushes all eight images at main's HEAD, pins every chart to that SHA, runs `release-e2e`, and
uploads the pinned charts, versioned `0.0.0-g<sha12>`, as the run's `edge-charts-<version>`
artifact.

A release is a SemVer git tag: `git tag v1.2.3 && git push origin v1.2.3`. The same workflow
then also pushes every image as `:1.2.3` (next to `:<sha>`), pins the charts to `:1.2.3`, checks
that each pulled image carries the labels `org.opencontainers.image.version=1.2.3` and
`.revision=<sha>`, packages every chart as version 1.2.3, fails unless the packaged version
equals the tag (`deploy/hack/release-version.sh --check`), and attaches the charts to the GitHub
release `v1.2.3`. `make release-version-test` checks the tag-to-version mapping without a tag.

`make kind-cutover` (`deploy/local/cutover.sh`) rehearses the launch-day order on its own
cluster (`edge-cutover`): main as committed (the control-plane image pin, which serves
nothing), image bump, auth-service with JWKS and mTLS, client certificate, enable. After every
step it checks that tenant routes still answer 200, that a jwt route is never served without a
valid token, and that the fleet is not frozen on last-good. CI runs it on the same paths
(`.github/workflows/kind-cutover.yaml`). The real-cluster steps are
[docs/ext-authz-launch-runbook.md](../../docs/ext-authz-launch-runbook.md).

`make kind-rollback` (`deploy/local/rollback.sh`) runs the same steps on its own cluster
(`edge-rollback`), records what the gateway serves just before the enable, then takes the
auth-service down with ext_authz on. It shows that flipping `extAuthz.enabled` back alone leaves
every gated request denied, and that the full revert (jwt routes out first, then the control-plane
release back to its pre-enable revision) restores exactly the pre-enable traffic and xDS version.
CI runs it on the same paths (`.github/workflows/kind-rollback.yaml`).

The end state: a request to the node's published **:443** for each tenant's host
reaches **that tenant's** backend.

```
curl -H 'Host: tenant-a.local' http://localhost:443/    # -> 200 TENANT-A-BACKEND
curl -H 'Host: tenant-b.local' http://localhost:443/    # -> 200 TENANT-B-BACKEND
curl -H 'Host: nope.local'     http://localhost:443/    # -> 404 (no route)
```

## Prerequisites (host toolchain)

`docker` (Docker Desktop, **≥ ~6–8 GiB** free — this stack is heavy: Calico +
cert-manager + Kyverno + Postgres + NATS + 7 app charts), `kind`, `kubectl`,
`helm` **v3+**, `jq`, `openssl`, `go`, and a Rust toolchain is **not** required on
the host (auth-service builds in-container). `up.sh` checks for the required
binaries and stops with a precise message if one is missing.

Host ports **80** and **443** must be free — a worker publishes them.

Dependency manifests (Calico, cert-manager, Kyverno) and the csi-driver-spiffe
chart are fetched from pinned upstream URLs at run time, so the first run needs
network access.

## Usage

```bash
deploy/local/up.sh                    # all 9 phases, in order (idempotent)
deploy/local/up.sh phase8_seed        # re-run a single phase function
CLUSTER_NAME=foo deploy/local/up.sh   # override any knob (see lib.sh)
deploy/local/down.sh                  # delete the kind cluster
```

Re-running `up.sh` is safe: an existing cluster is reused, manifests re-apply as
no-ops, secrets/certs/PKI are not duplicated, and a prior stuck/failed helm
release is cleared before re-install.

## What it does (phases)

| # | Phase | Result |
|---|-------|--------|
| 1 | **Cluster + Calico** | Multi-node kind (1 cp + 2 workers), **default CNI disabled**, Calico installed (kindnet does not enforce NetworkPolicy). Sets `ipipMode=CrossSubnet` — kind nodes share one subnet, so native routing preserves the node IP as the source of the hostNetwork gateway (required for the SEC-3 gateway-allow; see adaptations). |
| 2 | **Cluster deps** | cert-manager + Kyverno (server-side apply; its CRDs exceed the client-side limit) + dev Postgres (shared `edge` DB + issuer's `issuer` DB) + NATS (JetStream). |
| 3 | **Images** | Builds **all 7** images (5 control-plane Go targets, edge-osb, auth-service in-container) and `kind load`s them. Extends `make docker-build-local` (which builds only 3). |
| 4 | **Data-plane PKI** | `helm install edge-pki` (selfsigned roots → the `edge-internal-ca` and `edge-spiffe` ClusterIssuers). No certificate is applied by hand: each chart issues its own in Phase 7, and Phase 7's verify fails on any Certificate in `infra` or `edge` that no helm release owns. |
| 5 | **Admin PKI + secrets** | Runs `scripts/bootstrap-pki.sh` (admin CA, custodian cert, KEK) + issuer RSA signing key, and creates every app secret (DSNs `sslmode=disable`). |
| 6 | **Migrate** | Runs `edge-migrate` as a Job against the shared DB (both schema sets, idempotent). |
| 7 | **Deploy** | `helm upgrade --install` for all 7 charts with dev + local overlays, `--wait`, **extAuthz ON** (the chart default; the local overlay does not set it). Envoy connects to the control-plane over mTLS xDS. |
| 8 | **Seed** | Two tenant backends + the missing route source: a gateway on **:443** and a host-route per tenant (via direct SQL). |
| 9 | **Prove** | A request per tenant through the node **:443** hostPort → 200 from the correct backend. |
| 25 | **Default jwt service** (runs right after 9) | On the charts exactly as installed — nothing has switched ext_authz yet — the OSB broker provisions a service **without** naming an `auth_policy`, so it gets the default `jwt`. It is published and gated on :80: **401** with no token or a garbage one, **200** `OSB-PROVISIONED-BACKEND` with a JWT minted by the issuer, and tenant-a (`none`) still 200. Then deprovisioned, because phase 12 switches ext_authz off. |
| 10 | **SEC-3 Property 1** (admission) | Applies the Kyverno guardrails (Enforce), then proves red-first: a NetworkPolicy allowing from an empty podSelector `{}` is **DENIED**; a NodePort backend Service is **DENIED**. |
| 26 | **Signed-image admission** (runs right after 10) | Applies `k8s/policies/verify-image-signatures.yaml`, then proves red-first, once for each signer generation — `ghcr.io/talyvor` (signed by `Talyvor/edge-infra`, `SIGNED_IMAGE`/`UNSIGNED_IMAGE`) and `ghcr.io/gaboracnicolai` (built before the 12 Oct 2026 move, `OLD_SIGNED_IMAGE`/`OLD_UNSIGNED_IMAGE`): a Deployment of `auth-service:<sha>-amd64`, the per-arch intermediate nothing signs, is **DENIED** with `no signatures found`, and so is the same image written as `ghcr.io:443/…`; a Deployment of a signed main build of `edge-osb` is admitted, its image rewritten to the digest Kyverno verified. Kyverno fetches the signatures from ghcr and checks them against the public Rekor log, so this phase needs the internet. |
| 11 | **SEC-3 Property 2** (data-plane) | A pod-network attacker (IP outside NODE_CIDR) reaches each backend's ClusterIP with no policy (RED), then — after the resolved backend policy — is **dropped** while the node-`:443` gateway path stays **200** (two separate assertions). |
| 12 | **CFG-1 flip + ext_authz LIVE** | Four properties, red-first: (P4) the CFG-1 guard refuses a jwt route while ext_authz is OFF; then the live flip; (P1) a real minted JWT → 200 + trusted identity-header injection (forged headers overwritten); (P2) no/invalid JWT → 401; (P3) auth-service down → fail-closed 403. |
| 13–14 | **R8 fail-static guard + metrics** | A dangling route is refused, the last good config keeps serving, and the blocked counter rises on the live `/metrics`. |
| 15 | **OSB broker** | `edge-osb` answers `/healthz`; a tenant-keyed `POST /v1/services` is completed by the worker and the new host is served through Envoy :80 by a stub (`OSB-PROVISIONED-BACKEND`); `DELETE` removes it again. |
| 16 | **Per-node SDS** (XDS-1) | Pins tenant-a's and tenant-b's HTTPS `:8443` gateways to the two workers via `node_selector` (`kubernetes.io/hostname`). Each node's live Envoy SDS holds **only its own** tenant's key; each serves its tenant with that tenant's cert and **cannot** present the other tenant's cert; after a control-plane restart (a new replica is Ready only after its first publish, so only the late-join catch-up can serve a node) and a restart of one node's edge-proxy, the fresh Envoy again holds only its own tenant's key. |
| 17 | **Chart NetworkPolicies** | Every chart runs with its NetworkPolicy on (the local overlays). Red-first on auth-service: with its policy switched off a pod-network attacker connects to ext_authz :50051; back on, it is dropped. Then every chart port — auth-service, control-plane xDS, issuer, OSB, ratelimit, secrets — drops the attacker, while the gateway's own source (a node) still connects to each port the gateway uses. |
| 18 | **SCIM + OIDC sign-in** | Dex stands in for the customer's IdP. Red-first: Dex signs `sso-user@corp.local` in and the issuer refuses (403, not provisioned). The IdP's SCIM client creates the user (`POST /scim/v2/Users`); the same sign-in now returns a gateway token, and Envoy serves `secure.local` with `x-user-email` and `x-user-id` = the SCIM user. SCIM `PATCH active=false` → the next sign-in is refused. |
| 19 | **Confidential compute** (mock TEE) | Labels one worker `talyvor.io/confidential=true`, adds RuntimeClass `confidential-mock` and a mock attester. The auth-service chart with `confidential.enabled`: with no attester, and with a report signed by a key it does not trust, its `attest` init container exits 1 and auth-service never starts; with a valid report both pods start, on the labelled node, under the RuntimeClass. See [docs/self-host-confidential-compute.md](../../docs/self-host-confidential-compute.md). |
| 20 | **Per-route SNI certs** | One HTTPS gateway on `:9443` with no cert of its own and two routes, each carrying its own cert (`sni-a.local`, `sni-b.local`). `tls_inspector` reads the SNI, so `curl --resolve` to each host on the one port gets **that** host's cert (`CN=sni-a.local` / `CN=sni-b.local`) and its own backend; a request on `sni-b.local`'s connection with `Host: sni-a.local` does **not** reach tenant-a (each SNI chain reads only its own host's routes); an SNI no route names fails the TLS handshake (curl exit 35, no cert). |
| 27 | **Agent certificates (SVIDs)** (runs last) | Uses the agent trust root the `edge-pki` chart installed (`edge-spiffe`, its own CA) and installs csi-driver-spiffe. The trust bundle goes in through the `edge-secrets` custodian as a `validation_context`, named by an `mtls` route on `agents.edge.local:9446`, and Envoy receives it over SDS. `agent-alpha` mounts the driver's volume and holds an SVID for `spiffe://edge.talyvor.local/ns/agents/sa/agent-alpha` that chains to the bundle; with it the route answers **200** from tenant-a. A pod with **no certificate** is refused at the TLS handshake (`certificate required`, no HTTP answer), and so is a pod presenting a certificate for the **same SPIFFE ID from another CA** (`unknown ca`). See [docs/agent-certificates.md](../../docs/agent-certificates.md). |
| 29 | **Egress lockdown** | Removes the mock provider's own NetworkPolicy, so it answers any pod, and applies `k8s/policies/agent-egress-lockdown.yaml`. An agent in the new namespace `agents-locked` calls the provider directly and is served. With the namespace labelled `talyvor.io/agents=true`, Kyverno writes the `agent-egress-lockdown` NetworkPolicy (egress to `kube-dns:53` and `edge/edge-egress:3128` only): the same direct call times out (`curl-exit=28`), and the same call through `edge-egress` is **200** from the provider. Deleted, the NetworkPolicy is written back by Kyverno and the direct call is dropped again. See [docs/agent-egress.md](../../docs/agent-egress.md#locking-agents-in). |
| 30 | **Keyless agents** | Has auth-service trust the cluster's ServiceAccount issuer (audience `edge-egress`) and starts `agent-keyless` in `agents-locked` with a provider key planted in its environment. While `mock-llm` is not keyless the provider echoes the planted key back, so the instrument can see it. Marked `keyless`, `mock-llm` answers the planted key alone with **407** from `edge-egress`; with the agent's projected ServiceAccount token as `Proxy-Authorization` it is **200**, and the provider receives no `Authorization`, `X-Api-Key`, `Api-Key`, `key=` or workload token — only an `x-gateway-auth` assertion for `system:serviceaccount:agents-locked:agent-keyless` (`amr: agent`) that verifies against the published transit key. CONNECT to the keyless host is **403** and the direct call is dropped by the lockdown. See [docs/agent-egress.md](../../docs/agent-egress.md#keyless-agents). |
| 31 | **Per-agent rate limits and the decision log** | Sets the control plane to 5 requests a minute per agent and turns its admin API on. In `agents-locked`, `rl-alpha-1` and `rl-alpha-2` share the ServiceAccount `rl-alpha`; `rl-beta` has its own. A burst from `rl-alpha-1` to keyless `mock-llm` is served 5 times, then **429**; `rl-alpha-2` gets **429** at once (`x-ratelimit-limit: 5`, `retry-after: 60`) — the bucket is the agent's, not the pod's — and `rl-beta` is served. The `edge-egress` access log names the agent with `RL`. `GET /admin/v1/decisions` exports the decision log (the 429s, the 200, Phase 30's 407s) and `scripts/verify-decisions.sh` verifies the hash chain from record 1; with one record rewritten it does not. See [docs/agent-egress.md](../../docs/agent-egress.md#rate-limits-per-agent). |
| 33 | **KEK rotation** | Writes a cert for `rotate.local` through the custodian (sealed `enc:v2:<kid>:…`) and routes it on Phase 20's `:9443`. Gives the control plane and the custodian a new `SECRET_KEK` with the old one as `SECRET_KEK_PREVIOUS` and restarts both; `POST /v1/reseal` (what `secrets reseal` calls) moves every key onto the new KEK, and no row is left under the old one. Then `SECRET_KEK_PREVIOUS` is removed and both restart holding the new KEK alone; a fresh Envoy is served `rotate.local`'s **same** cert. See [docs/kek-rotation.md](../../docs/kek-rotation.md). |
| 36 | **An agent's own ServiceAccount token** | Removes Phase 30's anonymous read of the API server's keys (an anonymous `GET /openid/v1/jwks` now gets 403) and has auth-service trust the cluster's ServiceAccount issuer for the gateway's audience with `ca_file` and `token_file` from its own pod, so it fetches the keys as itself. `agent-sa` in `agents-sa` has two projected tokens and no other credential; through the gateway's `:80` an OSB service provisioned with the default jwt auth answers **200** to its token for the gateway's audience and **401** to its token for `billing.internal`. |
| 35 | **Offline licence** (runs last) | Installs a licence signed by a key made for the run (`licence.publicKeys`). Valid for a day it reads `edge_licence_valid 1`; replaced in its Secret by one that expired yesterday it reads `0`, the control plane logs `licence EXPIRED`, and both tenants still return **200** — then again after a cold control-plane restart and a fresh Envoy. See [docs/licence.md](../../docs/licence.md). |

## Topology

Two edge-infra namespaces (plus `tenant-a` / `tenant-b` for the backends):

- **`infra`** — edge-control-plane, edge-issuer, auth-service, edge-osb,
  edge-ratelimit, edge-secrets + the dev datastores (postgres, nats). Services
  address each other at `*.infra.svc.cluster.local`.
- **`edge`** — edge-proxy only. Its three envoy certs are issued in `edge`, and a
  pod can mount secrets only from its own namespace, so the proxy runs here and
  dials the control-plane at `…infra.svc…`. It's a **DaemonSet** with
  `hostNetwork` + hostPort 80/443; the routable worker publishes those to the host.

## Local adaptations (why the overlays exist)

The charts target a GitOps (ArgoCD) deploy; a few things need dev-overlay **values**
(never template changes) for a raw local `helm install`:

- **ServiceAccount for hooks** (control-plane, issuer): the pre-install migrate
  **hook** references the chart SA, which is a regular post-hook resource — so
  under `helm install` the hook runs before the SA exists and `FailedCreate`s.
  The overlays point both at the `default` SA (they need no special RBAC).
- **edge-osb TLS off**: the chart forces `verify-full` Postgres TLS + mutual NATS
  TLS whenever `tls` is set; the dev datastores are plaintext. `tls: null` removes
  the block; `DB_SSL_MODE=disable` comes via the secret.
- **auth_policy=none on seeded routes**: they are the no-token baseline every phase
  probes, and they must keep serving while phase 12 has `ext_authz` off — the xDS
  reconciler is **fail-closed** and withholds the entire snapshot if any route
  wants auth while `ext_authz` is off.
- **:443 plaintext**: the seed gateway is protocol HTTP on port 443 (no TLS
  termination) so the routing proof is a clean plaintext request to the hostPort.
- **Calico `CrossSubnet`** (SEC-3): with the manifest default `ipipMode=Always`,
  cross-node hostNetwork traffic (the gateway) egresses via `tunl0` and takes the
  tunnel's pod-CIDR IP as source — which would NOT match a node-CIDR ipBlock allow,
  so the gateway would be dropped. kind nodes share one subnet, so `CrossSubnet`
  uses native routing and preserves the node IP as source.
- **edge-proxy roll after an ext_authz flip** (CFG-1): `helm_set_extauthz` rolls
  edge-proxy after every flip so it reconnects fresh.
  **⚠ STALE RATIONALE — the original reason no longer applies on `main`.** It was:
  the xDS snapshot version counter was per-process, so it RESET to `v1` when the
  control-plane rolled on a flip, and a still-connected edge-proxy holding a higher
  version rejected the new push as stale (`cds/lds update_failure`; the config
  silently never applied). **#47 made the version a pure function of the config
  hash** (`internal/xds/reconciler.go:399-440`), and `reconciler.go:413` states
  outright that the roll workaround is no longer needed. The roll is now harmless
  belt-and-braces, not a requirement.
  **But note:** the committed control-plane image pin (`values.yaml:5`,
  `447ceb18`, 2026-05-20) PREDATES #47, so against that image the old rationale
  still holds. Two staleness bugs cancelling out is not a safety property — see
  the root [README](../../README.md) and
  [docs/ext-authz-cutover-and-rollback.md](../../docs/ext-authz-cutover-and-rollback.md).
- **In-cluster JWT minter** (Phase 12): the macOS system `curl` is LibreSSL and
  cannot TLS-handshake the issuer's Go server, so the token is minted from an
  in-cluster OpenSSL `curl` pod (`POST /login`) rather than a host port-forward.

## Configuration (env knobs, see `lib.sh`)

`CLUSTER_NAME` (default `edge-local`), `INFRA_NS` (`infra`), `IMAGE_TAG` (`local`),
`GATEWAY_HOST_PORT` (`443`), and pinned versions `CALICO_VERSION`,
`CERT_MANAGER_VERSION`, `KYVERNO_VERSION`, `KIND_NODE_IMAGE`.

## Files

| File | Purpose |
|------|---------|
| `lib.sh` | Shared config + helpers (sourced; no side effects). |
| `kind-config.yaml` | Multi-node cluster, default CNI disabled, publishes 80/443. |
| `up.sh` / `down.sh` | Phase-by-phase standup / teardown. |
| `e2e.sh` | `make kind-e2e`: fresh cluster → every phase → teardown. |
| `cutover.sh` | `make kind-cutover`: fresh cluster → the CFG-1 cutover in launch-day order, checked per step → teardown. |
| `rollback.sh` | `make kind-rollback`: fresh cluster → cutover state → auth-service down → flip-back-alone (denied) → full revert (exactly as before) → teardown. |
| `manifests/` | namespaces, postgres, nats, migrate Job, tenant backends, SEC-3 attacker, secure (whoami+minter) backend, OSB stub upstream. |
| `values/` | Per-chart local overlays (images + the adaptations above). |
| `.pki-bootstrap/` | Generated admin PKI + KEK + signing key (gitignored). |

## SEC-3 + ext_authz live enforcement (phases 10-12)

### SEC-3 (phases 10-11) — two properties, proven **red-first and separately**:

1. **Admission (Kyverno)** — the guardrails reject rules that would re-open the
   bypass/lateral-movement hole: a NetworkPolicy allowing from an empty
   podSelector `{}`, and a LoadBalancer/NodePort backend Service. The resolved
   ipBlock allow-from-gateway (no empty podSelector) is admitted.
2. **Data-plane (Calico)** — a compromised **pod-network** foothold (attacker pod,
   IP outside NODE_CIDR) can hit a backend's ClusterIP directly with no policy;
   after the backend policy it is dropped, while the gateway path stays 200.

### Honesty — the precision ceiling under hostNetwork

The gateway (edge-proxy) runs `hostNetwork`, so its traffic to a backend carries
the **node** IP, and the allow rule is therefore an `ipBlock` of the node CIDR.
This means the control **drops pod-network footholds** — a compromised app pod,
SSRF from a workload, a malicious sidecar (the realistic lateral-movement threat)
— but it does **not** make the gateway the only possible source: **any** hostNetwork
pod on a node would also match the node-CIDR allow. App-layer `x-gateway-auth`
(ext_authz, a later run) is the backstop for gateway *identity*. What is proven
here is exactly: pod-network → backend is dropped; node-network (the gateway) →
backend on the echo port is allowed.

### ext_authz cutover (phase 12) — four properties, red-first, one at a time

`ext_authz` is **on by default** (phase 7 installs it so). Phase 12 switches it
**off** with `helm --set` to prove the guard, then flips it back on. Before flipping, a **deny-all-trap
gate**: auth-service Ready (⇒ JWKS-at-boot succeeded) AND edge-proxy actually has
`/etc/authz-client-tls/ca.crt` mounted (no caFile ⇒ the ext_authz cluster renders
plaintext ⇒ the fail-closed auth-service rejects it ⇒ deny-all). Flip only if both
pass.

1. **P4 CFG-1 guard** (pre-flip): a route with `auth_policy=jwt` while ext_authz is
   OFF ⇒ the reconciler **refuses to publish** (an identity-bearing listener must
   never serve open). The existing routes keep the last-good snapshot.
2. **P1 valid JWT** ⇒ 200 + the auth-service injects trusted identity headers
   (`x-user-id`, `x-user-email`, `x-auth-iss`, `x-user-teams`, `x-gateway-auth`);
   a **client-forged** `x-user-email` is overwritten (OverwriteIfExistsOrAdd).
3. **P2** no/invalid JWT ⇒ 401.
4. **P3** auth-service down ⇒ **fail-closed 403** (`failure_mode_allow:false`);
   recovers to 200.

`none`-policy routes (tenant-a/b) are per-route ext_authz **Disabled**, so they keep
serving without a token — the identity-header injection is only for the `jwt` route.

**Rollback (safe, LOCAL ONLY):** a FULL revert — `--set extAuthz.enabled=false`
**AND** remove the jwt route. Flipping `enabled=false` alone while the jwt route is
present re-triggers the CFG-1 guard ⇒ deny-all. The end state is ext_authz **ON**
with secure.local(jwt) + tenant-a/b(none) all serving.

> **⚠ DO NOT CARRY THIS PROCEDURE TO PRODUCTION.** It is written in `helm --set`
> terms for a 3-route demo where "remove the jwt route" is one seeded row. In
> production every route defaults to `auth_policy='jwt'`, so the equivalent is
> mutating every tenant's route while the gateway denies traffic — not something
> anyone can execute under pressure. The production rollback is a single SQL
> statement and is written up, with its verification steps and its one big caveat
> (OSB re-provisioning silently restores `auth_policy`), in
> [docs/ext-authz-cutover-and-rollback.md](../../docs/ext-authz-cutover-and-rollback.md).

### Honesty — the SEC-3 precision ceiling still applies

SEC-3's ipBlock allow lets **any** hostNetwork pod on a node reach a backend; it
drops pod-network footholds (compromised app pod, SSRF, malicious sidecar) but does
not make the gateway the only possible source. ext_authz's `x-gateway-auth`
transit-proof is the app-layer backstop for gateway *identity* — now live.
