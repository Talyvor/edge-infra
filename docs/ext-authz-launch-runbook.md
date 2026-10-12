# ext_authz launch-day runbook (CFG-1)

The order in which to turn gateway authentication on in a real cluster, and the check that must
pass after each step before you start the next. **If a check fails, stop.** Do not continue to the
next step, and do not improvise a reorder. The rollback is
[ext-authz-cutover-and-rollback.md §2](ext-authz-cutover-and-rollback.md#2--the-rollback).

Every step and check here has a counterpart in `make kind-cutover` (`deploy/local/cutover.sh`), which
runs the same sequence on a throwaway kind cluster and fails if any check fails. CI runs it whenever a
chart, an overlay or the harness changes (`.github/workflows/kind-cutover.yaml`). If you change this
runbook, change the rehearsal in the same PR.

---

## Why this order — each point was measured on kind

| Hazard | What the rehearsal shows | So |
|---|---|---|
| The committed control-plane pin (`deploy/helm/edge-control-plane/values.yaml`, `447ceb1`, 2026-05-20) predates `/readyz` and xDS TLS. | Under main's charts it never becomes Ready (its readiness probe fails on `:18001/readyz`, which it does not serve). Envoy cannot reach it. **The gateway serves nothing.** | The image bump is step 1, and it is required. Main as committed cannot serve traffic. |
| The auth-service pin is the same `447ceb1`. It has no `AUTH_TLS_*` support, so it has no mTLS at all. | — | Step 2 bumps the auth-service image as well. |
| Once bumped, the control plane has the CFG-1 fail-closed guard: while ext_authz is off, any route with `auth_policy != 'none'` makes it refuse **every** snapshot (`internal/xds/reconciler.go`, "refusing to build snapshot"). | One `auth_policy='jwt'` route added between the bump and the enable stops all publishing. New routes, removals and endpoint changes all wait. Envoy keeps serving last-good, so nothing looks broken. `xds_snapshots_blocked_total{reason="auth_wanted_extauthz_off"}` rises. | **Provisioning stays frozen from step 1 until step 4.** OSB's default `auth_policy` is `jwt` (`osb/models.py`). |
| ext_authz is fail-closed. If you enable it with no reachable auth-service, or with no client cert on the proxies, every jwt route is denied. | — | The auth-service (step 2) and the client cert (step 3) come before the enable. |
| Enabling the flag on the old pin does nothing: that binary never reads `EXT_AUTHZ_ENABLED`. | — | The enable is last, after the bump. Step 4 checks that the binary actually reports ext_authz on. |

The bump and the enable are separate steps so that each one can be checked on its own. The price is
the window between step 1 and step 4, in which provisioning must stay frozen.

---

## Before you start

**These preconditions assume a first install.** Talyvor Edge runs only on kind and nothing is deployed
(see the root README). If you find an existing fleet, this runbook was not rehearsed against it. Stop.

1. **Use the profile that ArgoCD reads.** The Applications in `deploy/argocd/applications/` read
   the profile `make argocd-apply PROFILE=<profile>` registered them with (`deploy/profiles/ha/` by
   default), and they self-heal. A `kubectl scale` or `helm --set` is reverted within minutes, so
   **every change below is a PR to that profile.**
2. **Choose `<SHA>`.** Use a main commit with a green "Build and push images" run (`images.yaml` pushes
   `ghcr.io/talyvor/<image>:<sha>` on every main push). Confirm that its code is the code the
   rehearsal passed on:
   ```bash
   gh run list --workflow images.yaml --branch main --status success --limit 5 --json headSha,createdAt
   git diff --quiet <SHA> <rehearsed-main-sha> -- cmd internal auth-service go.mod go.sum Dockerfile.control-plane \
     && echo same-code || echo DIFFERENT
   ```
3. **Turn on the admin READ API.** Every check asks the control plane what it is actually running.
   ```bash
   kubectl -n infra create secret generic edge-cp-admin --from-literal=admin-api-key="$(openssl rand -hex 24)"
   ```
   Then add `adminApi: {existingSecret: edge-cp-admin}` to `values-control-plane.yaml` in the step 1 PR.
4. **Install the CAs.** `helm upgrade --install edge-pki deploy/helm/edge-pki -n cert-manager --wait`.
   Every other chart issues its own certificate from it when it syncs (`certificate.*`). The
   edge-proxy chart issues the authz client cert only while `extAuthz.clientTLS.enabled` is on,
   so it does not exist until step 3.
5. **Let edge-proxy start without the authz client cert.** The chart mounts that cert as a required
   volume, so a proxy synced before step 3 never starts. In `values-proxy.yaml`, set:
   ```yaml
   extAuthz:
     clientTLS:
       enabled: false   # LAUNCH WINDOW ONLY — removed in step 3
   ```
6. **Freeze provisioning.** In `values-osb.yaml`, set `api: {replicaCount: 0}` and
   `worker: {replicaCount: 0}`. Both the broker API and the worker write `auth_policy`
   (`osb/translator.py`, `osb/worker.py`). Check:
   ```bash
   kubectl -n infra get deploy edge-osb-api edge-osb-worker   # READY 0/0 for both
   ```
7. **No route may want auth yet.** Step 1 freezes the fleet the moment it boots if one does.
   ```sql
   SELECT auth_policy, count(*) FROM routes WHERE deleted_at IS NULL GROUP BY 1;
   -- Expect only `none`, or no rows at all. Any `jwt`/`mtls` row: STOP. This runbook did not rehearse that case.
   ```

### The check kit, used after every step

```bash
ADMIN_KEY="$(kubectl -n infra get secret edge-cp-admin -o jsonpath='{.data.admin-api-key}' | base64 -d)"
DSN="$(kubectl -n infra get secret edge-control-plane-postgres -o jsonpath='{.data.dsn}' | base64 -d)"
kubectl -n infra port-forward deploy/edge-control-plane 18002:18002 2112:2112 >/dev/null &
admin()   { curl -s -H "X-Admin-Key: $ADMIN_KEY" "http://127.0.0.1:18002$1"; }
refused() { curl -s http://127.0.0.1:2112/metrics | grep 'xds_snapshots_blocked_total{reason="auth_wanted_extauthz_off"}'; }
proxies() { kubectl -n edge get pod -l app.kubernetes.io/name=edge-proxy --no-headers | grep -c ' Running '; }
```

**FLEET-LIVE**: this check catches a fleet frozen on last-good, which nothing else does. A new route
must be published, acknowledged by every proxy, and served. Point the canary at a backend you own,
never at a tenant's cluster:

```sql
INSERT INTO routes (id,name,gateway_id,hosts,path_prefix,cluster_name,timeout_seconds,auth_policy)
VALUES ('launch-canary','launch-canary','<gateway-id>',ARRAY['launch-canary.<domain>'],'/','<your-canary-cluster>',30,'none');
```
```bash
curl -s -o /dev/null -w '%{http_code}\n' https://launch-canary.<domain>/           # 200 within ~30s
admin /admin/v1/nodes | jq '{published_version, active_streams, nodes_behind}'     # active_streams == $(proxies), nodes_behind == 0
psql "$DSN" -c "DELETE FROM routes WHERE name='launch-canary';"
curl -s -o /dev/null -w '%{http_code}\n' https://launch-canary.<domain>/           # 404 within ~30s
```

**TENANTS**: every `auth_policy='none'` route you already serve answers 200 without a token.

---

## Step 1: image bump, with ext_authz still OFF

**Do:** open a PR to `values-control-plane.yaml` with the following, and do not touch `extAuthz`:
```yaml
image:   {tag: "<SHA>"}
migrate: {image: {tag: "<SHA>"}}   # the base pins the migrator hook to an older build
adminApi: {existingSecret: edge-cp-admin}
```
Merge it and wait for ArgoCD to sync.

**Check, then stop if any line fails:**
```bash
kubectl -n infra rollout status deploy/edge-control-plane
kubectl -n infra get deploy edge-control-plane -o jsonpath='{.spec.template.spec.containers[0].image}'   # …:<SHA>
admin /admin/v1/config | jq -c '[.xds.tls, .xds.client_ca, .ext_authz.enabled]'                       # [true,true,false]
refused                                                                                                 # … 0
```
Then TENANTS and FLEET-LIVE.

Provisioning stays frozen from here until step 4. A single jwt route now stops all publishing. The
rehearsal's CONTROL 1 shows it happening.

## Step 2: auth-service with JWKS and mTLS

**Prerequisites:** edge-issuer is serving, and the `auth-service-secrets` Secret holds
- `JWKS_URL=https://edge-issuer.infra.svc.cluster.local:8081/.well-known/jwks.json` (it must be https)
- `JWT_ISSUER`, which must equal the issuer's `ISSUER_URL`
- `JWT_AUDIENCE`, which must equal the issuer's `ISSUER_AUDIENCE`
- `TRANSIT_SIGNING_KEY`, a PEM Ed25519 private key (`openssl genpkey -algorithm ed25519`)

**Do:** open a PR to `values-auth-service.yaml` setting `image: {tag: "<SHA>"}`. Merge it and wait for the sync.

**Check:**
```bash
kubectl -n infra rollout status deploy/auth-service
kubectl -n infra logs deploy/auth-service | grep -E '"mtls":true|grpc server listening'   # both present
# It fetches the JWKS BEFORE it listens and exits if it cannot, so "listening" means the JWKS loaded.
kubectl -n edge run authz-nocert --rm -i --restart=Never --image=curlimages/curl:8.11.1 -- \
  curl -sk --max-time 6 -o /dev/null -w 'code=%{http_code}\n' https://auth-service.infra.svc.cluster.local:50051/
# code=000 with a non-zero exit: a client with no certificate is refused.
refused                                                                                   # unchanged since step 1
```
Then TENANTS and FLEET-LIVE.

## Step 3: client certificate

**Do:**
Open a PR to `values-proxy.yaml` that **removes** the launch-window `clientTLS.enabled: false`.
The chart default issues the cert and mounts it. Merge it. The DaemonSet rolls 10% of nodes at a
time, and your load balancer has to drain each node as it rolls. Once synced:
```bash
kubectl -n edge wait --for=condition=Ready certificate/envoy-authz-client-cert --timeout=120s
```

**Check:**
```bash
kubectl -n edge rollout status ds/edge-proxy
for p in $(kubectl -n edge get pod -l app.kubernetes.io/name=edge-proxy -o name); do
  kubectl -n edge exec "$p" -c envoy -- ls /etc/authz-client-tls/ca.crt /etc/authz-client-tls/tls.crt /etc/authz-client-tls/tls.key
done                                                    # every pod, all three files
kubectl -n edge run authz-cert --rm -i --restart=Never --image=curlimages/curl:8.11.1 --overrides='
{"spec":{"containers":[{"name":"authz-cert","image":"curlimages/curl:8.11.1","command":["curl","-s","--max-time","6",
 "--cacert","/c/ca.crt","--cert","/c/tls.crt","--key","/c/tls.key","-o","/dev/null","-w","code=%{http_code}\n",
 "https://auth-service.infra.svc.cluster.local:50051/"],"volumeMounts":[{"name":"c","mountPath":"/c"}]}],
 "volumes":[{"name":"c","secret":{"secretName":"envoy-authz-client-tls-secret"}}]}}'
# a real HTTP code (not 000): the auth-service accepted the cert, and the client verified the server's chain.
refused                                                 # unchanged since step 1
```
Then TENANTS and FLEET-LIVE.

## Step 4: enable

**Do:** open a PR to `values-control-plane.yaml` setting `extAuthz: {enabled: true}`, with the image
unchanged. Merge it. The control plane rolls. Envoy keeps serving through the roll: the rehearsal
drops zero tenant requests here.

**Check:**
```bash
kubectl -n infra rollout status deploy/edge-control-plane
admin /admin/v1/config | jq -c '[.ext_authz.enabled, .ext_authz.tls, .ext_authz.mtls]'   # [true,true,true]
refused                                                                                   # … 0 (a new process; it can no longer fire)
```
Then TENANTS and FLEET-LIVE.

**Unfreeze provisioning:** open a PR reverting the `values-osb.yaml` replica counts. Provision the
first jwt service, then check every request class against it:

| Request | Expect |
|---|---|
| no `Authorization` | 401 |
| `Authorization: Bearer not-a-jwt` | 401 |
| a valid token from the issuer's `POST /login` | 200, and the backend receives `x-user-email` from the token |
| a valid token plus a forged `x-user-email: attacker@evil.com` | 200, and the backend receives the token's email, not the forged one |
| every `none` route, no token | 200 |

Finish with `refused` (still 0) and FLEET-LIVE, now with jwt routes present.

**Done:** ext_authz is on. No allowed request was refused, no refused request was let through, and the
fleet never froze.
