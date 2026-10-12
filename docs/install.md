# Installing Talyvor Edge

This guide installs Talyvor Edge into your own Kubernetes cluster and ends with a request through
the gateway: refused without a token, answered by your own backend with one. It takes about half
an hour.

**Every `sh` block on this page is run, in order and as written, by `make kind-install-guide`**
(`deploy/local/install-guide.sh`), on a kind cluster it creates and deletes. CI runs it whenever
this page, a chart or the code inside an image changes, and every night. If a command here stops
working, that run goes red.

The other customer pages:

| | |
|---|---|
| [Sizing and high availability](sizing-and-ha.md) | what each part needs, and what keeps serving when a part fails |
| [Air-gapped install](air-gap.md) | installing from your own registry, with no route to the internet |
| [Upgrading](upgrade.md) | moving to a new release, and back |
| [Backup and restore](backup.md) | what to back up, and the restore drill |
| [Threat model](threat-model.md) | what Edge defends, against whom, and what it does not |
| [Data flow](data-flow.md) | where every request, key and answer goes, the answer pool included |

## Choose a profile

A profile is one values file per chart, in `deploy/profiles/<profile>/`, that sizes Edge for the
cluster you run it on. Every `helm` command below takes the profile's file for its chart.

| Profile | For | What it sets |
|---|---|---|
| `lite` | one node, to try Edge or for a small team | one copy of each service |
| `ha` | production, on two or more workers | two or three copies of each service, spread so that no node holds more than one copy more than any other, and across zones where your nodes carry a zone label |
| `airgap` | production with no route to the internet | the `ha` settings, with every image pulled from your own registry: see [Air-gapped install](air-gap.md) first |

The test below installs `ha`. [Sizing and high availability](sizing-and-ha.md) has what each
part needs and what keeps serving when one fails.

## What you need

**A Kubernetes cluster** (the test runs Kubernetes 1.35, on kind) with:

- **Two or more worker nodes** for `ha` and `airgap`; one node for `lite`. The gateway runs on every
  worker.
- **A network plugin that enforces NetworkPolicy.** Calico is the one tested. Without enforcement
  the charts' NetworkPolicies are accepted and do nothing.
- **A default StorageClass**, for the bundled Postgres, Redis and NATS. To use your own instead,
  see [§ Your own datastores](#your-own-datastores).
- **Ports 80 and 443 free on the workers.** The gateway listens on them on the node itself.
- **About 3 CPUs and 3 GiB of memory** to spare. [Sizing](sizing-and-ha.md) has the detail.
- **A way to pull** `ghcr.io/talyvor/*` and the Docker Hub images the charts name. With no
  route out, follow [Air-gapped install](air-gap.md) first.

**On your machine:** `kubectl` pointed at the cluster, `helm` (3.14 or later, or 4), `git`,
`openssl` 3, `jq` and `curl`.

Set four things in your shell before you start:

| Variable | What it is | Example |
|---|---|---|
| `PROFILE` | the profile you install: `lite`, `ha` or `airgap` | `export PROFILE=ha` |
| `EDGE_VERSION` | the release you install, from the [releases page](https://github.com/Talyvor/edge-infra/releases) | `export EDGE_VERSION=1.0.0` |
| `NODE_CIDR` | the network your nodes' InternalIPs are in. The gateway runs on the node's own network, so this is where its requests to the services come from | `export NODE_CIDR=10.0.0.0/16` |
| `GATEWAY` | an address that reaches port 80 on a worker: a node IP, or your load balancer in front of the nodes | `export GATEWAY=10.0.1.20` |

This checks them, and shows the nodes and their InternalIPs:

```sh
: "${PROFILE:?set PROFILE to lite, ha or airgap}"
: "${EDGE_VERSION:?set EDGE_VERSION to the release you install}"
: "${NODE_CIDR:?set NODE_CIDR to the network your nodes are in}"
: "${GATEWAY:?set GATEWAY to an address that reaches port 80 on a worker}"
kubectl get nodes -o wide
```

## 1. Get the release

The charts and the profiles come from the release's git tag. `release-pin.sh` points every chart
at that release's images, and `--list` prints the eight first-party images it will run. The last
line shows your profile's files.

```sh
git clone --quiet --depth 1 --branch "v$EDGE_VERSION" https://github.com/Talyvor/edge-infra.git
cd edge-infra
bash deploy/hack/release-pin.sh "$EDGE_VERSION"
bash deploy/hack/release-pin.sh --list
ls "deploy/profiles/$PROFILE"
```

Before you install them, you can check that every image is signed and carries its SBOM and
provenance: [Verifying the images](self-host-supply-chain.md).

## 2. cert-manager

Every certificate inside Edge is issued and renewed by cert-manager. If your cluster already runs
cert-manager, skip this step: applying this manifest would change your installed version to 1.20.

```sh
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.20.0/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=300s
```

## 3. Namespaces and certificate authorities

Edge's services run in `infra`; the gateway runs in `edge`. `edge-pki` creates two certificate
authorities in cert-manager: `edge-internal-ca`, which every chart issues its own certificate from,
and `edge-spiffe`, for [agent certificates](agent-certificates.md).

```sh
kubectl create namespace infra
kubectl create namespace edge
helm upgrade --install edge-pki deploy/helm/edge-pki -n cert-manager \
  -f "deploy/profiles/$PROFILE/edge-pki.yaml" --wait --timeout 5m
kubectl wait --for=condition=Ready clusterissuer/edge-internal-ca clusterissuer/edge-spiffe --timeout=120s
```

## 4. Datastores

`edge-datastores` runs Postgres, Redis and NATS, each on its own volume, creates the database
schema, and writes every connection address and password into one Secret, `edge-datastores`. The
passwords are generated on first install and kept across upgrades.

```sh
helm upgrade --install edge-datastores deploy/helm/edge-datastores -n infra \
  -f "deploy/profiles/$PROFILE/edge-datastores.yaml" --wait --timeout 10m
kubectl -n infra get statefulset,pvc
```

### Your own datastores

To use a Postgres, Redis or NATS you already run, switch that one off and give its address; the
Secret and the schema work the same way. For example, with your own Postgres (two databases, `edge`
and `issuer`):

```yaml
# values-datastores.yaml — pass with -f values-datastores.yaml in step 4, after the profile's file
postgres: { enabled: false }
external:
  postgres:
    dsn: postgres://edge:PASSWORD@db.example.internal:5432/edge?sslmode=verify-full
    issuerDsn: postgres://edge:PASSWORD@db.example.internal:5432/issuer?sslmode=verify-full
```

With your own Postgres over TLS, read the `tls` block of `deploy/helm/edge-osb/values.yaml` before
step 8: the guide's `DB_SSL_MODE=disable` and `tls=null` are for the bundled one.

## 5. Your keys

These keys are made on your machine and go into Secrets in your cluster, and nowhere else:

- the **admin CA** and the certificate of `edge-secrets`, which keeps your TLS keys;
- the **KEK**, which encrypts every key `edge-secrets` stores;
- the issuer's **signing key**, which signs your users' tokens;
- the gateway's **transit key**, which signs the identity it passes to your backends.

They go into `.pki-bootstrap/`, readable only by you. **Copy that directory somewhere safe and
offline before you go on.** Without the KEK, no stored key can be read again; see
[Backup and restore](backup.md).

```sh
EDGE_NAMESPACE=infra bash scripts/bootstrap-pki.sh .pki-bootstrap > /dev/null
openssl genrsa -out .pki-bootstrap/k1.pem 2048
openssl genpkey -algorithm ed25519 -out .pki-bootstrap/transit.pem
ls .pki-bootstrap
```

## 6. Secrets

Each service reads its settings from a Secret. The database and NATS addresses come from the
`edge-datastores` Secret step 4 wrote.

```sh
ds() { kubectl -n infra get secret edge-datastores -o "jsonpath={.data.$1}" | base64 -d; }
KEK="$(cat .pki-bootstrap/secret_kek.b64)"
ISSUER_URL=https://edge-issuer.infra.svc.cluster.local:8081

kubectl -n infra create secret generic edge-control-plane-postgres \
  --from-literal=dsn="$(ds POSTGRES_DSN)" \
  --from-literal=SECRET_KEK="$KEK"

kubectl -n infra create secret generic issuer-secrets \
  --from-literal=ISSUER_URL="$ISSUER_URL" \
  --from-literal=ISSUER_AUDIENCE=edge-gateway \
  --from-literal=ISSUER_DATABASE_URL="$(ds ISSUER_DATABASE_URL)"
kubectl -n infra create secret generic issuer-signing-keys \
  --from-file=k1.pem=.pki-bootstrap/k1.pem

kubectl -n infra create secret generic auth-service-secrets \
  --from-literal=JWKS_URL="$ISSUER_URL/.well-known/jwks.json" \
  --from-literal=JWT_ISSUER="$ISSUER_URL" \
  --from-literal=JWT_AUDIENCE=edge-gateway \
  --from-file=TRANSIT_SIGNING_KEY=.pki-bootstrap/transit.pem

kubectl -n infra create secret generic edge-osb-secrets \
  --from-literal=DATABASE_URL="$(ds POSTGRES_DSN)" \
  --from-literal=DB_SSL_MODE=disable \
  --from-literal=NATS_URL="$(ds NATS_URL)"

kubectl -n infra create secret generic edge-admin-ca \
  --from-file=ca.crt=.pki-bootstrap/admin-ca.crt
kubectl -n infra create secret tls edge-secrets-tls \
  --cert=.pki-bootstrap/server.crt --key=.pki-bootstrap/server.key
kubectl -n infra create secret generic edge-secrets-config \
  --from-literal=SECRET_KEK="$KEK" \
  --from-literal=SECRETS_DATABASE_URL="$(ds POSTGRES_DSN)" \
  --from-literal=SECRETS_ADMIN_API_KEY="$(openssl rand -hex 32)"
```

`DB_SSL_MODE=disable` matches the bundled Postgres, which listens only inside the cluster.

## 7. Your first team

Services are registered through the broker, `edge-osb`, by a team holding a key. The broker keeps
only the key's SHA-256 and refuses to start until at least one team has a key. This makes the key for
a team called `platform`; keep it with the others.

```sh
TENANT_KEY="$(openssl rand -hex 32)"
printf '%s\n' "$TENANT_KEY" > .pki-bootstrap/team-platform.key
KEY_HASH="$(printf '%s' "$TENANT_KEY" | openssl dgst -sha256 -r | cut -d' ' -f1)"
kubectl -n infra exec edge-datastores-postgres-0 -- psql -U edge -d edge -v ON_ERROR_STOP=1 \
  -c "INSERT INTO tenant_api_keys (key_hash, team) VALUES ('$KEY_HASH', 'platform')"
```

## 8. Install Edge

In this order: the control plane, the issuer, the gateway's authorisation service, the broker, the
key custodian, then the gateway itself. Each waits until it is ready before the next starts.

Every service gets a NetworkPolicy that admits only the flows it needs, with the gateway let in from
`NODE_CIDR`. `serviceAccount.create=false` runs the control plane and issuer under the namespace's
default ServiceAccount: their schema step runs before Helm creates anything else, so it cannot use
a ServiceAccount from the same install, and neither needs any Kubernetes permissions.

```sh
helm upgrade --install edge-control-plane deploy/helm/edge-control-plane -n infra \
  -f "deploy/profiles/$PROFILE/edge-control-plane.yaml" \
  --set serviceAccount.create=false \
  --set networkPolicy.enabled=true --set "networkPolicy.gatewayCIDRs={$NODE_CIDR}" \
  --wait --timeout 10m

helm upgrade --install edge-issuer deploy/helm/edge-issuer -n infra \
  -f "deploy/profiles/$PROFILE/edge-issuer.yaml" \
  --set config.activeKid=k1 \
  --set serviceAccount.create=false \
  --set networkPolicy.enabled=true --set "networkPolicy.gatewayCIDRs={$NODE_CIDR}" \
  --wait --timeout 10m

helm upgrade --install auth-service deploy/helm/auth-service -n infra \
  -f "deploy/profiles/$PROFILE/auth-service.yaml" \
  --set networkPolicy.enabled=true --set "networkPolicy.gatewayCIDRs={$NODE_CIDR}" \
  --wait --timeout 10m

helm upgrade --install edge-osb deploy/helm/edge-osb -n infra \
  -f "deploy/profiles/$PROFILE/edge-osb.yaml" \
  --set tls=null \
  --set networkPolicy.enabled=true --set "networkPolicy.gatewayCIDRs={$NODE_CIDR}" \
  --wait --timeout 10m

helm upgrade --install edge-secrets deploy/helm/edge-secrets -n infra \
  -f "deploy/profiles/$PROFILE/edge-secrets.yaml" \
  --set networkPolicy.enabled=true \
  --wait --timeout 10m

helm upgrade --install edge-proxy deploy/helm/edge-proxy -n edge \
  -f "deploy/profiles/$PROFILE/edge-proxy.yaml" --wait --timeout 10m

kubectl -n infra get pods
kubectl -n edge get pods -o wide
```

`tls=null` is for the bundled datastores, which do not use TLS inside the cluster. Every profile
runs **one broker worker**: a second worker cannot yet share the queue with the first, and restarts
until it is removed. The broker's API runs as many copies as the profile sets. The gateway's
default certificate for HTTPS services is issued for `*.edge.io`; set yours with
`--set 'certificate.serving.dnsNames={*.example.com}'` on `edge-proxy`, or give each service its own
([§ per-route certificates](self-host-network-and-identity.md)).

## 9. Your first route

Run a small backend, then register it with the broker as `hello.example.test`. Like every service
unless you say otherwise, it needs a token.

```sh
kubectl create namespace hello
kubectl -n hello apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata: { name: echo }
spec:
  selector: { matchLabels: { app: echo } }
  template:
    metadata: { labels: { app: echo } }
    spec:
      containers:
        - name: echo
          image: hashicorp/http-echo:0.2.3
          args: ["-text=hello from your backend", "-listen=:5678"]
          ports: [{ containerPort: 5678 }]
---
apiVersion: v1
kind: Service
metadata: { name: echo }
spec:
  selector: { app: echo }
  ports: [{ port: 5678 }]
EOF
kubectl -n hello rollout status deploy/echo --timeout=120s
```

The broker is not exposed outside the cluster; reach it through a port-forward. It answers at once
with a request id, and the change is live when that request is `COMPLETED`.

```sh
kubectl -n infra port-forward svc/edge-osb 18080:8080 > /dev/null 2>&1 &
BROKER_FORWARD=$!
sleep 5
curl -fsS http://127.0.0.1:18080/v1/services \
  -H "Authorization: Bearer $TENANT_KEY" -H 'Content-Type: application/json' \
  -d '{"name": "hello", "team": "platform", "host": "echo.hello.svc.cluster.local",
       "port": 5678, "public_host": "hello.example.test"}' | tee provision.json
echo
REQUEST="$(jq -r .request_id provision.json)"
for i in $(seq 60); do
  STATUS="$(curl -fsS -H "Authorization: Bearer $TENANT_KEY" "http://127.0.0.1:18080/v1/requests/$REQUEST" | jq -r .status)"
  [ "$STATUS" = COMPLETED ] && break
  sleep 2
done
echo "$STATUS"
[ "$STATUS" = COMPLETED ]
kill "$BROKER_FORWARD"
```

Now through the gateway. With no token the route answers **401**:

```sh
for i in $(seq 30); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: hello.example.test' "http://$GATEWAY/" || true)"
  [ "$CODE" = 401 ] && break
  sleep 2
done
echo "$CODE"
[ "$CODE" = 401 ]
```

Make a user in the issuer and sign in as them. In use, your people sign in through your own identity
provider instead ([SCIM and OIDC sign-in](self-host-network-and-identity.md)).

```sh
USER_PASSWORD="$(openssl rand -hex 16)"
kubectl -n infra exec deploy/edge-issuer -- /issuer adduser \
  --email admin@example.test --password "$USER_PASSWORD" --team platform
kubectl -n infra get secret issuer-tls-secret -o 'jsonpath={.data.ca\.crt}' | base64 -d > issuer-ca.crt
kubectl -n infra port-forward svc/edge-issuer 18081:8081 > /dev/null 2>&1 &
ISSUER_FORWARD=$!
sleep 5
TOKEN="$(curl -fsS --cacert issuer-ca.crt \
  --resolve edge-issuer.infra.svc.cluster.local:18081:127.0.0.1 \
  https://edge-issuer.infra.svc.cluster.local:18081/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\": \"admin@example.test\", \"password\": \"$USER_PASSWORD\"}" | jq -r .access_token)"
kill "$ISSUER_FORWARD"
```

With the token, your backend answers:

```sh
curl -fsS -H 'Host: hello.example.test' -H "Authorization: Bearer $TOKEN" "http://$GATEWAY/" | tee answer.txt
grep -q 'hello from your backend' answer.txt
```

The gateway checked the token before the request reached your backend, and passed on who sent it
in headers your backend can trust: `x-user-id`, `x-user-email`, `x-user-teams`, and an
`x-gateway-auth` assertion signed with your transit key. Any of these a client sends itself is
replaced.

## 10. Check every part

Each chart carries its own test, which reaches its service the way its clients do, through its
NetworkPolicy.

```sh
for release in edge-datastores edge-control-plane edge-issuer auth-service edge-osb edge-secrets; do
  helm test "$release" -n infra --timeout 5m
done
helm test edge-proxy -n edge --timeout 5m
helm test edge-pki -n cert-manager --timeout 5m
```

## Next

- **Lock agents in.** Label an agent namespace `talyvor.io/agents=true` and its pods can reach
  nothing but the egress gateway, which reaches only the hosts you list:
  [agent egress](agent-egress.md). That needs Kyverno and the `k8s/policies` set.
- **Refuse unsigned images** at admission: [Verifying the images](self-host-supply-chain.md#refused-at-admission).
- **Sign your people in** through your identity provider, and provision them by SCIM:
  [network and identity](self-host-network-and-identity.md).
- **Watch it:** dashboards and alerts, in your Prometheus or the bundled one:
  [observability](observability.md).
- **Install your licence:** [licence](licence.md).
- **Before you depend on it:** [sizing and high availability](sizing-and-ha.md),
  [backup](backup.md) and [upgrading](upgrade.md).
