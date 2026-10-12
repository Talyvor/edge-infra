# Upgrading

Moving an install made with [the install guide](install.md) to a new release, and back.

**Every `sh` block on this page is run by `make kind-install-guide`** too: once the install guide has
finished, it upgrades that install to a second release with these commands and checks it again.

## Before you start

1. **Read the release notes** on the [releases page](https://github.com/Talyvor/edge-infra/releases)
   for every release between yours and the new one.
2. **Back up**, and check the backup finished ([Backup and restore](backup.md)). Schema changes
   only go forward, so the backup is your way back.
3. **Verify the new images:** `make verify-images TAG=<new release>`
   ([Verifying the images](self-host-supply-chain.md)).

Set `NEW_VERSION` to the release you are moving to (for example `export NEW_VERSION=1.1.0`) and
`PROFILE` to the profile you installed (`lite`, `ha` or `airgap`), and start in the `edge-infra`
directory you installed from:

```sh
: "${NEW_VERSION:?set NEW_VERSION to the release you are moving to}"
: "${PROFILE:?set PROFILE to the profile you installed: lite, ha or airgap}"
helm list -A
```

## Upgrade

Get the new release and pin its charts, as in step 1 of the install guide. For `airgap`, prepare
it on the connected side first, as [Air-gapped install](air-gap.md) says.

```sh
git clone --quiet --depth 1 --branch "v$NEW_VERSION" https://github.com/Talyvor/edge-infra.git "../edge-infra-$NEW_VERSION"
cd "../edge-infra-$NEW_VERSION"
bash deploy/hack/release-pin.sh "$NEW_VERSION"
```

Upgrade every release **in the install order**. `--reset-then-reuse-values` takes the new chart's
defaults — its new image tags among them — and keeps every `--set` you installed with; the new
release's profile file goes on top. (Plain `--reuse-values` would keep the *old* chart's defaults,
and so the old images.)

```sh
helm upgrade edge-pki deploy/helm/edge-pki -n cert-manager --reset-then-reuse-values \
  -f "deploy/profiles/$PROFILE/edge-pki.yaml" --wait --timeout 5m
helm upgrade edge-datastores deploy/helm/edge-datastores -n infra --reset-then-reuse-values \
  -f "deploy/profiles/$PROFILE/edge-datastores.yaml" --wait --timeout 10m
for release in edge-control-plane edge-issuer auth-service edge-osb edge-secrets; do
  helm upgrade "$release" "deploy/helm/$release" -n infra --reset-then-reuse-values \
    -f "deploy/profiles/$PROFILE/$release.yaml" --wait --timeout 10m
done
helm upgrade edge-proxy deploy/helm/edge-proxy -n edge --reset-then-reuse-values \
  -f "deploy/profiles/$PROFILE/edge-proxy.yaml" --wait --timeout 10m
```

What happens on the way:

- **Schema.** `edge-datastores` applies the new release's schema changes after its own upgrade,
  and the control plane and issuer check theirs before their new copies start. Each change is
  applied once and recorded; a failed change fails that `helm upgrade`, and the old copies keep
  running. ([Database migrations](migrations.md).)
- **Passwords.** The datastores keep the passwords they were installed with.
- **The broker's worker** restarts two or three times while its old copy lets go of the queue.
  Changes sent to the broker meanwhile wait in NATS and are applied once it is up.
- **No dropped traffic.** Each service replaces one copy at a time. The gateway rolls 10% of the
  workers at a time, and keeps serving its last configuration while the control plane restarts.

## Check

Every first-party image now runs at the new release (pods of the old one that are still shutting
down are left out), and every chart's own test passes:

```sh
kubectl get pods -A -o json \
  | jq -r '.items[] | select(.metadata.deletionTimestamp == null) | .spec.containers[].image' \
  | grep talyvor/ | sort -u | tee running-images.txt
OLD="$(grep -v ":$NEW_VERSION\$" running-images.txt || true)"
[ -z "$OLD" ]
for release in edge-datastores edge-control-plane edge-issuer auth-service edge-osb edge-secrets; do
  helm test "$release" -n infra --timeout 5m
done
helm test edge-proxy -n edge --timeout 5m
```

## Rolling back

Roll back in the **reverse** order, each release to the revision before the upgrade
(`helm history <release> -n <namespace>` lists them):

```
helm rollback edge-proxy -n edge
helm rollback edge-secrets -n infra
helm rollback edge-osb -n infra
helm rollback auth-service -n infra
helm rollback edge-issuer -n infra
helm rollback edge-control-plane -n infra
helm rollback edge-datastores -n infra
```

**Schema changes stay.** A rollback runs the previous release's code on the newer schema. If the
release notes say the previous release cannot run on it, restore the backup you took before the
upgrade instead ([Backup and restore](backup.md#restore)).

**If you changed `ext_authz`,** a rollback has an order of its own: routes that need a token come
out first, then the control plane goes back. Rolling the control plane back alone can leave every
gated route refusing: [ext_authz cutover and rollback](ext-authz-cutover-and-rollback.md).

## Rotating keys

An upgrade changes no key. To rotate the KEK that seals stored keys, see
[KEK rotation](kek-rotation.md); certificates inside Edge are renewed by cert-manager on their own.
