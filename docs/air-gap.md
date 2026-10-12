# Air-gapped install

Talyvor Edge installs and runs in a cluster with no route to the internet. You carry three things
across the gap — the release, its images and cert-manager — and then follow
[the install guide](install.md) with the `airgap` profile: the `ha` settings, with every chart
pulling from your own registry.

Once installed, nothing in Edge reaches outside your cluster: no call to Talyvor, no licence
server, no telemetry. [No internet at run time](no-internet-at-run-time.md) lists what each service
talks to, and how to trust an identity provider outside the cluster from a copy of its keys.

## On a machine with internet access

Set the release you install and the registry your cluster pulls from:

```sh
export EDGE_VERSION=1.0.0
export REGISTRY=registry.internal:5000
```

**The release.** The charts, the scripts and the guide, pinned to the release's images:

```sh
git clone --depth 1 --branch "v$EDGE_VERSION" https://github.com/Talyvor/edge-infra.git
cd edge-infra
bash deploy/hack/release-pin.sh "$EDGE_VERSION"
```

Point the `airgap` profile at your registry. Its files name `registry.internal:5000`; this
writes yours in their place, and shows what every chart will now pull from:

```sh
for f in deploy/profiles/airgap/*.yaml; do
  sed "s#registry.internal:5000#$REGISTRY#" "$f" > "$f.new" && mv "$f.new" "$f"
done
grep -h 'imageRegistry:' deploy/profiles/airgap/*.yaml | sort -u
```

Check every first-party image's signature, SBOM and provenance now, while you can reach the
signing log: `make verify-images TAG=$EDGE_VERSION` ([Verifying the images](self-host-supply-chain.md)).

**The images.** Every image any chart can run — the eight first-party ones, Envoy, the bundled
datastores, the backup and test images, and the observability stack:

```sh
awk '/^[[:space:]]*repository:/ {r = $2; gsub(/"/, "", r)}
     /^[[:space:]]*tag:/ && r != "" {t = $2; gsub(/"/, "", t); print r ":" t; r = ""}' \
  deploy/helm/*/values.yaml deploy/helm/*/charts/*/values.yaml | sort -u > images.txt
cat images.txt
```

Copy each one into your registry under the path the charts will ask for. A chart with
`global.imageRegistry` set drops the image's own registry and keeps the rest of its path, adding
`library/` to a Docker Hub image with no organisation, and keeps the tag and digest:

| The chart names | It pulls |
|---|---|
| `ghcr.io/talyvor/edge-osb:1.0.0` | `registry.internal:5000/talyvor/edge-osb:1.0.0` |
| `envoyproxy/envoy:v1.39.2@sha256:…` | `registry.internal:5000/envoyproxy/envoy:v1.39.2@sha256:…` |
| `postgres:16.15-alpine@sha256:…` | `registry.internal:5000/library/postgres:16.15-alpine@sha256:…` |

With [crane](https://github.com/google/go-containerregistry/tree/main/cmd/crane), which copies
every platform of an image and keeps its digest:

```sh
while read -r img; do
  name="${img%@*}"
  case "$name" in
    ghcr.io/*) dest="${name#ghcr.io/}" ;;
    */*)       dest="$name" ;;
    *)         dest="library/$name" ;;
  esac
  case "$img" in
    *@*) src="${name%:*}@${img#*@}" ;;
    *)   src="$img" ;;
  esac
  crane copy "$src" "$REGISTRY/$dest"
done < images.txt
```

If your registry cannot be reached from this machine, `crane pull --format=oci` each image to a
directory, carry it across, and `crane push` it on the other side.

**cert-manager.** Its manifest, and its images under the same paths:

```sh
curl -fsSLo cert-manager.yaml https://github.com/cert-manager/cert-manager/releases/download/v1.20.0/cert-manager.yaml
grep -o 'quay.io/jetstack/[^"[:space:]]*' cert-manager.yaml | sort -u | while read -r img; do
  crane copy "$img" "$REGISTRY/${img#quay.io/}"
done
sed -i.orig "s#quay.io/jetstack/#$REGISTRY/jetstack/#g" cert-manager.yaml
```

If your backends need an image to try the first route with (the guide's step 9 uses
`hashicorp/http-echo:0.2.3`), copy that too, or use one of your own.

Then carry the `edge-infra` directory, with `cert-manager.yaml` in it, across the gap.

## In the air-gapped network

Follow [the install guide](install.md) from the `edge-infra` directory you carried, with
`PROFILE=airgap` and two changes:

1. **Skip step 1.** The directory is the release, already pinned and pointed at your registry.
2. **Step 2:** `kubectl apply -f cert-manager.yaml`, the copy you rewrote, instead of the URL.

The profile's registry reaches every image a chart runs, init containers, the schema Jobs and
`helm test` included. Check what a chart will pull before you install it:

```
helm template edge-osb deploy/helm/edge-osb -f deploy/profiles/airgap/edge-osb.yaml | grep 'image:'
```

For a one-node air-gapped install, use `PROFILE=lite` instead and add
`--set global.imageRegistry=$REGISTRY` to every `helm upgrade --install`.

If your registry needs credentials, create a pull Secret in `infra` and `edge` and add
`--set 'imagePullSecrets[0].name=<secret>'` to the same commands (`global.imagePullSecrets[0].name`
for `edge-datastores`).

## What is different without the internet

- **Image signatures are not checked at admission.** The Kyverno policy that refuses unsigned
  images matches `ghcr.io/talyvor/*` and checks the signing log online, so it does not apply
  to your registry. Verify on the connected side, as above, before you copy.
- **An identity provider outside the cluster** is trusted from a copy of its keys in a Secret,
  which you refresh when it rotates them: [No internet at run time](no-internet-at-run-time.md#trusting-an-identity-provider-outside-the-cluster).
- **Your licence** is checked offline, from the licence file and the public key in the chart:
  [licence](licence.md).
- **Backups** go to an S3-compatible store inside your network, such as MinIO: [Backup](backup.md).

`make kind-e2e` proves the running part (phase 32): it cuts every node off from every public
address and stops CoreDNS answering for any name outside the cluster, restarts Edge cold, and checks
that it serves and that not one DNS query for an outside name was made.
