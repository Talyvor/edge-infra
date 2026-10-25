# Verifying the images before you install them

Every image the charts install is signed when it is built, and carries two signed
attestations: what is inside it (an SBOM) and how it was built (SLSA provenance).
The eight images are `edge-control-plane`, `edge-issuer`, `edge-ratelimit`,
`edge-secrets`, `edge-migrate`, `edge-attest`, `edge-osb` and `auth-service`, all
under `ghcr.io/talyvor`. Until 12 Oct 2026, when this repository moved from
`gaboracnicolai` to the Talyvor organisation, they were published under
`ghcr.io/gaboracnicolai` and signed as `gaboracnicolai/edge-infra`; check one of
those against that signer instead.

| | What it is | Check it with |
|---|---|---|
| Signature | a keyless cosign signature on the image digest | `cosign verify` |
| SBOM | an SPDX JSON list of every package in the image, made by syft 1.54.0 | `cosign verify-attestation --type spdxjson` |
| Provenance | SLSA v1 in GitHub's [workflow build type](https://actions.github.io/buildtypes/workflow/v1): the repository, ref, commit, trigger and run that built the image | `cosign verify-attestation --type slsaprovenance1` |

All three are made by the `sign` job in
[`.github/workflows/images.yaml`](../.github/workflows/images.yaml) and signed as
that workflow. No key is involved. cosign trades the job's GitHub OIDC token for a
short-lived Fulcio certificate that names the workflow, signs with it, and
records the signature in the public Rekor log. When you verify, you check that
name:

```
issuer    https://token.actions.githubusercontent.com
identity  https://github.com/Talyvor/edge-infra/.github/workflows/images.yaml@<ref>
```

`<ref>` is `refs/heads/main` for a build from main, or `refs/tags/v1.2.3` for the
release `v1.2.3`. The certificate must also name `Talyvor/edge-infra` as
the repository the run was in. `images.yaml` is a reusable workflow, and another
repository that called it would get a certificate with the same identity but its
own repository name. A signature made by another repository, another workflow,
or a pull-request build (`refs/pull/<n>/merge`) does not pass.

## One command

From a checkout of this repository, with `cosign` and `jq` on your PATH:

```sh
make verify-images TAG=1.2.3       # a release
make verify-images TAG=<sha>       # a build from main, at its commit sha
```

This verifies every first-party image named in `deploy/helm/*/values.yaml`, at
that tag. The tag sets the signer: `TAG=1.2.3` accepts only a signature from the
`v1.2.3` release run, and `TAG=<sha>` only one from a run at that commit, so an
older signed image retagged under the name you asked for does not pass. It exits
1 if any image is missing its signature, its SBOM or its provenance:

```
ok    ghcr.io/talyvor/edge-osb@sha256:…
      signed by   https://github.com/Talyvor/edge-infra/.github/workflows/images.yaml@refs/tags/v1.2.3
      sbom        <n> packages (SPDX, syft)
      provenance  built from git+https://github.com/Talyvor/edge-infra@refs/tags/v1.2.3 at <sha> by https://github.com/Talyvor/edge-infra/actions/runs/…
…
all 8 image(s) signed, with an SBOM and SLSA provenance, by https://github.com/Talyvor/edge-infra/.github/workflows/images.yaml@refs/{heads/main,tags/v<SemVer>}
```

You can set the signer yourself. `SIGNER_REF=refs/tags/v1.2.3` accepts only that
release's signer. `SIGNER_SHA=<sha>` requires the commit, both in the
certificate and in the provenance. You can name images directly:
`bash deploy/hack/supply-chain.sh verify ghcr.io/talyvor/edge-osb@sha256:…`.
If you have no cosign, `bash deploy/hack/supply-chain.sh install <dir>` fetches
the pinned one and checks its sha256.

## Scanned for known vulnerabilities

Before the `sign` job signs anything, the `scan` job in `images.yaml` runs
[trivy](https://github.com/aquasecurity/trivy) 0.74.0 over all eight images. If
any of them carries a HIGH or CRITICAL vulnerability that already has a fixed
version, the run fails and nothing is signed. That covers OS packages, the Go
modules and Go standard library compiled into each binary, and the OSB image's
Python packages. A vulnerability with no fix yet does not fail the run, because
there is nothing to upgrade to. The nightly run fails on the morning a fix
ships. To scan a release yourself, with `trivy` on your PATH:

```sh
make scan-images TAG=1.2.3
```

If you have no trivy, `bash deploy/hack/image-scan.sh install <dir>` fetches the
pinned one and checks its sha256.

What goes into an image is locked as well:

- **Base images are pinned to a digest**, e.g.
  `gcr.io/distroless/static:nonroot@sha256:…`, so a commit always builds on the
  same bytes. A new base comes in as a commit, and that commit's run scans it.
  `bash deploy/hack/image-scan.sh bases` fails if any `FROM` names a tag alone.
- **Go 1.27.3** builds every Go binary, from the pinned `golang` image, and
  `go.mod` asks for the same version.
- **The OSB image installs `osb/requirements.lock`**, which pins every Python
  package to an exact version and hash. pip refuses any package the lock does
  not name. `make -f osb/Makefile lock` regenerates it from `osb/pyproject.toml`.

CI also proves the scan can fail. It plants PyYAML 5.3.1 (CVE-2020-14343,
CRITICAL) in the OSB image the same run pushed
([`test/image-scan/planted`](../test/image-scan/planted)). The scan must refuse
that image and name that CVE.

## By hand, with cosign alone

You do not need this repository:

```sh
IMG=ghcr.io/talyvor/edge-control-plane:1.2.3
WHO=(--certificate-oidc-issuer https://token.actions.githubusercontent.com
     --certificate-github-workflow-repository Talyvor/edge-infra
     --certificate-identity https://github.com/Talyvor/edge-infra/.github/workflows/images.yaml@refs/tags/v1.2.3)

cosign verify "${WHO[@]}" "$IMG"

cosign verify-attestation "${WHO[@]}" --type spdxjson "$IMG" \
  | jq -r .payload | base64 -d | jq '.predicate.packages[] | {name, versionInfo}'

cosign verify-attestation "${WHO[@]}" --type slsaprovenance1 "$IMG" \
  | jq -r .payload | base64 -d | jq '.predicate.buildDefinition'
```

To accept any build from main or any release instead of one tag, swap
`--certificate-identity` for
`--certificate-identity-regexp '^https://github\.com/Talyvor/edge-infra/\.github/workflows/images\.yaml@refs/(heads/main|tags/v.*)$'`.

## How CI proves it

The `verify` job in `images.yaml` runs on every image build: on every pull
request and push that changes an image, on every release, and nightly. It runs
`supply-chain.sh verify` on the eight digests that run pushed. It pins the
run's own ref and commit, so each image has to carry a signature, an SBOM and
provenance from that run. It has no write access and no OIDC token. It then
verifies the per-arch `auth-service:<sha>-amd64` image, which is an intermediate
that nothing signs, and requires the check to fail.

## Refused at admission

[`k8s/policies/verify-image-signatures.yaml`](../k8s/policies/verify-image-signatures.yaml)
is a Kyverno policy that makes the cluster run the signature check on every pod.
Argo CD syncs it with the other policies in `k8s/policies`. To apply it by hand,
on a cluster with Kyverno:

```sh
kubectl apply -f k8s/policies/verify-image-signatures.yaml
```

Every pod, and every Deployment, StatefulSet, DaemonSet, Job or CronJob, that
names an image under `ghcr.io/talyvor/` must carry a signature from the
signer above: `images.yaml` in `Talyvor/edge-infra`, on main or on a
`v<SemVer>` release tag. Anything else is refused when you apply it:

```
$ kubectl create deployment x --image=ghcr.io/talyvor/auth-service:<sha>-amd64
error: failed to create deployment: admission webhook "mutate.kyverno.svc-fail" denied the request:
resource Deployment/default/x was blocked due to the following policies
verify-image-signatures:
  autogen-signed-by-edge-infra-images-workflow: 'failed to verify image ghcr.io/talyvor/auth-service:<sha>-amd64:
    .attestors[0].entries[0].keyless: no signatures found'
```

A signature from a pull-request build, another workflow or another repository
is refused the same way, with `subject mismatch` or `extension mismatch`. An
image that passes is rewritten to the digest Kyverno verified, e.g.
`edge-osb:1.2.3@sha256:…`, so the tag cannot move to other bytes after.
A first-party image written any other way, such as `ghcr.io:443/talyvor/…`
or `GHCR.IO/talyvor/…`, is refused too, because the check matches the
image as written. Images from other registries are not checked.

The policy fails closed. If Kyverno cannot reach ghcr.io or the public Rekor
log, it refuses the pod. To pull `edge-issuer` and `edge-ratelimit`, which are
private, Kyverno needs read access to them too: name a pull secret in its
`--imagePullSecrets` flag.

`make kind-e2e` runs it in Phase 26. A Deployment of the per-arch auth-service
image, which nothing signs, is denied with `no signatures found`, so is the same image written as
`ghcr.io:443/…`, and a signed `edge-osb` build from main is admitted, pinned to
its digest.

## From your own registry

Every chart takes `global.imageRegistry`. Set it and every image the chart
runs, init containers and the schema jobs included, is pulled from that
registry instead of the one it names, with its path kept:

```sh
helm install edge-osb deploy/helm/edge-osb --set global.imageRegistry=registry.internal:5000
```

| The chart names | Pulled as |
| --- | --- |
| `ghcr.io/talyvor/edge-osb:<tag>` | `registry.internal:5000/talyvor/edge-osb:<tag>` |
| `envoyproxy/envoy:<tag>@sha256:…` | `registry.internal:5000/envoyproxy/envoy:<tag>@sha256:…` |
| `redis:<tag>@sha256:…` | `registry.internal:5000/library/redis:<tag>@sha256:…` |

Tags and digests are unchanged, so copy each image under its path with its
digest intact (e.g. `crane copy` or `skopeo copy --all`). To list what a chart
will pull:

```sh
helm template x deploy/helm/edge-osb --set global.imageRegistry=registry.internal:5000 | grep 'image:'
```

`make verify-image-registry` renders every chart, for its defaults and every
profile, and fails if any image is not from the override; CI runs it.

## What this does not cover yet

- **Admission does not check images pulled from your own registry.** The
  Kyverno policy matches `ghcr.io/talyvor/*` as written, so with
  `global.imageRegistry` set it no longer applies. Run `make verify-images`
  against the originals before you copy them.

- **Admission checks the signature, not the SBOM or the provenance.** Those are
  checked by `make verify-images`.
- **The provenance is SLSA Build Level 2, not 3.** GitHub's hosted runner
  generates and signs it, as the build's own workflow. Build L3 needs the
  provenance to come from a generator the build steps cannot touch, and here it
  is a script in the same workflow, so an edit to that workflow could change
  what it says. The Fulcio certificate records the ref, commit and trigger on
  its own, apart from the predicate. `SIGNER_SHA` (or cosign's
  `--certificate-github-workflow-sha`) checks the commit there.
- **The SBOM is the `linux/amd64` variant's.** The `arm64` variant is built
  from the same sources and lockfiles.
- **Two packages are private** (`edge-issuer`, `edge-ratelimit`). To verify
  them, `docker login ghcr.io` with read access first. Their digests and
  signer identity still go to the public Rekor log, like every other image's.
