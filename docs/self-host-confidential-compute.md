# Self-host: confidential compute

The auth-service chart can run only on confidential nodes, and only after the
node proves what it is. `make kind-e2e` runs it (Phase 19 of `deploy/local/up.sh`).

## What switching it on does

```yaml
# values for the auth-service chart
confidential:
  enabled: true
  runtimeClassName: kata-qemu-snp          # or empty for a node pool of confidential VMs
  nodeSelector:
    talyvor.io/confidential: "true"        # labels only your confidential nodes carry
  tolerations: []                           # if those nodes are tainted
  attestation:
    image: {repository: ghcr.io/talyvor/edge-attest, tag: <sha>}
    evidenceURL: http://127.0.0.1:8006/aa/evidence
    trustedKey: <the attester's ed25519 public key, base64>
    measurements: [<launch measurement allowed to start, hex>]
```

- **Node selection.** The pods carry the `nodeSelector` (and `tolerations`), so they
  schedule on your confidential nodes and nowhere else, and the `runtimeClassName`
  when your confidential runtime needs one. The chart refuses to render with
  `enabled: true` and no `nodeSelector`, `trustedKey` or `measurements`.
- **Attestation gate.** An `attest` init container runs before auth-service. It
  sends the attester a fresh random nonce (`?runtime_data=<hex>`, the shape of the
  Confidential Containers attestation agent) and checks the report that comes
  back: signed by `trustedKey`, bound to that nonce, a measurement in
  `measurements`, issued within `maxAge` (5m). If no report arrives within
  `timeout` (30s), or one arrives and any check fails, the gate exits 1 and
  auth-service never starts. The reason is in the pod's status:

  ```
  kubectl get pod <pod> -o jsonpath='{.status.initContainerStatuses[0].lastState.terminated.message}'
  attestation REFUSED: report is not signed by the trusted attester key
  ```

## What is real and what is not

The chart option and the gate are real. The attestation is mocked: the gate
verifies reports from its `mock` TEE only — an attester that signs with an
ed25519 key you pin (`attest mock-attester`, used by the kind run). Real
attestation needs confidential VMs: an AMD SEV-SNP or Intel TDX report is
produced only inside one, and verifying it needs the vendor's certificate chain
(VCEK / PCK), which this gate does not implement. A report from either is refused
as unverifiable, never passed.

## What the kind run proves

Phase 19 labels one worker `talyvor.io/confidential=true`, adds a RuntimeClass
`confidential-mock` (plain runc, limited to that node) and starts the mock
attester. Then it installs the auth-service chart three more times:

| Release | Attestation | Result asserted |
|---|---|---|
| `auth-cc-noreport` | no attester at the URL | gate exits 1, "no attestation report"; auth-service never started, pod not Ready |
| `auth-cc-untrusted` | a valid report, but the chart trusts another key | gate exits 1, "report is not signed by the trusted attester key"; auth-service never started |
| `auth-cc` (2 replicas) | a valid report from the trusted attester | gate exits 0 and logs the verified measurement; both pods Ready, on the labelled node, under `confidential-mock` |
