# Threat model

What Talyvor Edge defends, against whom, how, and what it does not defend against yet. Where a
defence is shown working on a running cluster, the last column names the `make kind-e2e` phase
that shows it ([deploy/local/README.md](../deploy/local/README.md) describes each phase).

## What it protects

- **Your services**, from requests by anyone the gateway has not authenticated.
- **Your agents' outbound calls**: an agent reaches only the hosts you list, and a provider key it
  holds never leaves the cluster on a keyless route.
- **One team's routes, keys and traffic** from every other team on the same Edge.
- **The keys Edge holds**: the TLS keys of your services, the KEK that seals them, the issuer's
  signing key and the gateway's transit key.
- **The configuration** the gateway runs, from being changed by anyone but the broker's teams and
  your operators, and from a bad change taking the gateway down.

## Who is trusted

| Trusted | Not trusted |
|---|---|
| Your cluster administrators: anyone who can read Secrets in `infra` or `edge`, exec into or port-forward to their pods, or change the charts | Every client of the gateway |
| The nodes and their operating system | Every agent, and every workload outside `infra` and `edge` |
| cert-manager, the network plugin and, if you use it, Kyverno | Anyone on the pod network |
| Your identity provider, for who your people are | Each team using the broker, towards every other team |
| | Talyvor: Edge makes no call to Talyvor, needs no account and sends nothing out |

Edge cannot defend against someone who already controls the cluster: they can read every Secret,
including the KEK. Limit who has those rights in `infra` and `edge`.

## Threats, and what stops them

| Threat | What stops it | Shown in |
|---|---|---|
| A request with no token, a forged one, or an expired one reaches a service that needs one | The gateway asks `auth-service` about every request to such a route before it is forwarded; no valid token is **401** | phases 12, 25 |
| The authorisation service is down, so requests go through unchecked | The gateway **fails closed**: those routes answer 403 while it is down | phase 12 |
| A route that needs a token is published while token checks are switched off | The control plane refuses to publish any configuration in which a route wants a token and checks are off, and keeps the last good one | phase 12 |
| A client sends `x-user-id`, `x-user-email` or `x-gateway-auth` itself, to pose as someone | The gateway removes them and sets its own; `x-gateway-auth` is signed with your transit key, so a backend can check it | phases 12, 23 |
| A path such as `/../admin` reaches something it should not | The gateway normalises paths and refuses traversal | phase 23 |
| A workload calls a service directly, around the gateway | Each chart's NetworkPolicy admits only the flows it needs, and the gateway only from the node network; Kyverno refuses NetworkPolicies that would open a backend to everyone, and NodePort Services | phases 10, 11, 17 |
| An agent calls an outside host it should not | With its namespace labelled `talyvor.io/agents=true`, its pods can reach nothing but `edge-egress`, which reaches only the hosts you list | phases 28, 29 |
| A provider key planted in or leaked to an agent is used | For a keyless host `edge-egress` removes every credential the agent sends and sends a signed assertion of the agent's identity instead | phase 30 |
| One agent uses up a shared provider allowance | Per-agent rate limits on `edge-egress` | phase 31 |
| An egress decision is erased or changed afterwards | Every decision is in a hash chain; `scripts/verify-decisions.sh` finds a changed or missing record | phase 31 |
| One team reads or changes another team's routes | The broker derives the team from the team's key, never from the request; a team's services are named and stored under it | `osb/tests/test_tenancy.py` |
| A gateway node holds another node's keys | Each node's gateway is sent only the keys of the gateways placed on it | phase 16 |
| The configuration channel is read or spoofed | The gateway and the control plane talk mutually authenticated TLS, with certificates from your own CA, renewed by cert-manager | phase 7 |
| A stolen database backup reveals your TLS keys | Every stored key is sealed with the KEK, which is not in the database | phase 33 |
| The KEK leaks | Rotate it: every key is sealed again under the new one and the old one is dropped | phase 33 |
| A bad or empty configuration takes the gateway down | The control plane refuses to publish it and the gateway keeps the last good one | phases 13, 14, 22 |
| A modified image is run | Every first-party image is signed, with an SBOM and provenance; Kyverno refuses an unsigned one | phase 26 |
| The node or hypervisor reads the authorisation service's memory | Optional: run it on confidential nodes, where it starts only with a verified attestation | phase 19 |
| Edge depends on, or leaks to, the internet | Nothing in Edge makes a call out; it runs with no route to the internet | phase 32 |
| The gateway's admin interface is used to change it | Envoy's admin port listens on the pod's localhost only (`127.0.0.1:9901`) | the `edge-proxy` chart |

## What it does not defend against yet

- **Wallet rules, approvals and metering are not applied at the edge.** Lens applies them when an
  agent's call goes through it; Edge does not yet run Lens, so an agent that calls a provider
  directly through `edge-egress` is limited by the destination list and rate limits, not by its
  wallet. See [data flow](data-flow.md#lens-and-the-answer-pool).
- **Rate limiting by identity at the gateway** (`edge-ratelimit`) is built but not routed to.
  Per-route and per-agent limits work.
- **The control plane's admin API is off** until you give it a key (`adminApi.existingSecret`).
- **The bundled datastores do not use TLS** inside the cluster, and run one copy each. Use your own
  with TLS for production ([sizing and HA](sizing-and-ha.md#high-availability)).
- **Images from your own registry are not checked at admission**: the signature policy matches
  `ghcr.io/talyvor/*` ([air-gap](air-gap.md#what-is-different-without-the-internet)).
- **A broker team key is a bearer secret.** Anyone holding it acts as that team. Store it like a
  password; Edge keeps only its hash.
- **Denial of service** beyond rate limits: Edge does not absorb a flood aimed at the nodes' ports.
  Put it behind your load balancer's protection.
