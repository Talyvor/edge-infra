//! Implementation of Envoy's ext_authz Authorization service.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, CheckResponse, HeaderAppendAction, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckRequestExt, CheckResponseExt, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use envoy_types::pb::google::protobuf::{value::Kind, Struct, Value};
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde::{Deserialize, Deserializer};
use tonic::{Request, Response, Status};

use crate::jwks::JwksCache;
use crate::metrics::Metrics;
use crate::transit::{self, TransitSigner, Vouch};

/// JWT claims the service inspects. `aud` is validated by jsonwebtoken.
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    /// Subject identifier (typically the user ID).
    pub sub: String,
    /// Expiration time (seconds since epoch).
    pub exp: usize,
    /// Issued-at time (seconds since epoch).
    pub iat: usize,
    /// Intended audience(s); validated against the configured audience. A
    /// single string (Okta, Auth0) or an array (Kubernetes ServiceAccounts).
    #[serde(deserialize_with = "one_or_many")]
    pub aud: Vec<String>,
    /// Issuer; validated against the configured issuer.
    pub iss: String,
    /// Optional team membership; forwarded as `x-user-teams`.
    pub teams: Option<Vec<String>>,
    /// Optional verified email; forwarded as `x-user-email` so backends can
    /// join the identity to their own per-workspace member records.
    pub email: Option<String>,
}

fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(aud) => vec![aud],
        OneOrMany::Many(auds) => auds,
    })
}

/// An identity provider this gateway trusts: the keys its tokens must be
/// signed with and the issuer and audience they must carry.
#[derive(Debug)]
pub struct TrustedIssuer {
    /// This issuer's JWKS, resolving signing keys by `kid`.
    pub jwks: Arc<JwksCache>,
    /// Pre-built validation config (algorithm, audience, issuer).
    pub validation: Validation,
}

impl TrustedIssuer {
    /// Trust RS256 tokens from `issuer` for `audience`, signed by a key in `jwks`.
    pub fn new(issuer: &str, audience: &str, jwks: Arc<JwksCache>) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer]);
        // A token is refused before its `nbf` as well as after its `exp` (B67.7).
        validation.validate_nbf = true;
        Self { jwks, validation }
    }
}

/// gRPC ext_authz service: validates a Bearer JWT and forwards identity headers.
#[derive(Debug)]
pub struct AuthService {
    /// Trusted issuers keyed by `iss`. A token is checked only against the
    /// keys of the issuer it names, so one provider's key can never vouch
    /// for a token claiming to come from another.
    pub issuers: HashMap<String, TrustedIssuer>,
    /// Metrics handle shared with the metrics HTTP server.
    pub metrics: Arc<Metrics>,
    /// Mints the signed transit assertion injected as `x-gateway-auth`, so a
    /// backend can verify a request actually passed through this gateway.
    pub transit: Arc<TransitSigner>,
}

#[tonic::async_trait]
impl Authorization for AuthService {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let req = request.into_inner();

        // agent: a keyless egress destination (edge-egress, B28.224). The agent
        // proves who it is with its workload token and every credential it sent
        // is removed before the request leaves.
        let (method, host, path) = request_line(&req);
        if auth_policy(&req) == Some("agent") {
            return Ok(Response::new(self.check_agent(&req, method, host, path)));
        }

        // jwt_or_mtls: if this route allows mTLS and Envoy forwarded a verified
        // client cert (source.certificate, populated by include_peer_certificate),
        // authorize on the cert alone — injecting a TRANSPORT marker, never a user
        // identity. A cert-less caller falls through to the JWT path below.
        if let Some(subject) = mtls_cert_subject(&req) {
            let vouch = Vouch {
                sub: &subject,
                amr: "mtls",
                method,
                host,
                path,
                ..Default::default()
            };
            let Ok(assertion) = self.transit.sign(&vouch) else {
                return Ok(Response::new(self.denied("transit assertion unavailable")));
            };
            self.metrics
                .auth_requests
                .with_label_values(&["ok_mtls"])
                .inc();
            return Ok(Response::new(self.allow_mtls(&subject, assertion)));
        }

        let headers = match req.get_client_headers() {
            Some(h) => h,
            None => return Ok(Response::new(self.denied("client headers missing"))),
        };

        let auth_header = match headers
            .get("authorization")
            .or_else(|| headers.get("Authorization"))
        {
            Some(v) => v,
            None => return Ok(Response::new(self.denied("missing authorization header"))),
        };

        let Some(token) = bearer(auth_header) else {
            return Ok(Response::new(self.denied("Bearer scheme required")));
        };

        let claims = match self.verify_jwt(token) {
            Ok(claims) => claims,
            Err(msg) => return Ok(Response::new(self.denied(&msg))),
        };

        let teams = claims.teams.clone().unwrap_or_default().join(",");
        let email = claims.email.clone().unwrap_or_default();
        let vouch = Vouch {
            sub: &claims.sub,
            amr: "jwt",
            idp: Some(&claims.iss),
            email: claims.email.as_deref(),
            teams: claims.teams.as_deref(),
            method,
            host,
            path,
        };
        let Ok(assertion) = self.transit.sign(&vouch) else {
            return Ok(Response::new(self.denied("transit assertion unavailable")));
        };

        let mut builder = OkHttpResponseBuilder::new();
        builder
            // OverwriteIfExistsOrAdd ensures a malicious client can't smuggle
            // these identity headers in alongside their own value.
            .add_header(
                "x-user-id",
                claims.sub.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            )
            .add_header(
                "x-user-teams",
                teams,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            )
            .add_header(
                "x-auth-iss",
                claims.iss.clone(),
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            )
            // Verified email for the backend's workspace-member join. Always
            // overwrite (keep_empty_value = true) so a missing claim still
            // strips any x-user-email a client tried to smuggle in.
            .add_header(
                "x-user-email",
                email,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            )
            // Transit-proof: a signed, single-use assertion for THIS request
            // and identity, so a backend can verify it came through the
            // gateway. Overwrite (not append) strips any value a client tried
            // to smuggle in.
            .add_header(
                transit::HEADER,
                assertion,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                false,
            );

        let mut response = CheckResponse::with_status(Status::ok("ok"));
        response.set_http_response(builder);

        self.metrics.auth_requests.with_label_values(&["ok"]).inc();
        Ok(Response::new(response))
    }
}

impl AuthService {
    /// Verify a bearer JWT against the issuer it names. The error is the
    /// reason given to the caller.
    fn verify_jwt(&self, token: &str) -> Result<Claims, String> {
        let timer = self.metrics.jwt_validation.start_timer();
        let kid = match decode_header(token) {
            Ok(h) => h.kid.ok_or("JWT missing kid")?,
            Err(_) => return Err("malformed JWT".into()),
        };
        // Route on the unverified `iss`; decode() below re-checks it against
        // that issuer's validation once the signature verifies.
        let idp = unverified_issuer(token)
            .and_then(|iss| self.issuers.get(&iss))
            .ok_or("untrusted issuer")?;
        let key = idp.jwks.get_key(&kid).ok_or("unknown kid")?;
        let claims = decode::<Claims>(token, &key, &idp.validation)
            .map_err(|err| format!("invalid JWT: {err}"))?
            .claims;
        timer.observe_duration();
        Ok(claims)
    }

    /// Authorize an agent calling a keyless destination through edge-egress.
    /// Its identity is the workload token in Proxy-Authorization (a projected
    /// ServiceAccount token, verified like any JWT). Every credential the agent
    /// sent — headers and URL parameters, the workload token included — is
    /// removed, and the signed transit assertion is the only proof of who is
    /// calling that leaves the cluster.
    fn check_agent(&self, req: &CheckRequest, method: &str, host: &str, path: &str) -> CheckResponse {
        let Some(headers) = req.get_client_headers() else {
            return self.agent_denied("client headers missing");
        };
        let Some(token) = headers.get("proxy-authorization").and_then(|v| bearer(v)) else {
            return self.agent_denied(
                "this destination is keyless: send the agent's workload token as Proxy-Authorization: Bearer <token>",
            );
        };
        let claims = match self.verify_jwt(token) {
            Ok(claims) => claims,
            Err(msg) => return self.agent_denied(&msg),
        };

        // The assertion names the request as it leaves, so a URL credential
        // never travels inside it either.
        let (params, sent_path) = strip_credential_params(path);
        let vouch = Vouch {
            sub: &claims.sub,
            amr: "agent",
            idp: Some(&claims.iss),
            method,
            host,
            path: &sent_path,
            ..Default::default()
        };
        let Ok(assertion) = self.transit.sign(&vouch) else {
            return self.agent_denied("transit assertion unavailable");
        };

        let mut builder = OkHttpResponseBuilder::new();
        let mut names: Vec<&String> = headers.keys().filter(|n| is_credential_header(n)).collect();
        names.sort();
        for name in names {
            builder.remove_header(name.as_str());
        }
        for name in params {
            builder.remove_query_parameter(name);
        }
        builder.add_header(
            transit::HEADER,
            assertion,
            Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
            false,
        );
        let mut response = CheckResponse::with_status(Status::ok("ok"));
        response.set_http_response(builder);
        response.set_dynamic_metadata(Some(agent_metadata(&claims.sub)));
        self.metrics
            .auth_requests
            .with_label_values(&["ok_agent"])
            .inc();
        response
    }

    /// A 407 for an agent on a keyless destination: it reached a proxy that
    /// wants the agent's own token, not the provider's.
    fn agent_denied(&self, msg: &str) -> CheckResponse {
        self.metrics
            .auth_requests
            .with_label_values(&["denied"])
            .inc();
        let mut builder = DeniedHttpResponseBuilder::new();
        builder
            .set_http_status(HttpStatusCode::ProxyAuthenticationRequired)
            .add_header("proxy-authenticate", "Bearer realm=\"edge-egress\"", None, false)
            .set_body(format!("edge-egress: {msg}\n"));
        let mut response = CheckResponse::with_status(Status::unauthenticated(msg));
        response.set_http_response(builder);
        response
    }

    /// Build a 401-with-body deny response and bump the denied counter.
    fn denied(&self, msg: &str) -> CheckResponse {
        self.metrics
            .auth_requests
            .with_label_values(&["denied"])
            .inc();

        let mut builder = DeniedHttpResponseBuilder::new();
        builder
            .set_http_status(HttpStatusCode::Unauthorized)
            .set_body(msg.to_string());

        let mut response = CheckResponse::with_status(Status::unauthenticated(msg));
        response.set_http_response(builder);
        response
    }

    /// Authorize a request that presented a verified client cert on a jwt_or_mtls
    /// route. Injects a TRANSPORT marker (`x-auth-method: mtls` + the cert
    /// subject) and the gateway transit-proof — deliberately NOT
    /// `x-user-id`/`x-user-teams`/`x-user-email`, so a client cert never
    /// masquerades as a user identity. The subject is informational for the
    /// backend; identity semantics differ from the JWT path by design.
    fn allow_mtls(&self, cert_subject: &str, assertion: String) -> CheckResponse {
        let mut builder = OkHttpResponseBuilder::new();
        for (name, value) in mtls_headers(cert_subject, assertion) {
            // keep_empty_value=true so a missing/unparseable subject still strips
            // any value a client tried to smuggle in under these header names.
            builder.add_header(
                name,
                value,
                Some(HeaderAppendAction::OverwriteIfExistsOrAdd),
                true,
            );
        }
        let mut response = CheckResponse::with_status(Status::ok("ok"));
        response.set_http_response(builder);
        response
    }
}

/// The headers injected for a cert-authorized (jwt_or_mtls) request: a transport
/// marker, the cert subject, and the gateway transit-proof. Deliberately excludes
/// every x-user-* header — a client cert authorizes transit, it does NOT
/// masquerade as a user identity (that is only the JWT path's job).
fn mtls_headers(cert_subject: &str, assertion: String) -> Vec<(&'static str, String)> {
    vec![
        ("x-auth-method", "mtls".to_string()),
        ("x-client-cert-subject", cert_subject.to_string()),
        (transit::HEADER, assertion),
    ]
}

/// The token in a `Bearer <token>` header value.
fn bearer(value: &str) -> Option<&str> {
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
}

/// The route's auth_policy context extension, when it set one.
fn auth_policy(req: &CheckRequest) -> Option<&str> {
    req.attributes
        .as_ref()?
        .context_extensions
        .get("auth_policy")
        .map(String::as_str)
}

/// Whether a header or URL parameter name carries a credential, by the names
/// providers and agents put keys, tokens and secrets under: Authorization,
/// x-api-key, api-key, x-goog-api-key, Ocp-Apim-Subscription-Key, cookies,
/// ?key=, ?access_token= and the like. `_` and `-` are treated alike.
fn is_credential_name(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "authorization",
        "proxy-authorization",
        "cookie",
        "key",
        "sig",
    ];
    const PARTS: &[&str] = &[
        "api-key",
        "apikey",
        "access-key",
        "subscription-key",
        "token",
        "secret",
        "password",
        "credential",
        "signature",
        "x-auth",
    ];
    let n = name.to_ascii_lowercase().replace('_', "-");
    EXACT.contains(&n.as_str()) || PARTS.iter().any(|p| n.contains(p))
}

/// The ext_authz dynamic metadata an agent's allowed request carries: the
/// ServiceAccount it proved, under `agent`. edge-egress keys the agent's rate
/// limit on it and writes it into its access and decision logs (B28.228).
fn agent_metadata(sub: &str) -> Struct {
    Struct {
        fields: HashMap::from([(
            "agent".to_string(),
            Value {
                kind: Some(Kind::StringValue(sub.to_string())),
            },
        )]),
    }
}

/// A header the agent may not send on: a credential, or an identity header
/// only the gateway sets (x-user-*, x-client-cert-subject). The transit header
/// is never one: the gateway overwrites whatever value a client put there.
fn is_credential_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if n == transit::HEADER {
        return false;
    }
    n.starts_with("x-user-") || n == "x-client-cert-subject" || is_credential_name(&n)
}

/// The credential URL parameters in `path`, and the path as Envoy sends it on
/// once they are removed. Envoy rebuilds the query from what is left, ordered
/// by name, so the path is rebuilt the same way; with nothing to remove it is
/// returned as it came.
fn strip_credential_params(path: &str) -> (Vec<String>, String) {
    let Some((base, query)) = path.split_once('?') else {
        return (Vec::new(), path.to_string());
    };
    let mut removed: Vec<String> = Vec::new();
    let mut kept: std::collections::BTreeMap<&str, Vec<&str>> = Default::default();
    for param in query.split('&') {
        let (name, value) = param.split_once('=').unwrap_or((param, ""));
        // Judged by the name the provider will decode (%6Bey is key); removed
        // by the name Envoy sees.
        let decoded = percent_encoding::percent_decode_str(name).decode_utf8_lossy();
        if is_credential_name(&decoded) {
            if !removed.iter().any(|r| r == name) {
                removed.push(name.to_string());
            }
        } else {
            kept.entry(name).or_default().push(value);
        }
    }
    if removed.is_empty() {
        return (removed, path.to_string());
    }
    let mut sent = base.to_string();
    let mut delim = '?';
    for (name, values) in kept {
        for value in values {
            sent.push(delim);
            sent.push_str(name);
            sent.push('=');
            sent.push_str(value);
            delim = '&';
        }
    }
    (removed, sent)
}

/// The `iss` a token claims, read WITHOUT verifying it — only to pick which
/// issuer's keys and rules the token is then verified against.
fn unverified_issuer(token: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Iss {
        iss: String,
    }
    let payload = URL_SAFE_NO_PAD.decode(token.split('.').nth(1)?).ok()?;
    serde_json::from_slice::<Iss>(&payload).ok().map(|c| c.iss)
}

/// The method, host and path Envoy is authorizing — what the transit
/// assertion is bound to. Empty strings when Envoy sent no HTTP attributes.
fn request_line(req: &CheckRequest) -> (&str, &str, &str) {
    match req
        .attributes
        .as_ref()
        .and_then(|a| a.request.as_ref())
        .and_then(|r| r.http.as_ref())
    {
        Some(http) => (&http.method, &http.host, &http.path),
        None => ("", "", ""),
    }
}

/// Decide whether to authorize on a client cert: Some(subject) when this route is
/// jwt_or_mtls AND Envoy forwarded a verified peer certificate; None otherwise
/// (the caller falls back to the JWT path). Pure so it is unit-testable without a
/// full AuthService.
fn mtls_cert_subject(req: &CheckRequest) -> Option<String> {
    let attrs = req.attributes.as_ref()?;
    if attrs
        .context_extensions
        .get("auth_policy")
        .map(String::as_str)
        != Some("jwt_or_mtls")
    {
        return None;
    }
    let cert = &attrs.source.as_ref()?.certificate;
    if cert.is_empty() {
        return None;
    }
    Some(client_cert_subject(cert))
}

/// Parse the Subject DN from Envoy's URL+PEM-encoded peer certificate
/// (source.certificate). Best effort: returns "" if it can't be decoded/parsed —
/// the cert was ALREADY verified by Envoy's validation_context, so authorization
/// still proceeds; only the informational subject header is empty.
fn client_cert_subject(url_encoded_pem: &str) -> String {
    let decoded = match percent_encoding::percent_decode_str(url_encoded_pem).decode_utf8() {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    match x509_parser::pem::parse_x509_pem(decoded.as_bytes()) {
        Ok((_, pem)) => match pem.parse_x509() {
            Ok(cert) => cert.subject().to_string(),
            Err(_) => String::new(),
        },
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use envoy_types::pb::envoy::service::auth::v3::{attribute_context, AttributeContext};
    use std::collections::HashMap;

    // A self-signed test client cert, subject "CN=test-client, O=EdgeInfra".
    const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIDNDCCAhygAwIBAgITA0zI5QMNOSftMEOJqr1g8evsNzANBgkqhkiG9w0BAQsF\n\
ADAqMRQwEgYDVQQDDAt0ZXN0LWNsaWVudDESMBAGA1UECgwJRWRnZUluZnJhMB4X\n\
DTI2MDcwODIyMjkxM1oXDTM2MDcwNTIyMjkxM1owKjEUMBIGA1UEAwwLdGVzdC1j\n\
bGllbnQxEjAQBgNVBAoMCUVkZ2VJbmZyYTCCASIwDQYJKoZIhvcNAQEBBQADggEP\n\
ADCCAQoCggEBAJ+Nb+g57/Dpgmv2K6Q+dfQfm+8RUL8iWmIJch5ENoFHSUDG/g7n\n\
qm0ZxEXTTQriWrlerO0El2zThKSH7Z5TJ7mNT6XuTeUlf210LmW54/uAu0NpKtwi\n\
Bli6X6Wh/uOp0jjyZ7NENwoXqvJ/YAhdLGyqmvTGP2WQxJpNjywP86KqcQQ97tng\n\
TlulwGtV3zgjnALzBX2UmPK4PpTAlvM577L0u49L0/AnfWOFka3OgqvAdXbkUhbN\n\
e4ibKX/9cwYV21V4DyV5VsDZwjlrQ3dZgNK6aE+PE+LCWAWId8p/tkyMkRED6aKS\n\
OPYQEa0qDXtJkoRmApopxH/MKjueGzfct08CAwEAAaNTMFEwHQYDVR0OBBYEFDhd\n\
FZh5wqENkzpAhUXkH7PsfmfAMB8GA1UdIwQYMBaAFDhdFZh5wqENkzpAhUXkH7Ps\n\
fmfAMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJWsToocNzg2\n\
6bLDv0b53j6Q4mp69JHlhfYI7RHrF/8F8J8NY+hPtt62nnlcJT0mkfo7LirdQFtV\n\
Q+Rm+prpJyBhaTqYJS+pQcEFumAw9JSk+0URX2EtfwGNeFjfs4igD9R4pC8Bkql4\n\
+KJ+9O7/2A7GzoAhu/3UYs/es4fW2Q9FG1mksF+sIu/zEBdYwiYifRDChkxIzwBf\n\
zUExQh59l4e7Ya2Ei+gnhdmnq33W9+J1C3JfKv7U87Qk2tlXt8UCnJORsIDxNg3a\n\
hFUpfp8pVELdEiLTqryJQ/H/YbkQqKZudUOIAryeR5MIAaGvesIdaygG6QvVbM2j\n\
aMVnTHM8GoM=\n\
-----END CERTIFICATE-----\n";

    fn req_with(auth_policy: Option<&str>, cert: Option<&str>) -> CheckRequest {
        let mut ctx = HashMap::new();
        if let Some(p) = auth_policy {
            ctx.insert("auth_policy".to_string(), p.to_string());
        }
        let source = cert.map(|c| attribute_context::Peer {
            certificate: c.to_string(),
            ..Default::default()
        });
        CheckRequest {
            attributes: Some(AttributeContext {
                source,
                context_extensions: ctx,
                ..Default::default()
            }),
        }
    }

    // A jwt_or_mtls route WITH a presented cert → authorize on the cert; the
    // subject carries the cert's CN.
    #[test]
    fn cert_present_on_jwt_or_mtls_authorizes_with_subject() {
        let subject = mtls_cert_subject(&req_with(Some("jwt_or_mtls"), Some(TEST_CERT_PEM)))
            .expect("jwt_or_mtls + cert must authorize on the cert");
        assert!(
            subject.contains("test-client"),
            "subject must carry the client cert CN"
        );
    }

    // A jwt_or_mtls route with NO cert → fall back to the JWT path.
    #[test]
    fn no_cert_on_jwt_or_mtls_falls_back_to_jwt() {
        assert!(mtls_cert_subject(&req_with(Some("jwt_or_mtls"), None)).is_none());
        assert!(mtls_cert_subject(&req_with(Some("jwt_or_mtls"), Some(""))).is_none());
    }

    // A cert on a NON-jwt_or_mtls route (jwt, or no context) → JWT path, never
    // authorized on the cert (no policy confusion).
    #[test]
    fn cert_without_jwt_or_mtls_context_is_ignored() {
        assert!(mtls_cert_subject(&req_with(Some("jwt"), Some(TEST_CERT_PEM))).is_none());
        assert!(mtls_cert_subject(&req_with(None, Some(TEST_CERT_PEM))).is_none());
    }

    // Keyless egress: what an agent might carry a key in is a credential; what
    // a model call needs to work is not.
    #[test]
    fn credential_names_cover_provider_keys_and_spare_the_request() {
        for name in [
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "api-key",
            "x-goog-api-key",
            "ocp-apim-subscription-key",
            "cookie",
            "x-amz-security-token",
            "x-user-id",
            "x-client-cert-subject",
        ] {
            assert!(is_credential_header(name), "{name} must be stripped");
        }
        for name in [
            "content-type",
            "accept",
            "user-agent",
            "openai-organization",
            "anthropic-version",
            "x-gateway-auth",
        ] {
            assert!(!is_credential_header(name), "{name} must be kept");
        }
    }

    // A key in the URL is removed, and the path the assertion names is the one
    // Envoy sends on: the rest of the query, ordered by name.
    #[test]
    fn credential_params_are_removed_and_the_rest_reordered_as_envoy_does() {
        let (removed, sent) = strip_credential_params("/v1/models?z=1&key=sk-planted&a=2&access_token=t");
        assert_eq!(removed, ["key", "access_token"]);
        assert_eq!(sent, "/v1/models?a=2&z=1");
        let (removed, sent) = strip_credential_params("/v1/models?%6Bey=sk-planted");
        assert_eq!(removed, ["%6Bey"], "an encoded name is still a key");
        assert_eq!(sent, "/v1/models");
        let (removed, sent) = strip_credential_params("/v1/models?z=1&a=2");
        assert!(removed.is_empty());
        assert_eq!(sent, "/v1/models?z=1&a=2", "a query with no credential is left as it came");
    }

    // The subject parser extracts the DN from a URL-encoded PEM (as Envoy sends).
    #[test]
    fn client_cert_subject_parses_dn_from_url_encoded_pem() {
        let url_encoded = TEST_CERT_PEM.replace('\n', "%0A");
        let subject = client_cert_subject(&url_encoded);
        assert!(
            subject.contains("test-client"),
            "must parse subject from a URL-encoded PEM"
        );
    }

    // The cert path injects ONLY transport markers — never a user identity. This
    // is the load-bearing security property: a client cert must not be able to
    // masquerade as a user (no x-user-id/teams/email).
    #[test]
    fn mtls_headers_are_transport_only_never_user_identity() {
        let hdrs = mtls_headers("CN=test-client", "assertion".to_string());
        let names: Vec<&str> = hdrs.iter().map(|(n, _)| *n).collect();
        assert!(
            names.contains(&"x-auth-method"),
            "must mark the auth method"
        );
        assert!(
            names.contains(&"x-client-cert-subject"),
            "must carry the cert subject"
        );
        for n in &names {
            assert!(
                !n.starts_with("x-user-"),
                "cert path must NOT inject a user-identity header; found {n}"
            );
        }
        let method = hdrs
            .iter()
            .find(|(n, _)| *n == "x-auth-method")
            .map(|(_, v)| v.as_str());
        assert_eq!(method, Some("mtls"));
    }
}
