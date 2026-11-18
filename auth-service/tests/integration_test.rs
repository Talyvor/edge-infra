//! Integration tests for the ext_authz Authorization service.
//!
//! Each test builds a fresh AuthService backed by an in-memory JWKS containing
//! a freshly generated RSA key pair, then drives `check()` directly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use auth_service::auth::{AuthService, TrustedIssuer};
use auth_service::jwks::JwksCache;
use auth_service::metrics::Metrics;
use auth_service::transit::{TransitError, TransitSigner, TransitVerifier};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use envoy_types::ext_authz::v3::pb::{
    Authorization, CheckRequest, HeaderAppendAction, HeaderValueOption, HttpResponse,
};
use envoy_types::pb::envoy::service::auth::v3::AttributeContext;
use envoy_types::pb::google::protobuf::value::Kind;
use envoy_types::pb::envoy::service::auth::v3::attribute_context::{
    HttpRequest, Request as AttrRequest,
};
use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse,
    RSAKeyParameters, RSAKeyType,
};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rsa::RsaPrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use serde::Serialize;
use tonic::Request;

const TEST_AUDIENCE: &str = "edge.example.com";
const TEST_ISSUER: &str = "https://auth.example.com";
const TEST_KID: &str = "test-kid";
const TEST_TRANSIT_ISSUER: &str = "edge-gateway";

#[derive(Debug, Serialize)]
struct TestClaims {
    sub: String,
    exp: usize,
    iat: usize,
    aud: Vec<String>,
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    teams: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

struct Fixture {
    private_pem: String,
    jwks: JwkSet,
}

fn make_fixture(kid: &str) -> Fixture {
    let mut rng = rand::thread_rng();
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate rsa key");
    let public_key = private_key.to_public_key();

    let n = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

    let jwk = Jwk {
        common: CommonParameters {
            public_key_use: Some(PublicKeyUse::Signature),
            key_operations: None,
            key_algorithm: Some(KeyAlgorithm::RS256),
            key_id: Some(kid.to_string()),
            x509_url: None,
            x509_chain: None,
            x509_sha1_fingerprint: None,
            x509_sha256_fingerprint: None,
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n,
            e,
        }),
    };
    let pem = private_key
        .to_pkcs1_pem(LineEnding::LF)
        .expect("encode pkcs1 pem");

    Fixture {
        private_pem: pem.to_string(),
        jwks: JwkSet { keys: vec![jwk] },
    }
}

fn now_secs() -> usize {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs() as usize
}

fn sign_jwt(private_pem: &str, kid: &str, claims: &impl Serialize) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("encoding key");
    encode(&header, claims, &key).expect("encode jwt")
}

fn build_check_request(authorization: Option<&str>) -> Request<CheckRequest> {
    build_check_request_with(authorization, &[])
}

/// Like `build_check_request` but lets a test seed extra client-supplied
/// headers — used to prove the gateway overwrites smuggled identity headers.
fn build_check_request_with(
    authorization: Option<&str>,
    extra: &[(&str, &str)],
) -> Request<CheckRequest> {
    let mut headers = HashMap::new();
    if let Some(value) = authorization {
        headers.insert("authorization".to_string(), value.to_string());
    }
    for (key, value) in extra {
        headers.insert((*key).to_string(), (*value).to_string());
    }
    let req = CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(AttrRequest {
                http: Some(HttpRequest {
                    method: "GET".into(),
                    headers,
                    path: "/".into(),
                    host: "example.com".into(),
                    scheme: "http".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
    };
    Request::new(req)
}

fn build_service(jwks: JwkSet) -> (AuthService, Arc<Metrics>) {
    build_multi_issuer_service(&[(TEST_ISSUER, TEST_AUDIENCE, jwks)])
}

/// An AuthService trusting each (issuer, audience, JWKS) — one gateway in
/// front of several identity providers.
fn build_multi_issuer_service(idps: &[(&str, &str, JwkSet)]) -> (AuthService, Arc<Metrics>) {
    let metrics = Metrics::new().expect("metrics");
    let issuers = idps
        .iter()
        .map(|(iss, aud, jwks)| {
            let idp = TrustedIssuer::new(iss, aud, JwksCache::from_jwk_set(jwks.clone()));
            (iss.to_string(), idp)
        })
        .collect();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .expect("transit keygen");
    let transit = TransitSigner::from_pkcs8(pkcs8.as_ref(), TEST_TRANSIT_ISSUER, 30)
        .expect("transit signer");
    let service = AuthService {
        issuers,
        metrics: Arc::clone(&metrics),
        transit: Arc::new(transit),
    };
    (service, metrics)
}

/// A backend's verifier for `svc`'s assertions, built from its public JWKS.
fn backend_verifier(svc: &AuthService) -> TransitVerifier {
    TransitVerifier::from_jwks(&svc.transit.jwks(), TEST_TRANSIT_ISSUER).expect("verifier")
}

fn header_value<'a>(headers: &'a [HeaderValueOption], key: &str) -> Option<&'a str> {
    headers
        .iter()
        .filter_map(|opt| opt.header.as_ref())
        .find(|h| h.key.eq_ignore_ascii_case(key))
        .map(|h| h.value.as_str())
}

/// Returns the full HeaderValueOption (not just the value) so a test can
/// assert the append action Envoy will apply.
fn header_opt<'a>(
    headers: &'a [HeaderValueOption],
    key: &str,
) -> Option<&'a HeaderValueOption> {
    headers.iter().find(|opt| {
        opt.header
            .as_ref()
            .is_some_and(|h| h.key.eq_ignore_ascii_case(key))
    })
}

fn valid_claims(sub: &str, teams: Option<Vec<String>>) -> TestClaims {
    let now = now_secs();
    TestClaims {
        sub: sub.to_string(),
        exp: now + 3600,
        iat: now,
        aud: vec![TEST_AUDIENCE.to_string()],
        iss: TEST_ISSUER.to_string(),
        teams,
        email: None,
    }
}

#[tokio::test]
async fn test_valid_jwt_returns_ok() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-1", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();

    let code = response
        .status
        .as_ref()
        .expect("status present")
        .code;
    assert_eq!(code, 0, "expected OK (0), got {code}");

    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(header_value(&ok.headers, "x-user-id"), Some("user-1"));
    assert_eq!(
        header_value(&ok.headers, "x-auth-iss"),
        Some(TEST_ISSUER)
    );
}

#[tokio::test]
async fn test_gateway_auth_header_injected() {
    // The transit-proof header is what lets a backend (e.g. Track) trust
    // x-user-id: without it, an exposed backend port lets anyone forge
    // identity. Every authenticated request carries a signed assertion that
    // a backend verifies once, for this request and this user.
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-7", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();

    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    let assertion = header_value(&ok.headers, "x-gateway-auth")
        .expect("gateway must inject the transit assertion");
    let backend = backend_verifier(&svc);
    let vouched = backend
        .verify(assertion, "GET", "example.com", "/")
        .expect("a backend must accept the gateway's assertion");
    assert_eq!(vouched.sub, "user-7");
    assert_eq!(vouched.amr, "jwt");
    assert_eq!(
        backend.verify(assertion, "GET", "example.com", "/"),
        Err(TransitError::Replayed),
        "the same assertion must not be accepted twice"
    );
}

#[tokio::test]
async fn test_gateway_auth_overwrites_client_supplied_value() {
    // A malicious client tries to smuggle its own transit-proof header in
    // alongside the request. The gateway must overwrite it with the real
    // secret, never append, so the backend never sees the forgery.
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-8", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request_with(
            Some(&auth),
            &[("x-gateway-auth", "forged-by-client")],
        ))
        .await
        .expect("rpc")
        .into_inner();

    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };

    let opt = header_opt(&ok.headers, "x-gateway-auth")
        .expect("x-gateway-auth must be present");
    let value = opt.header.as_ref().map(|h| h.value.as_str()).unwrap_or_default();
    assert_ne!(value, "forged-by-client", "the client's forgery must not survive");
    backend_verifier(&svc)
        .verify(value, "GET", "example.com", "/")
        .expect("value must be the gateway's own assertion");
    assert_eq!(
        opt.append_action,
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        "transit-proof header must overwrite, never append"
    );
}

#[tokio::test]
async fn test_email_header_forwarded() {
    // The issuer puts the verified email in the JWT; the gateway forwards it
    // as x-user-email so Track can join the identity to its per-workspace
    // member (members are unique by email within a workspace).
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = TestClaims {
        email: Some("ada@example.com".into()),
        ..valid_claims("user-9", None)
    };
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(
        header_value(&ok.headers, "x-user-email"),
        Some("ada@example.com"),
        "verified email must be forwarded for the workspace-member join"
    );
}

#[tokio::test]
async fn test_email_absent_overwrites_client_supplied_value() {
    // No email claim in the token: the gateway must STILL overwrite any
    // client-supplied x-user-email (to empty) so a caller cannot forge one.
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-10", None); // email: None
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request_with(
            Some(&auth),
            &[("x-user-email", "forged@evil.com")],
        ))
        .await
        .expect("rpc")
        .into_inner();
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    let opt = header_opt(&ok.headers, "x-user-email")
        .expect("x-user-email must be present, overwriting any client value");
    assert_eq!(
        opt.header.as_ref().map(|h| h.value.as_str()),
        Some(""),
        "absent email must overwrite the client's forgery with empty"
    );
    assert_eq!(
        opt.append_action,
        HeaderAppendAction::OverwriteIfExistsOrAdd as i32,
        "x-user-email must overwrite, never append"
    );
}

#[tokio::test]
async fn test_missing_auth_header_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks);

    let response = svc
        .check(build_check_request(None))
        .await
        .expect("rpc")
        .into_inner();

    let code = response.status.expect("status").code;
    assert_eq!(code, 16, "expected UNAUTHENTICATED (16), got {code}");
}

#[tokio::test]
async fn test_expired_jwt_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let now = now_secs();
    let claims = TestClaims {
        sub: "user-2".into(),
        exp: now - 3600,
        iat: now - 7200,
        aud: vec![TEST_AUDIENCE.into()],
        iss: TEST_ISSUER.into(),
        teams: None,
        email: None,
    };
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.status.expect("status").code, 16);
}

#[tokio::test]
async fn test_wrong_audience_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let now = now_secs();
    let claims = TestClaims {
        sub: "user-3".into(),
        exp: now + 3600,
        iat: now,
        aud: vec!["someone-else".into()],
        iss: TEST_ISSUER.into(),
        teams: None,
        email: None,
    };
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.status.expect("status").code, 16);
}

#[tokio::test]
async fn test_unknown_kid_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-4", None);
    // sign with a kid that isn't in the JWKS
    let token = sign_jwt(&fix.private_pem, "rogue-kid", &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    assert_eq!(response.status.expect("status").code, 16);
}

#[tokio::test]
async fn test_teams_header_forwarded() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());

    let claims = valid_claims("user-5", Some(vec!["eng".into(), "platform".into()]));
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");

    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(
        header_value(&ok.headers, "x-user-teams"),
        Some("eng,platform")
    );
}

#[tokio::test]
async fn test_metrics_incremented() {
    let fix = make_fixture(TEST_KID);
    let (svc, metrics) = build_service(fix.jwks.clone());

    // One denied
    let _ = svc
        .check(build_check_request(None))
        .await
        .expect("rpc");

    // One OK
    let claims = valid_claims("user-6", None);
    let token = sign_jwt(&fix.private_pem, TEST_KID, &claims);
    let auth = format!("Bearer {token}");
    let _ = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc");

    let ok_count = metrics.auth_requests.with_label_values(&["ok"]).get();
    let denied_count = metrics.auth_requests.with_label_values(&["denied"]).get();
    assert_eq!(ok_count, 1, "ok counter");
    assert_eq!(denied_count, 1, "denied counter");
}

const OKTA_ISSUER: &str = "https://dev-31337.okta.com/oauth2/default";
const OKTA_AUDIENCE: &str = "api://default";
const SA_ISSUER: &str = "https://kubernetes.default.svc.cluster.local";

/// An Okta access token's claims: `aud` is a single STRING, plus Okta's
/// own cid/uid/scp/ver/jti claims the gateway does not read.
fn okta_claims(sub: &str) -> serde_json::Value {
    let now = now_secs();
    serde_json::json!({
        "ver": 1,
        "jti": "AT.5bxkQ6M3vb3yBsfXf2Gfp5Hv6s1XOS8q5fGRe7tdS2Q",
        "iss": OKTA_ISSUER,
        "aud": OKTA_AUDIENCE,
        "iat": now,
        "exp": now + 3600,
        "cid": "0oa1b2c3d4EXAMPLE",
        "uid": "00u1a2b3c4EXAMPLE",
        "scp": ["openid", "email"],
        "sub": sub,
        "email": sub,
    })
}

/// A projected Kubernetes ServiceAccount token's claims: `aud` is an ARRAY,
/// with nbf and the nested kubernetes.io claim.
fn service_account_claims() -> serde_json::Value {
    let now = now_secs();
    serde_json::json!({
        "aud": [TEST_AUDIENCE],
        "exp": now + 3600,
        "iat": now,
        "nbf": now,
        "iss": SA_ISSUER,
        "kubernetes.io": {
            "namespace": "agents",
            "pod": {"name": "billing-bot-7d9f", "uid": "5c1d3e9a-0000-4000-8000-000000000001"},
            "serviceaccount": {"name": "billing-bot", "uid": "5c1d3e9a-0000-4000-8000-000000000002"}
        },
        "sub": "system:serviceaccount:agents:billing-bot",
    })
}

async fn check_token(svc: &AuthService, token: &str) -> Result<Vec<HeaderValueOption>, String> {
    let auth = format!("Bearer {token}");
    let response = svc
        .check(build_check_request(Some(&auth)))
        .await
        .expect("rpc")
        .into_inner();
    match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => Ok(ok.headers),
        Some(HttpResponse::DeniedResponse(denied)) => Err(denied.body),
        other => panic!("unexpected response {other:?}"),
    }
}

// B28.204: one gateway, two identity providers — a person signed in through
// Okta (aud a string) and an agent's Kubernetes ServiceAccount (aud an array).
#[tokio::test]
async fn test_okta_and_service_account_tokens_both_accepted() {
    let okta = make_fixture("okta-kid");
    let cluster = make_fixture("sa-kid");
    let (svc, _metrics) = build_multi_issuer_service(&[
        (OKTA_ISSUER, OKTA_AUDIENCE, okta.jwks.clone()),
        (SA_ISSUER, TEST_AUDIENCE, cluster.jwks.clone()),
    ]);

    let person = sign_jwt(&okta.private_pem, "okta-kid", &okta_claims("ada@example.com"));
    let headers = check_token(&svc, &person).await.expect("Okta token must be accepted");
    assert_eq!(header_value(&headers, "x-user-id"), Some("ada@example.com"));
    assert_eq!(header_value(&headers, "x-auth-iss"), Some(OKTA_ISSUER));
    // The signed assertion names the provider, so a backend can key the
    // identity on (idp, sub) and two providers' "ada" never collide.
    let assertion = header_value(&headers, "x-gateway-auth").expect("transit assertion");
    let vouched = backend_verifier(&svc)
        .verify(assertion, "GET", "example.com", "/")
        .expect("assertion verifies");
    assert_eq!(vouched.idp.as_deref(), Some(OKTA_ISSUER));

    let agent = sign_jwt(&cluster.private_pem, "sa-kid", &service_account_claims());
    let headers = check_token(&svc, &agent)
        .await
        .expect("ServiceAccount token must be accepted");
    assert_eq!(
        header_value(&headers, "x-user-id"),
        Some("system:serviceaccount:agents:billing-bot")
    );
    assert_eq!(header_value(&headers, "x-auth-iss"), Some(SA_ISSUER));
}

// A key only vouches for its own issuer: a token signed by the cluster's key
// but claiming to be from Okta is refused, and so is an issuer nobody listed.
#[tokio::test]
async fn test_key_from_one_issuer_cannot_vouch_for_another() {
    let okta = make_fixture("okta-kid");
    let cluster = make_fixture("sa-kid");
    let (svc, _metrics) = build_multi_issuer_service(&[
        (OKTA_ISSUER, OKTA_AUDIENCE, okta.jwks.clone()),
        (SA_ISSUER, TEST_AUDIENCE, cluster.jwks.clone()),
    ]);

    let forged = sign_jwt(&cluster.private_pem, "sa-kid", &okta_claims("ada@example.com"));
    let err = check_token(&svc, &forged).await.expect_err("cross-issuer key must be refused");
    assert_eq!(err, "unknown kid");

    let mut stranger = service_account_claims();
    stranger["iss"] = serde_json::json!("https://idp.attacker.example");
    let token = sign_jwt(&cluster.private_pem, "sa-kid", &stranger);
    let err = check_token(&svc, &token).await.expect_err("unlisted issuer must be refused");
    assert_eq!(err, "untrusted issuer");
}

/// An agent's call through edge-egress to a keyless destination: Envoy sends
/// auth_policy=agent, and whatever headers and path the agent sent.
fn agent_request(headers: &[(&str, &str)], path: &str) -> Request<CheckRequest> {
    Request::new(CheckRequest {
        attributes: Some(AttributeContext {
            request: Some(AttrRequest {
                http: Some(HttpRequest {
                    method: "POST".into(),
                    headers: headers
                        .iter()
                        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                        .collect(),
                    path: path.into(),
                    host: "api.openai.com".into(),
                    scheme: "http".into(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            context_extensions: HashMap::from([("auth_policy".to_string(), "agent".to_string())]),
            ..Default::default()
        }),
    })
}

// B28.224: a keyless agent. Its ServiceAccount token buys it a signed
// assertion, and every key planted in it — headers, the URL, the workload
// token itself — is removed before the request leaves.
#[tokio::test]
async fn test_keyless_agent_credentials_stripped_and_assertion_signed() {
    let cluster = make_fixture("sa-kid");
    let (svc, _metrics) = build_multi_issuer_service(&[(SA_ISSUER, TEST_AUDIENCE, cluster.jwks.clone())]);
    let workload = format!("Bearer {}", sign_jwt(&cluster.private_pem, "sa-kid", &service_account_claims()));
    let planted = "sk-planted-0123456789";
    let bearer_key = format!("Bearer {planted}");

    let response = svc
        .check(agent_request(
            &[
                ("proxy-authorization", &workload),
                ("authorization", &bearer_key),
                ("x-api-key", planted),
                ("content-type", "application/json"),
            ],
            &format!("/v1/chat/completions?key={planted}"),
        ))
        .await
        .expect("rpc")
        .into_inner();
    // edge-egress keys the agent's rate limit and its decision log on this (B28.228).
    let agent = response
        .dynamic_metadata
        .as_ref()
        .and_then(|m| m.fields.get("agent"))
        .and_then(|v| v.kind.clone());
    assert_eq!(
        agent,
        Some(Kind::StringValue("system:serviceaccount:agents:billing-bot".into()))
    );
    let ok = match response.http_response {
        Some(HttpResponse::OkResponse(ok)) => ok,
        other => panic!("expected OkResponse, got {other:?}"),
    };
    assert_eq!(ok.headers_to_remove, ["authorization", "proxy-authorization", "x-api-key"]);
    assert_eq!(ok.query_parameters_to_remove, ["key"]);
    for h in ok.headers.iter().filter_map(|o| o.header.as_ref()) {
        assert!(!h.value.contains(planted), "{} carries the planted key", h.key);
    }
    let assertion = header_value(&ok.headers, "x-gateway-auth").expect("transit assertion");
    let vouched = backend_verifier(&svc)
        .verify(assertion, "POST", "api.openai.com", "/v1/chat/completions")
        .expect("the assertion names the request as it leaves, without the key");
    assert_eq!(vouched.sub, "system:serviceaccount:agents:billing-bot");
    assert_eq!(vouched.amr, "agent");
    assert_eq!(vouched.idp.as_deref(), Some(SA_ISSUER));

    // The planted key alone, without the workload token: refused by the proxy.
    let response = svc
        .check(agent_request(&[("authorization", &bearer_key)], "/v1/chat/completions"))
        .await
        .expect("rpc")
        .into_inner();
    match response.http_response {
        Some(HttpResponse::DeniedResponse(denied)) => {
            assert_eq!(denied.status.map(|s| s.code), Some(407));
            assert!(denied.body.contains("Proxy-Authorization"), "body: {}", denied.body);
        }
        other => panic!("expected a 407, got {other:?}"),
    }
}

// B67.7 (Dependabot #1, jsonwebtoken GHSA type confusion): a token that is not valid yet must be
// denied, whether its `nbf` is a number or a string. The gateway never checked `nbf` at all, and
// jsonwebtoken 9 skipped a check whose claim had the wrong JSON type as though it were absent.
fn claims_with(extra: serde_json::Value) -> serde_json::Value {
    let now = now_secs();
    let mut claims = serde_json::json!({
        "sub": "user-nbf",
        "exp": now + 3600,
        "iat": now,
        "aud": TEST_AUDIENCE,
        "iss": TEST_ISSUER,
    });
    for (k, v) in extra.as_object().expect("object") {
        claims[k] = v.clone();
    }
    claims
}

#[tokio::test]
async fn test_token_not_valid_yet_denied() {
    let fix = make_fixture(TEST_KID);
    let (svc, _metrics) = build_service(fix.jwks.clone());
    let later = now_secs() + 3600;

    let ok = sign_jwt(&fix.private_pem, TEST_KID, &claims_with(serde_json::json!({"nbf": now_secs()})));
    assert!(check_token(&svc, &ok).await.is_ok(), "a token valid now is accepted");

    let numeric = sign_jwt(&fix.private_pem, TEST_KID, &claims_with(serde_json::json!({"nbf": later})));
    assert!(check_token(&svc, &numeric).await.is_err(), "nbf an hour ahead must be denied");

    let string = sign_jwt(&fix.private_pem, TEST_KID, &claims_with(serde_json::json!({"nbf": later.to_string()})));
    assert!(check_token(&svc, &string).await.is_err(), "nbf as a string must be denied, not skipped");

    let exp_string = sign_jwt(
        &fix.private_pem,
        TEST_KID,
        &claims_with(serde_json::json!({"exp": (now_secs() - 3600).to_string()})),
    );
    assert!(check_token(&svc, &exp_string).await.is_err(), "exp as a string must be denied");
}
