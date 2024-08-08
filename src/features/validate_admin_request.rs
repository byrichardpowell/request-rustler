use base64::decode;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

use hmac::{Hmac, Mac};
use jwt::VerifyWithKey;
use sha2::Sha256;

#[derive(Deserialize)]
pub struct Request {
    method: String,
    headers: HashMap<String, String>,
    url: String,
}

#[derive(Deserialize)]
pub struct Config {
    public_key: String,
    private_key: String,
    urls: Urls,
}

#[derive(Deserialize)]
pub struct Urls {
    app: String,
    patch_session_token: String,
    login: String,
    exit_iframe: String,
}

#[derive(Serialize, Deserialize)]
pub struct ResponseObject {
    status: u16,
    body: String,
    headers: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct JwtResult {
    id_token: String,
    payload: JwtPayload,
}

#[derive(Serialize, Deserialize)]
struct JwtPayload {
    iss: String,  // Issuer
    dest: String, // Destination
    aud: String,  // Audience
    sub: String,  // Subject
    exp: i64,     // Expiration time (seconds since the epoch)
    nbf: i64,     // Not before time (seconds since the epoch)
    iat: i64,     // Issued at time (seconds since the epoch)
    jti: String,  // JWT ID (unique identifier)
    sid: String,  // Session ID
    sig: String,  // Signature
}

pub type LogFn = fn(&str);

pub fn validate_admin_request(
    request: &Request,
    config: &Config,
    _log: LogFn,
) -> Result<JwtResult, ResponseObject> {
    let request_url = Url::parse(&request.url).unwrap();
    let urls = &config.urls;
    let app_url = Url::parse(&urls.app).unwrap();
    let patch_session_token_url = Url::parse(&urls.patch_session_token).unwrap();
    let login_url = Url::parse(&urls.login).unwrap();
    let exit_iframe_url = Url::parse(&urls.exit_iframe).unwrap();

    if request.method == "OPTIONS" {
        let default_origin = "".to_string();
        let origin = request.headers.get("Origin").unwrap_or(&default_origin);
        if origin == app_url.as_str() {
            return Err(ResponseObject {
                status: 204,
                body: "".to_string(),
                headers: [("Access-Control-Max-Age".to_string(), "7200".to_string())]
                    .iter()
                    .cloned()
                    .collect(),
            });
        } else {
            return Err(ResponseObject {
                status: 204,
                body: "".to_string(),
                headers: [
                    ("Access-Control-Max-Age".to_string(), "7200".to_string()),
                    ("Access-Control-Allow-Origin".to_string(), "*".to_string()),
                    (
                        "Access-Control-Expose-Headers".to_string(),
                        "X-Shopify-API-Request-Failure-Reauthorize-Url".to_string(),
                    ),
                    (
                        "Access-Control-Allow-Headers".to_string(),
                        "Authorization, Content-Type".to_string(),
                    ),
                ]
                .iter()
                .cloned()
                .collect(),
            });
        }
    }

    if request_url.origin() == patch_session_token_url.origin()
        && request_url.path() == patch_session_token_url.path()
    {
        let shop = request_url
            .query_pairs()
            .find(|(key, _)| key == "shop")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();

        return Err(ResponseObject {
            status: 200,
            body: format!(
                r#"<script data-api-key="{}" src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script>"#,
                config.public_key
            ),
            headers: [
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "Link".to_string(),
                    "<https://cdn.shopify.com/shopifycloud/app-bridge.js>; rel=\"preload\"; as=\"script\"".to_string(),
                ),
                (
                    "Content-Security-Policy".to_string(),
                    format!(
                        "frame-ancestors https://{} https://admin.shopify.com https://*.spin.dev;",
                        shop
                    ),
                ),
            ]
            .iter()
            .cloned()
            .collect(),
        });
    }

    if request_url.origin() == exit_iframe_url.origin()
        && request_url.path() == exit_iframe_url.path()
    {
        let exit_iframe = request_url
            .query_pairs()
            .find(|(key, _)| key == "exitIFrame")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        let exit_iframe_url = Url::parse(&exit_iframe)
            .or_else(|_| app_url.join(&exit_iframe))
            .unwrap();
        return Err(ResponseObject {
            status: 200,
            body: format!(
                r#"<script data-api-key="{}" src="https://cdn.shopify.com/shopifycloud/app-bridge.js"></script><script>window.open("{}", "_top")</script>"#,
                config.public_key, urls.exit_iframe
            ),
            headers: [
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "Link".to_string(),
                    "<https://cdn.shopify.com/shopifycloud/app-bridge.js>; rel=\"preload\"; as=\"script\"".to_string(),
                ),
                (
                    "Content-Security-Policy".to_string(),
                    format!(
                        "frame-ancestors https://{} https://admin.shopify.com https://*.spin.dev;",
                        exit_iframe_url.host_str().unwrap_or("")
                    ),
                ),
            ]
            .iter()
            .cloned()
            .collect(),
        });
    }

    if !request.headers.contains_key("Authorization") {
        let shop = request_url
            .query_pairs()
            .find(|(key, _)| key == "shop")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        if shop.is_empty() {
            return Err(ResponseObject {
                status: 302,
                body: "".to_string(),
                headers: [("Location".to_string(), login_url.to_string())]
                    .iter()
                    .cloned()
                    .collect(),
            });
        }

        let re = Regex::new(r"^admin\.(myshopify\.com|shopify\.com|myshopify\.io)/store/([a-zA-Z0-9][a-zA-Z0-9-_]*)$").unwrap();
        let shop = if re.is_match(&shop) {
            let captures = re.captures(&shop).unwrap();
            format!("{}.myshopify.com", &captures[2])
        } else {
            shop
        };

        let re = Regex::new(
            r"^[a-zA-Z0-9][a-zA-Z0-9-_]*\.(myshopify\.com|shopify\.com|myshopify\.io)[/]*$",
        )
        .unwrap();
        if !re.is_match(&shop) {
            return Err(ResponseObject {
                status: 302,
                body: "".to_string(),
                headers: [("Location".to_string(), login_url.to_string())]
                    .iter()
                    .cloned()
                    .collect(),
            });
        }

        let host = request_url
            .query_pairs()
            .find(|(key, _)| key == "host")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        if host.is_empty() {
            return Err(ResponseObject {
                status: 302,
                body: "".to_string(),
                headers: [("Location".to_string(), login_url.to_string())]
                    .iter()
                    .cloned()
                    .collect(),
            });
        }

        let re = Regex::new(r"^[0-9a-zA-Z+/]+={0,2}$").unwrap();
        if !re.is_match(&host) {
            return Err(ResponseObject {
                status: 400,
                body: "Invalid host".to_string(),
                headers: HashMap::new(),
            });
        }

        let decoded_host = decode(&host).unwrap();
        let decoded_host = String::from_utf8(decoded_host).unwrap();
        let re = Regex::new(r"(myshopify\.com|shopify\.com|myshopify\.io)").unwrap();
        if !re.is_match(&decoded_host) {
            return Err(ResponseObject {
                status: 302,
                body: "".to_string(),
                headers: [("Location".to_string(), login_url.to_string())]
                    .iter()
                    .cloned()
                    .collect(),
            });
        }

        let embedded = request_url
            .query_pairs()
            .find(|(key, _)| key == "embedded")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        if embedded != "1" {
            return Err(ResponseObject {
                status: 302,
                body: "".to_string(),
                headers: [(
                    "Location".to_string(),
                    format!("https://{}/apps/{}", decoded_host, config.public_key),
                )]
                .iter()
                .cloned()
                .collect(),
            });
        }

        let id_token = request_url
            .query_pairs()
            .find(|(key, _)| key == "id_token")
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        if id_token.is_empty() {
            let mut search_params: Vec<(String, String)> =
                request_url.query_pairs().into_owned().collect();
            search_params.retain(|(key, _)| key != "id_token");
            let search_params: String = search_params
                .iter()
                .map(|(key, value)| format!("{}={}", key, value))
                .collect::<Vec<String>>()
                .join("&");
            let redirect_url = format!("{}{}?{}", app_url, request_url.path(), search_params);
            return Err(ResponseObject {
                status: 302,
                body: "".to_string(),
                headers: [(
                    "Location".to_string(),
                    format!(
                        "{}?{}&shopify-reload={}",
                        patch_session_token_url, search_params, redirect_url
                    ),
                )]
                .iter()
                .cloned()
                .collect(),
            });
        }
    }

    let id_token = request
        .headers
        .get("Authorization")
        .map(|auth| auth.trim_start_matches("Bearer ").to_string())
        .unwrap_or_else(|| {
            request_url
                .query_pairs()
                .find(|(key, _)| key == "id_token")
                .map(|(_, value)| value.to_string())
                .unwrap_or_default()
        });

    if id_token.is_empty() {
        return Err(ResponseObject {
            status: 400,
            body: "Missing id_token".to_string(),
            headers: HashMap::new(),
        });
    }

    let key: Hmac<Sha256> = Hmac::new_from_slice(config.private_key.as_bytes()).unwrap();
    let claims: JwtPayload = id_token.verify_with_key(&key).unwrap();

    Ok(JwtResult {
        id_token,
        payload: claims,
    })
}
