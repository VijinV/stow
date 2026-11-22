//! The metadata-only device API. No request follows a redirect.
use crate::{json::Json, remote};
use bt_s3::{http::Request, BytesBody, Url};

#[derive(Debug)]
pub(crate) struct Error {
    pub status: u16,
    pub message: String,
}

impl Error {
    pub fn local(message: impl Into<String>) -> Self {
        Self {
            status: 0,
            message: message.into(),
        }
    }

    pub fn authorization_failed(&self) -> bool {
        matches!(self.status, 401 | 403)
    }
}

pub(crate) struct Api {
    origin: Url,
    http: bt_s3::http::HttpClient,
}

impl Api {
    pub fn new(origin: &str) -> Result<Self, Error> {
        Ok(Self {
            origin: Url::parse(origin).map_err(Error::local)?,
            http: remote::dashboard_http().map_err(Error::local)?,
        })
    }

    pub fn request(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&Json>,
    ) -> Result<Json, Error> {
        let mut url = self.origin.clone();
        url.path = format!("/api/v1{path}");
        let mut headers = vec![("accept".into(), "application/json".into())];
        if let Some(token) = token {
            headers.push(("authorization".into(), format!("Bearer {token}")));
        }
        let body = body.map(Json::to_string_compact);
        let payload = body.as_ref().map(|value| BytesBody(value.as_bytes()));
        if payload.is_some() {
            headers.push(("content-type".into(), "application/json".into()));
        }
        let request = Request {
            method,
            url: &url,
            headers: &headers,
            body: payload.as_ref().map(|body| body as &dyn bt_s3::http::Body),
            cancel: None,
        };
        let response = self.http.send(&request, None, &mut |_| {}).map_err(|_| {
            Error::local("Could not reach the dashboard. Check the address and connection.")
        })?;
        if !(200..300).contains(&response.status) {
            let message = match response.status {
                401 | 403 => "The dashboard denied this request. Check the pairing code or device access.",
                404 => "The requested dashboard record was not found.",
                409 => "The dashboard refused this run because the device already has a backup in progress.",
                429 => "The dashboard requested a short wait before trying again.",
                503 => "The dashboard service or AWS storage access is unavailable. Check the dashboard settings.",
                300..=399 => "The dashboard address redirected the request. Enter the final address.",
                _ => "The dashboard rejected the request.",
            };
            return Err(Error {
                status: response.status,
                message: message.into(),
            });
        }
        Json::parse(&response.body_text())
            .map_err(|_| Error::local("The dashboard returned an invalid response."))
    }
}
