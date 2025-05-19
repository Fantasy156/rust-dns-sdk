use reqwest::{Client, Method, header::HeaderMap};
use std::error::Error;


pub trait DnsHttpClient: Send + Sync {
    fn request(
        &self,
        method: Method,
        url: String,
        headers: HeaderMap,
        body: Option<String>,
    ) -> impl Future<Output = Result<serde_json::Value, Box<dyn Error>>> + Send;
}

pub struct DefaultDnsClient {
    inner: Client,
}

impl DefaultDnsClient {
    pub fn new() -> Self {
        Self {
            inner: Client::new(),
        }
    }
}

impl Default for DefaultDnsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsHttpClient for DefaultDnsClient {
    async fn request(
        &self,
        method: Method,
        url: String,
        headers: HeaderMap,
        body: Option<String>,
    ) -> Result<serde_json::Value, Box<dyn Error>> {
        let mut req = self.inner.request(method, url).headers(headers);
        if let Some(body) = body {
            req = req.body(body);
        }
        let text = req.send().await?.text().await?;

        let json_value: serde_json::Value = serde_json::from_str(&text)?;

        Ok(json_value)
    }
}