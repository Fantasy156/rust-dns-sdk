// Copyright 2023 rust-dns-sdk authors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::error::Error;
use async_trait::async_trait;
use dns_sdk_macros::extract_params;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Method;
use serde_json::to_string;
use crate::client::{DnsClient, DnsProviderBuilder, DnsProviderImpl, RecordOperationBuilder};
use crate::utils::request::{DefaultDnsClient, DnsHttpClient};

#[derive(Default)]
pub struct CloudFlareDnsBuilder<T: DnsHttpClient + Default> {
    api_token: Option<String>,
    api:  String,
    _marker: std::marker::PhantomData<T>,
}

impl<T: DnsHttpClient + Default + 'static> DnsProviderBuilder for CloudFlareDnsBuilder<T> {
    type Output = DnsProviderImpl<T>;

    /// Sets configuration parameters for the DNS provider builder.
    ///
    /// Supported token:
    /// - "api_token"
    ///
    /// # Panics
    /// Panics if an unknown parameter key is provided.
    fn set_param(self: Box<Self>, key: &str, value: &str) -> Box<dyn DnsProviderBuilder<Output = DnsProviderImpl<T>>> {
        let mut this = *self;
        match key {
            "api_token" => this.api_token = Some(value.into()),
            _ => panic!("Invalid parameter: {}", key),
        }
        Box::new(this)
    }

    /// Constructs a new CloudFlare client instance using configured parameters.
    fn build(self: Box<Self>) -> DnsProviderImpl<T> {
        DnsProviderImpl::CloudFlare(CloudFlareDns {
            http_client: T::default(),
            api: "https://api.cloudflare.com/client/v4".into(),
            api_token: self.api_token.unwrap(),
        })
    }
}

pub struct CloudFlareDns<T: DnsHttpClient> {
    /// HTTP client for making requests
    http_client: T,
    /// API endpoint
    api: String,
    /// API Token
    api_token: String,
}

#[async_trait]
impl<T: DnsHttpClient> DnsClient for CloudFlareDns<T> {
    /// Retrieves detailed information about the current user's zones.
    async fn describe_user_detail(&self) -> Result<String, Box<dyn Error>> {
        let url = format!("{}/zones", self.api);
        let headers = build_headers(&self.api_token)?;

        let response = self.http_client.request(Method::GET, url, headers, None).await?;

        Ok(response.to_string())

    }

    /// Lists all domain names associated with the account, handling pagination.
    async fn describe_domain_name_list(&self) -> Result<String, Box<dyn Error>> {
        let mut page = 1;
        let mut all_zones = Vec::new();

        loop {
            let url = format!("{}/zones?page={}&per_page=50", self.api, page);
            let headers = build_headers(&self.api_token)?;

            let response = self.http_client.request(Method::GET, url, headers, None).await?;

            let result_array = response
                .get("result")
                .and_then(|v| v.as_array())
                .ok_or("Missing 'result' array in response")?;

            all_zones.extend(result_array.iter().cloned());

            let page_info = response
                .get("result_info")
                .ok_or("Missing 'result_info' in response")?;

            let current_page = page_info.get("page").and_then(|v| v.as_u64()).unwrap_or(1);
            let total_pages = page_info.get("total_pages").and_then(|v| v.as_u64()).unwrap_or(1);

            if current_page >= total_pages {
                break;
            }

            page += 1;
        }

        Ok(serde_json::to_string_pretty(&all_zones)?)
    }

    /// Cloudflare does not support the concept of record lines, returns error.
    async fn describe_record_line_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        Err("Cloudflare does not support record line concept".into())
    }

    /// Retrieves a list of DNS records for the specified domain.
    async fn describe_record_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain"
        });

        let headers = build_headers(&self.api_token)?;

        let zone_id = get_zone_id(&self.api, &self.api_token, &*params.domain).await?;


        let mut page = 1;
        let mut all_records = Vec::new();

        loop {
            let url = format!("{}/zones/{}/dns_records?page={}&per_page=50", self.api, zone_id, page);

            let response = self.http_client.request(Method::GET, url, headers.clone(), None).await?;

            let result_array = response
                .get("result")
                .and_then(|v| v.as_array())
                .ok_or("Missing 'result' array in DNS record response")?;

            all_records.extend(result_array.iter().cloned());

            let page_info = response
                .get("result_info")
                .ok_or("Missing 'result_info'")?;

            let current_page = page_info.get("page").and_then(|v| v.as_u64()).unwrap_or(1);
            let total_pages = page_info.get("total_pages").and_then(|v| v.as_u64()).unwrap_or(1);

            if current_page >= total_pages {
                break;
            }

            page += 1;
        }

        Ok(serde_json::to_string_pretty(&all_records)?)
    }

    /// Filters DNS records to only include those matching a specific subdomain.
    async fn describe_subdomain_record_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
        required domain: String => "Domain",
        required subdomain: String => "SubDomain"
    });

        let full_subdomain = format!("{}.{}", params.subdomain, params.domain);

        let record_list_str = self.describe_record_list(builder).await?;

        let mut records: serde_json::Value = serde_json::from_str(&record_list_str)?;

        if let Some(array) = records.as_array_mut() {
            array.retain(|record| record.get("name").map_or(false, |name| name == &full_subdomain));
        }

        Ok(to_string(&records)?)
    }

    /// Gets details for a specific DNS record identified by domain and subdomain.
    async fn describe_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain"
        });

        let record_name = if params.subdomain== "@" {
            params.domain.clone()
        } else {
            format!("{}.{}", params.subdomain, params.domain)
        };

        let headers = build_headers(&self.api_token)?;

        let zone_id = get_zone_id(&self.api, &self.api_token, &*params.domain).await?;

        let records_url = format!("{}/zones/{}/dns_records?name={}", self.api, zone_id, record_name);
        let records_response = self.http_client.request(Method::GET, records_url, headers.clone(), None).await?;

        let records = records_response
            .get("result").and_then(|v| v.as_array())
            .ok_or("Missing 'result' array for DNS records")?;

        Ok(to_string(&records)?)

    }

    /// Creates a new DNS record with the specified parameters.
    async fn create_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            required record_type: String => "RecordType",
            required value: String => "Value",
            required proxied: bool => "Proxied",
            optional ttl: u32 = 600 => "TTL"
        });

        let record_name = if params.subdomain == "@" {
            params.domain.clone()
        } else {
            format!("{}.{}", params.subdomain, params.domain)
        };

        let headers = build_headers(&self.api_token)?;

        let zone_id = get_zone_id(&self.api, &self.api_token, &params.domain).await?;

        let body = serde_json::json!({
        "type": params.record_type,
        "name": record_name,
        "content": params.value,
        "ttl": params.ttl,
        "proxied": params.proxied
    });

        let create_url = format!("{}/zones/{}/dns_records", self.api, zone_id);
        let create_response = self.http_client
            .request(Method::POST, create_url, headers, Some(body.to_string()))
            .await?;

        Ok(create_response.to_string())
    }

    /// Modifies an existing DNS record with new values.
    async fn modify_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            required record_type: String => "RecordType",
            required value: String => "Value",
            required proxied: bool => "Proxied",
            optional ttl: u32 = 600 => "TTL"
        });

        let record_name = if params.subdomain == "@" {
            params.domain.clone()
        } else {
            format!("{}.{}", params.subdomain, params.domain)
        };

        let headers = build_headers(&self.api_token)?;

        let zone_id = get_zone_id(&self.api, &self.api_token, &params.domain).await?;

        let list_url = format!("{}/zones/{}/dns_records?type={}&name={}",
                               self.api, zone_id, params.record_type, record_name);
        let list_resp_text = self.http_client.request(Method::GET, list_url, headers.clone(), None).await?;

        let record_id =list_resp_text["result"][0]["id"].as_str().ok_or("record_id not found")?;

        let body = serde_json::json!({
        "type": params.record_type,
        "name": record_name,
        "content": params.value,
        "ttl": params.ttl,
        "proxied": params.proxied
    });

        let modify_url = format!("{}/zones/{}/dns_records/{}", self.api, zone_id, record_id);
        let modify_resp_text = self.http_client.request(Method::PUT, modify_url, headers, Some(body.to_string())).await?;

        Ok(modify_resp_text.to_string())
    }

    /// Deletes one or more DNS records based on domain, subdomain, and optionally record ID.
    async fn delete_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            optional record_id: String = "".to_string() => "RecordId"
        });

        let headers = build_headers(&self.api_token)?;

        let zone_id = get_zone_id(&self.api, &self.api_token, &params.domain).await?;

        if !params.record_id.is_empty() {
            let delete_url = format!("{}/zones/{}/dns_records/{}", self.api, zone_id, params.record_id);
            let delete_resp = self.http_client
                .request(Method::DELETE, delete_url, headers, None)
                .await?;
            return Ok(delete_resp.to_string());
        }

        let subdomain_list_str = self.describe_subdomain_record_list(builder).await?;

        // Parse JSON string into array
        let records: serde_json::Value = serde_json::from_str(&subdomain_list_str)?;
        let Some(array) = records.as_array() else {
            return Err("Expected JSON array of records".into());
        };

        let mut deleted = Vec::new();

        for record in array {
            let record_name = record.get("name").and_then(|n| n.as_str());
            let expected_name = if params.subdomain == "@" {
                &params.domain
            } else {
                &format!("{}.{}", params.subdomain, params.domain)
            };

            if record_name == Some(expected_name) {
                if let Some(record_id) = record.get("id").and_then(|id| id.as_str()) {
                    let delete_url = format!("{}/zones/{}/dns_records/{}", self.api, zone_id, record_id);
                    let delete_resp = self.http_client
                        .request(Method::DELETE, delete_url, headers.clone(), None)
                        .await?;
                    deleted.push(delete_resp.to_string());
                }
            }
        }

        Ok(format!("Deleted records: {}", deleted.join(", ")))
    }
}

fn build_headers(token: &str) -> Result<HeaderMap, Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/json".parse()?);
    headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token))?);
    Ok(headers)
}

/// Retrieves the zone ID for a given domain name.
async fn get_zone_id(api_url : &str, api_token: &str, domain: &str) -> Result<String, Box<dyn Error>> {
    let http_client = DefaultDnsClient::new();
    let headers = build_headers(api_token)?;

    let zone_url = format!("{}/zones?name={}", api_url, domain);

    let zone_resp = http_client
        .request(Method::GET, zone_url, headers.clone(), None)
        .await?;
    let zone_id = zone_resp["result"][0]["id"]
        .as_str()
        .ok_or("zone_id not found")?;

    Ok(zone_id.to_string())

}