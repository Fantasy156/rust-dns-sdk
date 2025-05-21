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

use std::collections::HashMap;
use std::error::Error;
use async_trait::async_trait;
use chrono::DateTime;
use dns_sdk_macros::extract_params;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Method;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{to_string, Value};
use crate::client::{DnsClient, DnsProviderBuilder, DnsProviderImpl, RecordOperationBuilder};
use crate::utils::request::{DefaultDnsClient, DnsHttpClient};
use crate::utils::serde_utils::{is_empty_or_none, is_null_or_none, vec_is_empty, option_is_empty};

#[derive(Default)]
pub struct CloudFlareDnsBuilder<T: DnsHttpClient + Default> {
    api_token: Option<String>,
    _marker: std::marker::PhantomData<T>,
}

impl<T: DnsHttpClient + Default + 'static> DnsProviderBuilder for CloudFlareDnsBuilder<T> {
    type Output = DnsProviderImpl<T>;

    /// Sets configuration parameters for the DNS provider builder.
    ///
    /// Supported token:
    /// - "api_token"
    ///
    /// # Panics    ///  if an unknown parameter key is provided.
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

#[derive( Deserialize, Serialize)]
struct RawCloudFlareResponse {
    #[serde(rename = "result", default, deserialize_with = "deserialize_result", skip_serializing_if = "vec_is_empty")]
    result: Vec<CloudFlareResult>,
    #[serde(rename = "errors", default, skip_serializing_if = "is_empty_or_none")]
    errors: Option<Vec<Value>>,
    #[serde(rename = "messages", default, skip_serializing_if = "is_empty_or_none")]
    messages: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "option_is_empty")]
    result_info: Option<ResultInfo>,
    success: bool,
}

#[derive(Deserialize, Serialize)]
struct ResultInfo {
    page: Option<usize>,
    per_page: Option<usize>,
    total_pages: Option<usize>,
    count: Option<usize>,
    total_count: Option<usize>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
struct CloudFlareResult {
    #[serde(rename = "account", default, skip_serializing_if = "option_is_empty")]
    account: Option<Value>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

fn deserialize_result<'de, D>(deserializer: D) -> Result<Vec<CloudFlareResult>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum ResultWrapper {
        Single(CloudFlareResult),
        Multiple(Vec<CloudFlareResult>),
        Null
    }

    let wrapper = ResultWrapper::deserialize(deserializer)?;
    Ok(match wrapper {
        ResultWrapper::Single(record) => vec![record],
        ResultWrapper::Multiple(records) => records,
        ResultWrapper::Null => vec![]
    })
}

#[derive(Default, Deserialize, Serialize)]
struct CloudFlareResponse {
    #[serde(rename = "Response", default, skip_serializing_if = "option_is_empty")]
    response : Option<Response>,
    #[serde(rename = "errors", default, skip_serializing_if = "is_empty_or_none")]
    errors: Option<Vec<Value>>,
    #[serde(rename = "messages", default, skip_serializing_if = "is_empty_or_none")]
    messages: Option<Vec<Value>>,
    #[serde(rename = "success", default)]
    success: bool,
}

#[derive(Default, Deserialize, Serialize)]
struct Response {
    #[serde(rename = "UserInfo", default, skip_serializing_if = "is_null_or_none")]
    user_info: Option<Value>,
    #[serde(rename = "DomainCountInfo", default, skip_serializing_if = "option_is_empty")]
    domain_count_info: Option<DomainCountInfo>,
    #[serde(rename = "DomainList", default, skip_serializing_if = "vec_is_empty")]
    domain_list: Vec<DomainList>,
    #[serde(rename = "RecordList", default, skip_serializing_if = "vec_is_empty")]
    record_list: Vec<RecordList>,
    #[serde(rename = "RecordInfo", default, skip_serializing_if = "option_is_empty")]
    record_info: Option<RecordList>,
}

#[derive(Default, Deserialize, Serialize)]
struct DomainCountInfo {
    #[serde(rename = "AllTotal", default, skip_serializing_if = "is_null_or_none")]
    all_total: Option<Value>,
    #[serde(rename = "DomainTotal", default, skip_serializing_if = "is_null_or_none")]
    domain_total: Option<Value>,
    #[serde(rename = "RecordTotal", default, skip_serializing_if = "is_null_or_none")]
    record_total: Option<Value>,
    #[serde(rename = "MineTotal", default, skip_serializing_if = "is_null_or_none")]
    mine_total: Option<Value>,
}

#[derive(Deserialize, Serialize)]
struct DomainList {
    #[serde(rename = "CreatedOn", default, skip_serializing_if = "is_null_or_none")]
    created_on: Option<Value>,
    #[serde(rename = "EffectiveDNS", default, skip_serializing_if = "is_empty_or_none")]
    effective_dns: Option<Vec<Value>>,
    #[serde(rename = "Name", default, skip_serializing_if = "is_null_or_none")]
    name: Option<Value>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[derive(Default, Deserialize, Serialize)]
struct RecordList {
    #[serde(rename = "CreatedOn", default, skip_serializing_if = "is_null_or_none")]
    created_on: Option<Value>,
    #[serde(rename = "Name", default, skip_serializing_if = "is_null_or_none")]
    name: Option<Value>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[async_trait]
impl<T: DnsHttpClient> DnsClient for CloudFlareDns<T> {
    /// Retrieves detailed information about the current user's zones.
    async fn describe_user_detail(&self) -> Result<String, Box<dyn Error>> {
        let url = format!("{}/zones", self.api);
        let headers = build_headers(&self.api_token)?;

        let resp = self.http_client.request(Method::GET, url, headers, None).await?;

        let raw: RawCloudFlareResponse = serde_json::from_str(&resp.to_string())?;

        let final_response = CloudFlareResponse::from(raw);

        Ok(to_string(&final_response)?)

    }

    /// Lists all domain names associated with the account, handling pagination.
    async fn describe_domain_name_list(&self) -> Result<String, Box<dyn Error>> {
        let headers = build_headers(&self.api_token)?;
        let all_zones = fetch_paginated_data(
            &self.http_client,
            &format!("{}/zones", self.api),
            headers,
            |resp| serde_json::from_str::<RawCloudFlareResponse>(&resp.to_string())
                .map_err(|e| Box::new(e) as Box<dyn Error>),
        )
        .await?;

        let domain_list: Vec<DomainList> = all_zones
            .into_iter()
            .map(|zone| {
                let created_on = zone.extra.get("created_on")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1970-01-01T00:00:00Z");

                let name = zone.extra.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();

                let name_servers = zone.extra.get("name_servers")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>())
                    .unwrap_or_default();

                let plan_name = zone.extra.get("plan")
                    .and_then(|v| v.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Plan");

                let formatted_date = DateTime::parse_from_rfc3339(created_on)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|_| "1970-01-01 00:00:00".into());

                DomainList {
                    created_on: Some(Value::String(formatted_date)),
                    effective_dns: Some(
                        name_servers
                            .into_iter()
                            .map(|s| Value::String(s))
                            .collect::<Vec<Value>>()
                    ),
                    name: Some(Value::String(name.to_string())),
                    extra: {
                        let mut map = HashMap::new();
                        map.insert("DomainId".to_string(), Value::String(
                            zone.extra.get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string()
                        ));
                        map.insert("Grade".to_string(), Value::String(
                            match plan_name {
                                "Free Website" => "DP_FREE",
                                _ => "UNKNOWN"
                            }.to_string()
                        ));
                        map.insert("GradeTitle".to_string(), Value::String(plan_name.to_string()));
                        map.insert("RecordCount".to_string(), Value::Number(0.into()));
                        map.insert("TTL".to_string(), Value::Number(600.into()));
                        map.insert("IsVip".to_string(), Value::String("NO".to_string()));
                        map.insert("GroupId".to_string(), Value::Number(1.into()));
                        map
                    }
                }
            })
            .collect();

        let response = CloudFlareResponse {
            response: Some(Response {
                domain_count_info: Some(DomainCountInfo {
                    all_total: Some(Value::Number(domain_list.len().into())),
                    domain_total: Some(Value::Number(domain_list.len().into())),
                    mine_total: Some(Value::Number(domain_list.len().into())),
                    ..Default::default()
                }),
                domain_list,
                ..Default::default()
            }),
            success: true,
            ..Default::default()
        };

        Ok(to_string(&response)?)
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

        let all_records = fetch_paginated_data(
            &self.http_client,
            &format!("{}/zones/{}/dns_records", self.api, zone_id),
            headers,
            |resp| serde_json::from_str::<RawCloudFlareResponse>(&resp.to_string())
                .map_err(|e| Box::new(e) as Box<dyn Error>),
        )
        .await?;

        let record_list: Vec<RecordList> = all_records
            .into_iter()
            .map(|zone| {
                let created_on = zone.extra.get("created_on")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1970-01-01T00:00:00Z");

                let name = zone.extra.get("Name")
                    .and_then(|v| v.as_str())
                    .map(|s| if s.is_empty() { "@" } else { s })
                    .unwrap_or("@");

                let formatted_date = DateTime::parse_from_rfc3339(created_on)
                    .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                    .unwrap_or_else(|_| "1970-01-01 00:00:00".into());

                RecordList {
                    created_on: Some(Value::String(formatted_date)),
                    name: Some(Value::String(name.to_string())),
                    extra: {
                        let mut map = HashMap::new();
                        map.insert("RecordId".to_string(), Value::String(
                            zone.extra.get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string()
                        ));
                        map.insert("Value".to_string(), Value::String(
                            zone.extra.get("content")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_string()
                        ));
                        map
                    }
                }
            })
            .collect();

        let response = CloudFlareResponse {
            response: Some(Response {
                domain_count_info: Some(DomainCountInfo {
                    all_total: Some(Value::Number(record_list.len().into())),
                    record_total: Some(Value::Number(record_list.len().into())),
                    mine_total: Some(Value::Number(record_list.len().into())),
                    ..Default::default()
                }),
                record_list,
                ..Default::default()
            }),
            success: true,
            ..Default::default()
        };

        Ok(to_string(&response)?)
    }

    async fn describe_subdomain_record_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain"
        });

        let record_list_str = self.describe_record_list(builder).await?;
        let mut records: Value = serde_json::from_str(&record_list_str)?;

        if let Some(Value::Array(array)) = records.pointer_mut("/Response/RecordList") {
            array.retain(|record| {
                record.get("Name")
                    .and_then(|name| name.as_str())
                    .map(|name_str| name_str == params.subdomain)
                    .unwrap_or(false)
            });
        }

        Ok(to_string(&records)?)
    }

    async fn describe_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required record_id: String => "RecordId"
        });

        let headers = build_headers(&self.api_token)?;
        let zone_id = get_zone_id(&self.api, &self.api_token, &*params.domain).await?;

        let records_url = format!("{}/zones/{}/dns_records/{}", self.api, zone_id, params.record_id);
        let raw = self.http_client.request(Method::GET, records_url, headers.clone(), None).await?;

        let raw_value: RawCloudFlareResponse = serde_json::from_str(&raw.to_string())?;

        if !raw_value.success {
            return Ok(to_string(&CloudFlareResponse {
                errors: raw_value.errors,
                messages: raw_value.messages,
                success: false,
                ..Default::default()
            })?);
        }

        let record_list: Option<RecordList> = raw_value.result.first().map(|zone| {
            let created_on = zone.extra.get("created_on")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00Z");

            let name = zone.extra.get("Name")
                .and_then(|v| v.as_str())
                .map(|s| if s.is_empty() { "@" } else { s })
                .unwrap_or("@");

            let formatted_date = DateTime::parse_from_rfc3339(created_on)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|_| "1970-01-01 00:00:00".into());

            RecordList {
                created_on: Some(Value::String(formatted_date)),
                name: Some(Value::String(name.to_string())),
                extra: {
                    let mut map = HashMap::new();
                    map.insert("RecordId".to_string(), Value::String(
                        zone.extra.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    ));
                    map.insert("Value".to_string(), Value::String(
                        zone.extra.get("content")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    ));
                    map
                }
            }
        });

        let records_response = CloudFlareResponse {
            response: Some(Response {
                record_info: record_list,
                ..Default::default()
            }),
            success: true,
            ..Default::default()
        };

        Ok(to_string(&records_response)?)
    }

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
        let raw = self.http_client.request(Method::POST, create_url, headers, Some(body.to_string())).await?;

        let raw_value: RawCloudFlareResponse = serde_json::from_str(&raw.to_string())?;

        if !raw_value.success {
            return Ok(to_string(&CloudFlareResponse {
                errors: raw_value.errors,
                messages: raw_value.messages,
                success: false,
                ..Default::default()
            })?);
        }

        let record_list: Option<RecordList> = raw_value.result.first().map(|zone| {
            let created_on = zone.extra.get("created_on")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00Z");

            let name = zone.extra.get("Name")
                .and_then(|v| v.as_str())
                .map(|s| if s.is_empty() { "@" } else { s })
                .unwrap_or("@");

            let formatted_date = DateTime::parse_from_rfc3339(created_on)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|_| "1970-01-01 00:00:00".into());

            RecordList {
                created_on: Some(Value::String(formatted_date)),
                name: Some(Value::String(name.to_string())),
                extra: {
                    let mut map = HashMap::new();
                    map.insert("RecordId".to_string(), Value::String(
                        zone.extra.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    ));
                    map.insert("Value".to_string(), Value::String(
                        zone.extra.get("content")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    ));
                    map
                }
            }
        });

        let records_response = CloudFlareResponse {
            response: Some(Response {
                record_info: record_list,
                ..Default::default()
            }),
            success: true,
            ..Default::default()
        };

        Ok(to_string(&records_response)?)
    }

    async fn modify_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            required record_id: String => "RecordId",
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

        let modify_url = format!("{}/zones/{}/dns_records/{}", self.api, zone_id, params.record_id);
        let raw = self.http_client.request(Method::PUT, modify_url, headers, Some(body.to_string())).await?;

        let raw_value: RawCloudFlareResponse = serde_json::from_str(&raw.to_string())?;

        if !raw_value.success {
            return Ok(to_string(&CloudFlareResponse {
                errors: raw_value.errors,
                messages: raw_value.messages,
                success: false,
                ..Default::default()
            })?);
        }

        let record_list: Option<RecordList> = raw_value.result.first().map(|zone| {
            let created_on = zone.extra.get("created_on")
                .and_then(|v| v.as_str())
                .unwrap_or("1970-01-01T00:00:00Z");

            let name = zone.extra.get("Name")
                .and_then(|v| v.as_str())
                .map(|s| if s.is_empty() { "@" } else { s })
                .unwrap_or("@");

            let formatted_date = DateTime::parse_from_rfc3339(created_on)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|_| "1970-01-01 00:00:00".into());

            RecordList {
                created_on: Some(Value::String(formatted_date)),
                name: Some(Value::String(name.to_string())),
                extra: {
                    let mut map = HashMap::new();
                    map.insert("RecordId".to_string(), Value::String(
                        zone.extra.get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    ));
                    map.insert("Value".to_string(), Value::String(
                        zone.extra.get("content")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string()
                    ));
                    map
                }
            }
        });

        let records_response = CloudFlareResponse {
            response: Some(Response {
                record_info: record_list,
                ..Default::default()
            }),
            success: true,
            ..Default::default()
        };

        Ok(to_string(&records_response)?)
    }

    async fn delete_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            optional record_id: String = "".to_string() => "RecordId"
        });

        let headers = build_headers(&self.api_token)?;
        let zone_id = get_zone_id(&self.api, &self.api_token, &params.domain).await?;

        let record_ids = if !params.record_id.is_empty() {
            vec![params.record_id]
        } else {
            let subdomain_resp = self.describe_subdomain_record_list(builder).await?;
            let parsed: CloudFlareResponse = serde_json::from_str(&subdomain_resp)
                .map_err(|e| format!("Failed to resolve subdomain record: {}\nOriginal response: {}", e, subdomain_resp))?;

            let records = parsed
                .response
                .ok_or("The response field is missing")?
                .record_list;

            let record_ids: Vec<String> = records
                .into_iter()
                .filter_map(|r| {
                    r.extra.get("RecordId")?.as_str().map(|s| s.to_string())
                })
                .collect();

            record_ids
        };

        let mut record_list = Vec::new();

        for id in record_ids {
            let delete_url = format!("{}/zones/{}/dns_records/{}", self.api, zone_id, id);
            let delete_resp = self.http_client
                .request(Method::DELETE, delete_url, headers.clone(), None)
                .await?;

            let resp_json: Value = serde_json::from_str(&delete_resp.to_string())?;
            let record_id = resp_json["result"]["id"].clone();
            let success = resp_json["success"].as_bool().unwrap_or(false);
            let errors = resp_json["errors"].clone();

            let mut extra: HashMap<String, Value> = HashMap::new();
            extra.insert("id".to_string(), record_id);
            extra.insert("success".to_string(), Value::Bool(success));
            extra.insert("errors".to_string(), errors);

            record_list.push(RecordList {
                extra,
                ..Default::default()
            });
        }

        let response = CloudFlareResponse {
            response: Some(Response {
                record_list,
                ..Default::default()
            }),
            ..Default::default()
        };

        Ok(to_string(&response)?)
    }
}

async fn fetch_paginated_data<T, F>(
    http_client: &T,
    base_url: &str,
    headers: HeaderMap,
    parse_response: F,
) -> Result<Vec<CloudFlareResult>, Box<dyn Error>>
where
    T: DnsHttpClient,
    F: Fn(String) -> Result<RawCloudFlareResponse, Box<dyn Error>>,
{
    let mut page = 1;
    let mut all_data = Vec::new();

    loop {
        let url = format!("{}?page={}&per_page=50", base_url, page);
        let response_text = http_client.request(Method::GET, url, headers.clone(), None).await?;
        let response_value: RawCloudFlareResponse = parse_response(response_text.to_string())?;

        if !response_value.result.is_empty() {
            all_data.extend(response_value.result);
        }

        let page_info = response_value.result_info.ok_or("Missing 'result_info' in response")?;
        let current_page = page_info.page.unwrap_or(1);
        let total_pages = page_info.total_pages.unwrap_or(1);

        if current_page >= total_pages {
            break;
        }

        page += 1;
    }

    Ok(all_data)
}

fn build_headers(token: &str) -> Result<HeaderMap, Box<dyn Error>> {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    headers.insert("Authorization", HeaderValue::from_str(&format!("Bearer {}", token))?);
    Ok(headers)
}

async fn get_zone_id(api_url: &str, api_token: &str, domain: &str) -> Result<String, Box<dyn Error>> {
    let http_client = DefaultDnsClient::new();
    let headers = build_headers(api_token)?;

    let zone_url = format!("{}/zones?name={}", api_url, domain);
    let zone_resp = http_client.request(Method::GET, zone_url, headers.clone(), None).await?;

    let zone_id = zone_resp["result"][0]["id"]
        .as_str()
        .ok_or("zone_id not found")?;

    Ok(zone_id.to_string())
}

impl From<RawCloudFlareResponse> for CloudFlareResponse {
    fn from(raw: RawCloudFlareResponse) -> Self {
        let response = raw.result.first().and_then(|first| {
            first.account.as_ref().map(|account| Response {
                user_info: Some(account.clone()),
                domain_count_info: None,
                domain_list: vec![],
                record_list: vec![],
                record_info: None,
            })
        });

        CloudFlareResponse {
            response,
            errors: raw.errors,
            messages: raw.messages,
            success: raw.success,
        }
    }
}

impl CloudFlareResult {
    fn to_record_list(&self) -> Result<RecordList, Box<dyn Error>> {
        let created_on = self.extra.get("created_on")
            .and_then(|v| v.as_str())
            .ok_or("Missing created_on field")?;

        let name = self.extra.get("name")
            .and_then(|v| v.as_str())
            .map(|s| if s.is_empty() { "@" } else { s })
            .unwrap_or("@");

        let formatted_date = DateTime::parse_from_rfc3339(created_on)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|_| "1970-01-01 00:00:00".into());

        Ok(RecordList {
            created_on: Some(Value::String(formatted_date)),
            name: Some(Value::String(name.to_string())),
            extra: {
                let mut map = HashMap::new();
                map.insert("RecordId".to_string(), Value::String(
                    self.extra.get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                ));
                map.insert("Value".to_string(), Value::String(
                    self.extra.get("content")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string()
                ));
                map
            }
        })
    }
}
