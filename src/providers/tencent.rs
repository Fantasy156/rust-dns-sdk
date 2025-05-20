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
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Digest};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, HOST};
use hex::encode as hex_encode;
use crate::client::{DnsClient, DnsProviderBuilder, DnsProviderImpl, RecordOperationBuilder};
use async_trait::async_trait;
use serde_json::{json, to_string, Value};
use dns_sdk_macros::extract_params;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use crate::utils::request::DnsHttpClient;
use crate::utils::serde_utils::{is_empty_or_none, is_null_or_none, vec_is_empty, option_is_empty};

type HmacSha256 = Hmac<Sha256>;

/// Builder for creating Tencent Cloud DNS client instances.
#[derive(Default)]
pub struct TencentDnsBuilder<T: DnsHttpClient + Default> {
    secret_id: Option<String>,
    secret_key: Option<String>,
    api:  String,
    _marker: std::marker::PhantomData<T>,
}

impl<T: DnsHttpClient + Default + 'static> DnsProviderBuilder for TencentDnsBuilder<T> {
    type Output = DnsProviderImpl<T>;

    /// Sets configuration parameters for the DNS provider builder.
    ///
    /// Supported keys:
    /// - "secret_id"
    /// - "secret_key"
    ///
    /// # Panics    ///  if an unknown parameter key is provided.
    fn set_param(self: Box<Self>, key: &str, value: &str) -> Box<dyn DnsProviderBuilder<Output = DnsProviderImpl<T>>> {
        let mut this = *self;
        match key {
            "secret_id" => this.secret_id = Some(value.into()),
            "secret_key" => this.secret_key = Some(value.into()),
            _ => panic!("Invalid parameter: {}", key),
        }
        Box::new(this)
    }

    /// Constructs a new TencentDns client instance using configured parameters.
    fn build(self: Box<Self>) -> DnsProviderImpl<T> {
        DnsProviderImpl::Tencent(TencentDns {
            http_client: T::default(),
            api: "https://dnspod.tencentcloudapi.com".to_string(),
            secret_id: self.secret_id.unwrap(),
            secret_key: self.secret_key.unwrap(),
        })
    }
}

/// Helper for handling Tencent Cloud API authorization.
#[derive(Clone)]
pub(crate) struct Authorization {
    /// Service name (dnspod)
    service: String,
    /// API endpoint host
    host: String,
    region: String,
    version: String,
    action: String,
    pub(crate) payload: String,
    timestamp: i64,
    date: String,
    algorithm: String,
}

impl Authorization {
    /// Creates a new authorization context with default values.
    fn new() -> Self {
        let now = Utc::now();
        Self {
            service: "dnspod".to_string(),
            host: "dnspod.tencentcloudapi.com".to_string(),
            region: "".to_string(),
            version: "2021-03-23".to_string(),
            action: String::new(),
            payload: String::new(),
            timestamp: now.timestamp(),
            date: now.format("%Y-%m-%d").to_string(),
            algorithm: "TC3-HMAC-SHA256".to_string(),
        }
    }

    /// Sets the API action for authorization.
    fn action(mut self, action: &str) -> Self {
        self.action = action.to_string();
        self
    }

    /// Sets the request payload for authorization.
    fn payload(mut self, payload: String) -> Self {
        self.payload = payload;
        self
    }

    /// Signs a message using HMAC-SHA256 algorithm.
    fn sign(key: &[u8], msg: &str) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
        mac.update(msg.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// Computes SHA-256 hash of input and returns it as hexadecimal string.
    fn sha256_hex(input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hex_encode(hasher.finalize())
    }

    /// Generates canonical request string for AWS V4 signing process.
    fn generate_canonical_request(&self) -> String {
        let http_method = "POST";
        let canonical_uri = "/";
        let canonical_query_string = "";
        let content_type = "application/json; charset=utf-8";
        let canonical_headers = format!(
            "content-type:{}\nhost:{}\nx-tc-action:{}\n",
            content_type,
            self.host,
            self.action.to_lowercase()
        );
        let signed_headers = "content-type;host;x-tc-action";
        let hashed_payload = Self::sha256_hex(self.payload.as_str());
        format!(
            "{http_method}\n{canonical_uri}\n{canonical_query_string}\n{canonical_headers}\n{signed_headers}\n{hashed_payload}"
        )
    }

    /// Generates string-to-sign for AWS V4 signing process.
    fn generate_string_to_sign(&self, canonical_request: &str) -> String {
        let credential_scope = format!("{}/{}/tc3_request", self.date, self.service);
        let hashed_canonical_request = Self::sha256_hex(canonical_request);
        format!(
            "{}\n{}\n{}\n{}",
            self.algorithm, self.timestamp, credential_scope, hashed_canonical_request
        )
    }

    /// Calculates signature for given string-to-sign and secret key.
    fn calculate_signature(&self, string_to_sign: &str, secret_key: &str) -> String {
        let secret_date = Self::sign(format!("TC3{}", secret_key).as_bytes(), &self.date);
        let secret_service = Self::sign(&secret_date, &self.service);
        let secret_signing = Self::sign(&secret_service, "tc3_request");
        let signed_data = Self::sign(&secret_signing, string_to_sign);
        hex_encode(signed_data)
    }

    /// Generates complete authorization header for request.
    fn generate_authorization_header(&self, secret_id: &str, secret_key: &str) -> String {
        let canonical_request = self.generate_canonical_request();
        let string_to_sign = self.generate_string_to_sign(&canonical_request);
        let signature = self.calculate_signature(&string_to_sign, secret_key);
        let credential_scope = format!("{}/{}/tc3_request", self.date, self.service);
        format!(
            "{} Credential={}/{}, SignedHeaders={}, Signature={}",
            self.algorithm, secret_id, credential_scope, "content-type;host;x-tc-action", signature
        )
    }

    /// Builds signed HTTP request headers.
    pub fn build_request_headers(self, secret_id: &str, secret_key: &str) -> Result<HeaderMap, Box<dyn Error>> {
        // Calculate Authorization header
        let authorization_header = self.generate_authorization_header(secret_id, secret_key);

        // Construct HeaderMap
        let mut headers = HeaderMap::new();
        headers.insert("Authorization", HeaderValue::from_str(&authorization_header)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json; charset=utf-8"));
        headers.insert(HOST, HeaderValue::from_str(self.host.as_str())?);
        headers.insert("X-TC-Action", HeaderValue::from_str(self.action.as_str())?);
        headers.insert("X-TC-Timestamp", HeaderValue::from_str(&self.timestamp.to_string())?);
        headers.insert("X-TC-Version", HeaderValue::from_str(self.version.as_str())?);
        if !self.region.is_empty() {
            headers.insert("X-TC-Region", HeaderValue::from_str(&self.region)?);
        }

        // 返回构造好的 headers
        Ok(headers)
    }
}

/// Implementation of DNS client for Tencent Cloud.
pub struct TencentDns<T: DnsHttpClient> {
    /// HTTP client for making requests
    http_client: T,
    /// API endpoint
    api: String,
    /// API Secret ID
    secret_id: String,
    /// API Secret Key
    secret_key: String,
}

#[derive(Deserialize, Serialize)]
struct TencentResponse {
    #[serde(rename = "Response")]
    response :  Response,
}

#[derive(Deserialize, Serialize)]
#[derive(Default)]
struct Response {
    #[serde(rename = "RequestId", default)]
    request_id: String,
    #[serde(rename = "UserInfo", default, skip_serializing_if = "is_null_or_none")]
    user_info: Option<Value>,
    #[serde(rename = "DomainCountInfo", default, skip_serializing_if = "is_null_or_none")]
    domain_count_info: Option<Value>,
    #[serde(rename = "DomainList", default, skip_serializing_if = "is_empty_or_none")]
    domain_list: Option<Vec<Value>>,
    #[serde(rename = "LineGroupList", default, skip_serializing_if = "is_empty_or_none")]
    line_group_list: Option<Vec<Value>>,
    #[serde(rename = "LineList", default, skip_serializing_if = "is_empty_or_none")]
    line_list: Option<Vec<Value>>,
    #[serde(rename = "RecordCountInfo", default, skip_serializing_if = "is_null_or_none")]
    record_count_info: Option<Value>,
    #[serde(rename = "RecordList", default, skip_serializing_if = "vec_is_empty")]
    record_list: Vec<RecordList>,
    #[serde(rename = "RecordInfo", default,  skip_serializing_if = "option_is_empty")]
    record_info: Option<RecordInfo>,
    #[serde(rename = "Error", default, skip_serializing_if = "option_is_empty")]
    record_log_list: Option<TencentError>,
    #[serde(rename = "RecordInfoList", default, skip_serializing_if = "vec_is_empty")]
    record_info_list: Vec<RecordInfo>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
struct RecordInfo {
    #[serde(rename = "TTL", default)]
    ttl: Option<Value>,
    #[serde(rename = "Id", default)]
    id: Option<Value>,
    #[serde(rename = "SubDomain", default)]
    sub_domain: Option<Value>,
    #[serde(rename = "RecordType", default)]
    record_type: Option<Value>,
    #[serde(rename = "Value", default)]
    value: Option<Value>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
struct RecordList {
    #[serde(rename = "Name", default)]
    name: Option<Value>,
    #[serde(rename = "Type", default)]
    _type: Option<Value>,
    #[serde(rename = "Value", default)]
    value: Option<Value>,
    #[serde(rename = "TTL", default)]
    ttl: Option<Value>,
    #[serde(rename = "RecordId")]
    record_id: u64,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
struct TencentError {
    #[serde(rename = "Code", default)]
    code: Option<Value>,
    #[serde(rename = "Message", default)]
    message: Option<Value>,
    #[serde(flatten, default)]
    extra: HashMap<String, Value>,
}

#[async_trait]
impl<T: DnsHttpClient> DnsClient for TencentDns<T> {
    /// Retrieves user details from Tencent Cloud API.
    async fn describe_user_detail(&self) -> Result<String, Box<dyn Error>> {
        let headers = Authorization::new()
            .action("DescribeUserDetail")
            .build_request_headers(&*self.secret_id, &*self.secret_key)?;

        let resp = self.http_client.request(
            Method::POST,
            self.api.clone(),
            headers,
            None,
        ).await?;

        let parsed: TencentResponse = serde_json::from_str(&resp.to_string())?;

        Ok(to_string(&parsed)?)
    }

    /// Retrieves list of domain names associated with the user.
    async fn describe_domain_name_list(&self) -> Result<String, Box<dyn Error>> {
        let headers = Authorization::new()
            .action("DescribeDomainList")
            .build_request_headers(&*self.secret_id, &*self.secret_key)?;

        let resp = self.http_client.request(
            Method::POST,
            self.api.clone(),
            headers,
            None,
        ).await?;

        let parsed: TencentResponse = serde_json::from_value(resp)?;

        Ok(to_string(&parsed)?)
    }

    /// Retrieves record lines for a specific domain.
    ///
    /// Uses `describe_user_detail` to get user grade information.
    async fn describe_record_line_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let response = self.describe_user_detail().await?;
        let parsed: Value = serde_json::from_str(response.as_str())?;
        let user_grade = parsed["Response"]["UserInfo"]["UserGrade"]
            .as_str()
            .unwrap_or("DP_Free");

        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain"
            optional domain_grade: String = user_grade => "DomainGrade"
        });

        let json_body = to_string(&params)?;
        let headers = Authorization::new()
            .action("DescribeRecordLineList")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        let resp = self.http_client.request(
            Method::POST,
            self.api.clone(),
            headers,
            Some(json_body),
        ).await?;

        let parsed: TencentResponse = serde_json::from_value(resp)?;

        Ok(to_string(&parsed)?)
    }

    /// Retrieves record list for a specific domain.
    async fn describe_record_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain"
        });

        let json_body = to_string(&params)?;

        let headers = Authorization::new()
            .action("DescribeRecordList")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        let resp = self.http_client.request(
            Method::POST,
            self.api.clone(),
            headers,
            Some(json_body),
        ).await?;

        let parsed: TencentResponse = serde_json::from_value(resp)?;

        Ok(to_string(&parsed)?)
    }

    /// Filters DNS records to only include those matching a specific subdomain.
    async fn describe_subdomain_record_list(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
        required domain: String => "Domain",
        required subdomain: String => "SubDomain"
    });

        let raw_json = self.describe_record_list(builder).await?;

        let mut parsed: TencentResponse = serde_json::from_str(&raw_json)?;

        parsed.response.record_list.retain(|record| {
            record.name
                .as_ref()
                .and_then(|v| v.as_str())
                == Some(params.subdomain.as_str())
        });

        let count = parsed.response.record_list.len() as u32;
        parsed.response.record_count_info = Some(json!({
            "ListCount": count,
            "SubdomainCount": count,
            "TotalCount": count
        }));


        Ok(to_string(&parsed)?)
    }

    /// Retrieves details of a specific DNS record.
    async fn describe_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain"
            optional record_id: (String as u64) = 0 => "RecordId"
        });

        let mut record_info_list = Vec::new();
        let mut request_id = String::new();
        let mut record_count_info: Option<Value> = None;

        let record_ids = if params.record_id != 0 {
            record_count_info = Some(json!({
            "ListCount": 1,
            "SubdomainCount": 1,
            "TotalCount": 1
        }));
            vec![params.record_id]
        } else {
            let subdomain_resp = self.describe_subdomain_record_list(builder).await?;
            let parsed: TencentResponse = serde_json::from_str(&subdomain_resp)?;
            record_count_info = Option::from(parsed.response.record_count_info);
            parsed.response.record_list.into_iter().map(|r| r.record_id).collect()
        };


        for id in &record_ids {
            let params = extract_params!(builder, RequestParams, {required domain: String => "Domain",
                optional record_id: (String as u64) = *id => "RecordId"
            });

            let json_body = to_string(&params)?;
            let headers = Authorization::new()
                .action("DescribeRecord")
                .payload(json_body.clone())
                .build_request_headers(&self.secret_id, &self.secret_key)?;

            let resp = self.http_client.request(
                    Method::POST, "https://dnspod.tencentcloudapi.com".to_string(),
                    headers,
                    Some(json_body),
            ).await?;

            let parsed: TencentResponse = serde_json::from_value(resp)?;
            request_id = parsed.response.request_id;

            if let Some(record_info) = parsed.response.record_info {
                record_info_list.push(record_info);
            }
        }

        let merged_response = TencentResponse {
            response: Response {
                request_id,
                record_count_info,
                record_info_list,
                ..Default::default()
            }
        };

        Ok(to_string(&merged_response)?)
    }

    /// Creates a new DNS record.
    async fn create_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            required record_type: String => "RecordType",
            required value: String => "Value",
            optional record_line: String = "默认".to_string() => "RecordLine",
            optional ttl: u32 = 600 => "TTL"
        });

        let json_body = to_string(&params)?;
        let headers = Authorization::new()
            .action("CreateRecord")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        let resp = self.http_client.request(
            Method::POST,
            self.api.clone(),
            headers,
            Some(json_body),
        ).await?;

        let parsed: TencentResponse = serde_json::from_value(resp)?;

        Ok(to_string(&parsed)?)
    }

    /// Modifies an existing DNS record.
    async fn modify_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required record_type: String => "RecordType",
            required value: String => "Value",
            required record_id: (String as u64) => "RecordId",
            optional record_line: String = "默认".to_string() => "RecordLine",
            optional ttl: u32 = 600 => "TTL"
        });

        let json_body = to_string(&params)?;
        let headers = Authorization::new()
            .action("ModifyRecord")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        let resp = self.http_client.request(
            Method::POST,
            self.api.clone(),
            headers,
            Some(json_body),
        ).await?;

        let parsed: TencentResponse = serde_json::from_value(resp)?;

        Ok(to_string(&parsed)?)
    }

    /// Deletes one or more DNS records based on domain, subdomain, and optionally record ID.
    async fn delete_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required subdomain: String => "SubDomain",
            optional record_id: (String as u64) = 0 => "RecordId"
        });

        let record_ids = if params.record_id != 0 {
            vec![params.record_id]
        } else {
            let subdomain_resp = self.describe_subdomain_record_list(builder).await?;
            let parsed: TencentResponse = serde_json::from_str(&subdomain_resp)?;
            parsed.response.record_list.into_iter().map(|r| r.record_id).collect()
        };

        let mut deleted = Vec::new();

        for id in &record_ids {
            let json_body = to_string(&json!({
            "Domain": params.domain,
            "RecordId": id
        }))?;

            let headers = Authorization::new()
                .action("DeleteRecord")
                .payload(json_body.clone())
                .build_request_headers(&self.secret_id, &self.secret_key)?;

            self.http_client.request(
                Method::POST,
                self.api.clone(),
                headers,
                Some(json_body),
            ).await?;

            deleted.push(*id);
        }

        Ok(json!({
            "Response": {
                "DeletedList": deleted,
                "Subdomain": params.subdomain,
                "Domain": params.domain
            }
        }).to_string())
    }
}
