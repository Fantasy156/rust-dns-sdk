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
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Digest};
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, HOST};
use hex::encode as hex_encode;
use crate::client::{DnsClient, DnsProviderBuilder, DnsProviderImpl, RecordOperationBuilder};
use async_trait::async_trait;
use serde_json::{to_string, Value};
use dns_sdk_macros::extract_params;
use crate::providers::utils::clint;

type HmacSha256 = Hmac<Sha256>;

/// Builder for creating Tencent Cloud DNS client instances.
#[derive(Default)]
pub struct TencentDnsBuilder {
    secret_id: Option<String>,
    secret_key: Option<String>,
}

impl DnsProviderBuilder for TencentDnsBuilder {
    type Output = DnsProviderImpl;

    /// Sets configuration parameters for the DNS provider builder.
    ///
    /// Supported keys:
    /// - "secret_id"
    /// - "secret_key"
    ///
    /// # Panics
    /// Panics if an unknown parameter key is provided.
    fn set_param(self: Box<Self>, key: &str, value: &str) -> Box<dyn DnsProviderBuilder<Output = DnsProviderImpl>> {
        let mut this = *self;
        match key {
            "secret_id" => this.secret_id = Some(value.into()),
            "secret_key" => this.secret_key = Some(value.into()),
            _ => panic!("Invalid parameter: {}", key),
        }
        Box::new(this)
    }

    /// Constructs a new TencentDns client instance using configured parameters.
    fn build(self: Box<Self>) -> DnsProviderImpl {
        DnsProviderImpl::Tencent(TencentDns {
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
pub struct TencentDns {
    /// API Secret ID
    secret_id: String,
    /// API Secret Key
    secret_key: String,
}

#[async_trait]
impl DnsClient for TencentDns {
    /// Retrieves user details from Tencent Cloud API.
    async fn describe_user_detail(&self) -> Result<String, Box<dyn Error>> {
        let headers = Authorization::new()
            .action("DescribeUserDetail")
            .build_request_headers(&*self.secret_id, &*self.secret_key)?;

        Ok(clint(headers, String::new()).await?)
    }

    /// Retrieves list of domain names associated with the user.
    async fn describe_domain_name_list(&self) -> Result<String, Box<dyn Error>> {
        let headers = Authorization::new()
            .action("DescribeDomainList")
            .build_request_headers(&*self.secret_id, &*self.secret_key)?;

        Ok(clint(headers, String::new()).await?)
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

        Ok(clint(headers, json_body).await?)
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

        Ok(clint(headers, json_body).await?)
    }

    /// Retrieves details of a specific DNS record.
    async fn describe_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required record_id: u64 => "RecordId"
        });

        let json_body = to_string(&params)?;
        let headers = Authorization::new()
            .action("DescribeRecord")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        Ok(clint(headers, json_body).await?)
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

        Ok(clint(headers, json_body).await?)
    }

    /// Modifies an existing DNS record.
    async fn modify_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required record_type: String => "RecordType",
            required value: String => "Value",
            required record_id: u64 => "RecordId",
            optional record_line: String = "默认".to_string() => "RecordLine",
            optional ttl: u32 = 600 => "TTL"
        });

        let json_body = to_string(&params)?;
        let headers = Authorization::new()
            .action("ModifyRecord")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        Ok(clint(headers, json_body).await?)
    }

    /// Deletes a DNS record.
    async fn delete_record(&self, builder: &RecordOperationBuilder) -> Result<String, Box<dyn Error>> {
        let params = extract_params!(builder, RequestParams, {
            required domain: String => "Domain",
            required record_id: u64 => "RecordId"
        });

        let json_body = to_string(&params)?;
        let headers = Authorization::new()
            .action("DeleteRecord")
            .payload(json_body.clone())
            .build_request_headers(&self.secret_id, &self.secret_key)?;

        Ok(clint(headers, json_body).await?)
    }
}
