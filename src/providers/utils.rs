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
use reqwest::Client;
use reqwest::header::{HeaderMap, HOST};

/// Sends an HTTP POST request to the specified host with given headers and payload.
///
/// # Arguments
///
/// * `headers` - A HeaderMap containing the HTTP headers for the request.
/// * `payload` - The body content to be sent in the POST request.
///
/// # Returns
///
/// A Result containing either the decoded JSON response as a String or a dynamic Error.
///
/// # Process Description
///
/// 1. Extracts the Host header from the provided headers.
/// 2. Constructs a new HTTPS URL using the extracted host.
/// 3. Sends a POST request with the provided headers and payload.
/// 4. Receives the response body and parses it as JSON.
/// 5. Converts the parsed JSON back into a string for the output.
pub async fn clint(headers: HeaderMap, payload: String) -> Result<String, Box<dyn Error>> {
    // Extract the host from the headers
    let host = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .ok_or("Failed to extract host header")?;

    // Create a new HTTP client
    let client = Client::new();

    // Send the POST request
    let response = client
        .post(format!("https://{}/", host))
        .headers(headers)
        .body(payload)
        .send()
        .await?;

    // Get the response body as text
    let body = response.text().await?;

    // Parse the body as JSON
    let json_value: serde_json::Value = serde_json::from_str(&body)?;

    // Convert the JSON value back into a string
    let decoded_body = serde_json::to_string(&json_value)?;

    Ok(decoded_body)
}