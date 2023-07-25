/*
 *     Copyright 2023 The Dragonfly Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::Result;
use dragonfly_api::security::{
    certificate_client::CertificateClient as CertificateGRPCClient, CertificateRequest,
    CertificateResponse,
};
use std::net::SocketAddr;
use tonic::transport::Channel;

// CertificateClient is a wrapper of CertificateGRPCClient.
pub struct CertificateClient {
    // client is the grpc client of the certificate.
    pub client: CertificateGRPCClient<Channel>,
}

// CertificateClient implements the grpc client of the certificate.
impl CertificateClient {
    // new creates a new CertificateClient.
    pub async fn new(addr: SocketAddr) -> Result<Self> {
        let conn = tonic::transport::Endpoint::new(addr.to_string())?
            .connect()
            .await?;
        let client = CertificateGRPCClient::new(conn);
        Ok(Self { client })
    }

    // issue_certificate issues a certificate for the peer.
    pub async fn issue_certificate(
        &mut self,
        request: CertificateRequest,
    ) -> Result<CertificateResponse> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        let response = self.client.issue_certificate(request).await?;
        Ok(response.into_inner())
    }
}
