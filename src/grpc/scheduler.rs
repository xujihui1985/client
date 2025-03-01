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

// use crate::dynconfig::Dynconfig;
use crate::dynconfig::Dynconfig;
use crate::{Error, Result};
use dragonfly_api::common::v2::{Peer, Task};
use dragonfly_api::scheduler::v2::{
    scheduler_client::SchedulerClient as SchedulerGRPCClient, AnnounceHostRequest,
    ExchangePeerRequest, ExchangePeerResponse, LeaveHostRequest, LeavePeerRequest, StatPeerRequest,
    StatTaskRequest,
};
use std::str::FromStr;
use std::sync::Arc;
use tonic::transport::{Channel, Endpoint, Uri};
use tracing::{error, info};

// SchedulerClient is a wrapper of SchedulerGRPCClient.
#[derive(Clone)]
pub struct SchedulerClient {
    // dynconfig is the dynamic configuration of the dfdaemon.
    dynconfig: Arc<Dynconfig>,

    // client is the grpc client of the scehduler.
    pub client: Option<SchedulerGRPCClient<Channel>>,
}

// SchedulerClient implements the grpc client of the scheduler.
impl SchedulerClient {
    // new creates a new SchedulerClient.
    pub async fn new(dynconfig: Arc<Dynconfig>) -> Result<Self> {
        let mut client = Self {
            dynconfig,
            client: None,
        };

        client.refresh_scheduler_client().await?;
        Ok(client)
    }

    // stat_peer gets the status of the peer.
    pub async fn stat_peer(&self, request: StatPeerRequest) -> Result<Peer> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        let response = self.client()?.stat_peer(request).await?;
        Ok(response.into_inner())
    }

    // leave_peer tells the scheduler that the peer is leaving.
    pub async fn leave_peer(&self, request: LeavePeerRequest) -> Result<()> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        self.client()?.leave_peer(request).await?;
        Ok(())
    }

    // exchange_peer exchanges the peer with the scheduler.
    pub async fn exchange_peer(
        &self,
        request: ExchangePeerRequest,
    ) -> Result<ExchangePeerResponse> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        let response = self.client()?.exchange_peer(request).await?;
        Ok(response.into_inner())
    }

    // stat_task gets the status of the task.
    pub async fn stat_task(&self, request: StatTaskRequest) -> Result<Task> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        let response = self.client()?.stat_task(request).await?;
        Ok(response.into_inner())
    }

    // announce_host announces the host to the scheduler.
    pub async fn announce_host(&self, request: AnnounceHostRequest) -> Result<()> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        self.client()?.announce_host(request).await?;
        Ok(())
    }

    // leave_host tells the scheduler that the host is leaving.
    pub async fn leave_host(&self, request: LeaveHostRequest) -> Result<()> {
        let mut request = tonic::Request::new(request);
        request.set_timeout(super::REQUEST_TIMEOUT);

        self.client()?.leave_host(request).await?;
        Ok(())
    }

    // client gets the grpc client of the scheduler.
    fn client(&self) -> Result<SchedulerGRPCClient<Channel>> {
        match self.client.clone() {
            Some(client) => Ok(client),
            None => Err(Error::SchedulerClientNotFound()),
        }
    }

    // get_endpoints gets the endpoints of available schedulers.
    async fn refresh_scheduler_client(&mut self) -> Result<()> {
        // Refresh the dynamic configuration.
        self.dynconfig.refresh().await?;

        // Get the endpoints of available schedulers.
        let data = self.dynconfig.data.read().await;
        let mut endpoints: Vec<Endpoint> = Vec::new();
        for scheduler in data.available_schedulers.iter() {
            match Uri::from_str(format!("http://{}:{}", scheduler.ip, scheduler.port).as_str()) {
                Ok(uri) => endpoints.push(Endpoint::from(uri)),
                Err(e) => {
                    error!("failed to parse uri: {}", e);
                }
            }
        }
        info!(
            "available schedulers: {:?}",
            endpoints.iter().map(|e| e.uri()).collect::<Vec<_>>()
        );

        // Refresh the scheduler client.
        self.client
            .replace(SchedulerGRPCClient::new(Channel::balance_list(
                endpoints.into_iter(),
            )));
        Ok(())
    }
}
