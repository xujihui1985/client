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

use reqwest::header::HeaderMap;

pub mod announcer;
pub mod backend;
pub mod config;
pub mod downloader;
pub mod dynconfig;
pub mod grpc;
pub mod health;
pub mod metrics;
pub mod proxy;
pub mod shutdown;
pub mod storage;
pub mod task;
pub mod tracing;
pub mod utils;

// Error is the error for Client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    // RocksDB is the error for rocksdb.
    #[error(transparent)]
    RocksDB(#[from] rocksdb::Error),

    // JSON is the error for serde_json.
    #[error(transparent)]
    JSON(#[from] serde_json::Error),

    // IO is the error for IO operation.
    #[error(transparent)]
    IO(#[from] std::io::Error),

    // URLParse is the error for url parse.
    #[error(transparent)]
    URLParse(#[from] url::ParseError),

    // TonicTransport is the error for tonic transport.
    #[error(transparent)]
    TonicTransport(#[from] tonic::transport::Error),

    // TonicStatus is the error for tonic status.
    #[error(transparent)]
    TonicStatus(#[from] tonic::Status),

    // Reqwest is the error for reqwest.
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    // Reqwest is the error for reqwest.
    #[error(transparent)]
    HTTP(HttpError),

    // HostNotFound is the error when the host is not found.
    #[error{"host {0} not found"}]
    HostNotFound(String),

    // TaskNotFound is the error when the task is not found.
    #[error{"task {0} not found"}]
    TaskNotFound(String),

    // PieceNotFound is the error when the piece is not found.
    #[error{"piece {0} not found"}]
    PieceNotFound(String),

    // PieceStateIsFailed is the error when the piece state is failed.
    #[error{"piece {0} state is failed"}]
    PieceStateIsFailed(String),

    // AvailableSchedulersNotFound is the error when the available schedulers is not found.
    #[error{"available schedulers not found"}]
    AvailableSchedulersNotFound(),

    // ColumnFamilyNotFound is the error when the column family is not found.
    #[error{"column family {0} not found"}]
    ColumnFamilyNotFound(String),

    // InvalidStateTransition is the error when the state transition is invalid.
    #[error{"can not transit from {0} to {1}"}]
    InvalidStateTransition(String, String),

    // InvalidState is the error when the state is invalid.
    #[error{"invalid state {0}"}]
    InvalidState(String),

    // InvalidURI is the error when the uri is invalid.
    #[error("invalid uri {0}")]
    InvalidURI(String),

    // InvalidPeer is the error when the peer is invalid.
    #[error("invalid peer {0}")]
    InvalidPeer(String),

    // SchedulerClientNotFound is the error when the scheduler client is not found.
    #[error{"scheduler client not found"}]
    SchedulerClientNotFound(),

    // UnexpectedResponse is the error when the response is unexpected.
    #[error{"unexpected response"}]
    UnexpectedResponse(),

    // PieceDigestMismatch is the error when the piece digest is mismatch.
    #[error{"piece {0} digest mismatch"}]
    PieceDigestMismatch(String),
}

// HttpError is the error for http.
#[derive(Debug, thiserror::Error)]
#[error("http error {status_code}: {body}")]
pub struct HttpError {
    // status_code is the status code of the response.
    pub status_code: reqwest::StatusCode,

    // header is the headers of the response.
    pub header: HeaderMap,

    // body is the body of the response.
    pub body: String,
}

// Result is the result for Client.
pub type Result<T> = std::result::Result<T, Error>;
