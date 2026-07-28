//! Directional host/guest control-channel ports.
//!
//! The host endpoint can send only trusted requests and receive only untrusted
//! guest evidence. The guest endpoint exposes the inverse direction. Concrete
//! JSONL and Linux vsock adapters are defined separately from these ports.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{mpsc, Mutex};

use crate::model::{GuestToHost, HostToGuest};

pub mod model;

/// vsock 上的传输失败。
///
/// 设计原则（§13.3 控制面）：vsock 是信任边界，跨边界的失败要能精确区分，
/// 别让一个模糊的 `io::Error` 把「靶机被 AI 接管了」这种事实吞掉。
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
pub enum TransportError {
    #[error("对端在传输中途关闭连接")]
    PeerClosed,
    #[error("JSON 行解析失败：{msg}")]
    Decode { msg: String },
    #[error("JSON 序列化失败：{msg}")]
    Encode { msg: String },
    #[error("底层 I/O：{0}")]
    Io(String),
    #[error("帧不是有效 UTF-8")]
    InvalidUtf8,
    #[error("帧超过 {max_frame_bytes} 字节上限")]
    FrameTooLarge { max_frame_bytes: usize },
    #[error("帧为空")]
    EmptyFrame,
    #[error("连接在换行符前结束")]
    TruncatedFrame,
    #[error("消息方向错误：期望 {expected}，收到 {received}")]
    WrongDirection { expected: String, received: String },
}

impl TransportError {
    /// 从 [`serde_json::Error`] 构造 Decode（in 路径）。
    pub fn decode(e: serde_json::Error) -> Self {
        TransportError::Decode { msg: e.to_string() }
    }
    /// 从 [`serde_json::Error`] 构造 Encode（out 路径）。
    pub fn encode(e: serde_json::Error) -> Self {
        TransportError::Encode { msg: e.to_string() }
    }
}

/// Trusted host side of one directional control channel.
#[async_trait]
pub trait HostEndpoint: Send + Sync {
    async fn send(&self, message: &HostToGuest) -> Result<(), TransportError>;
    async fn recv(&self) -> Result<GuestToHost, TransportError>;
}

/// Untrusted guest side of one directional control channel.
#[async_trait]
pub trait GuestEndpoint: Send + Sync {
    async fn recv(&self) -> Result<HostToGuest, TransportError>;
    async fn send(&self, message: &GuestToHost) -> Result<(), TransportError>;
}

/// Namespace for constructing an in-memory directional endpoint pair.
pub struct MockTransport;

impl MockTransport {
    /// Construct independent bounded channels for both protocol directions.
    ///
    /// # Panics
    ///
    /// Panics when `capacity` is zero because Tokio bounded channels require a
    /// positive capacity.
    pub fn pair(capacity: usize) -> (MockHostEndpoint, MockGuestEndpoint) {
        assert!(
            capacity > 0,
            "mock transport capacity must be greater than zero"
        );
        let (host_tx, guest_rx) = mpsc::channel(capacity);
        let (guest_tx, host_rx) = mpsc::channel(capacity);

        (
            MockHostEndpoint {
                tx: host_tx,
                rx: Mutex::new(host_rx),
            },
            MockGuestEndpoint {
                tx: guest_tx,
                rx: Mutex::new(guest_rx),
            },
        )
    }
}

/// In-memory host endpoint returned by [`MockTransport::pair`].
pub struct MockHostEndpoint {
    tx: mpsc::Sender<HostToGuest>,
    rx: Mutex<mpsc::Receiver<GuestToHost>>,
}

#[async_trait]
impl HostEndpoint for MockHostEndpoint {
    async fn send(&self, message: &HostToGuest) -> Result<(), TransportError> {
        self.tx
            .send(message.clone())
            .await
            .map_err(|_| TransportError::PeerClosed)
    }

    async fn recv(&self) -> Result<GuestToHost, TransportError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(TransportError::PeerClosed)
    }
}

/// In-memory guest endpoint returned by [`MockTransport::pair`].
pub struct MockGuestEndpoint {
    tx: mpsc::Sender<GuestToHost>,
    rx: Mutex<mpsc::Receiver<HostToGuest>>,
}

#[async_trait]
impl GuestEndpoint for MockGuestEndpoint {
    async fn recv(&self) -> Result<HostToGuest, TransportError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(TransportError::PeerClosed)
    }

    async fn send(&self, message: &GuestToHost) -> Result<(), TransportError> {
        self.tx
            .send(message.clone())
            .await
            .map_err(|_| TransportError::PeerClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        EffectSample, EffectTelemetry, ErrorReport, ExecutionOutcome, ExecutionReceipt, Request,
        RequestBody, Response,
    };
    use chrono::Utc;
    use std::{sync::Arc, time::Duration};
    use uuid::Uuid;

    #[tokio::test]
    async fn directional_round_trip_preserves_request_id() {
        let (host, guest) = MockTransport::pair(2);
        let request_id = Uuid::new_v4();
        let request = HostToGuest::Request(Request {
            id: request_id,
            body: RequestBody::Introspect { pid: 1 },
        });
        host.send(&request).await.unwrap();

        match guest.recv().await.unwrap() {
            HostToGuest::Request(received) => {
                assert_eq!(received.id, request_id);
                assert!(matches!(received.body, RequestBody::Introspect { pid: 1 }));
            }
        }

        let response = GuestToHost::Response(Response::Err {
            req_id: request_id,
            error: ErrorReport::new("proc_not_found", "no such pid"),
        });
        guest.send(&response).await.unwrap();
        assert_eq!(host.recv().await.unwrap().request_id(), request_id);
    }

    #[tokio::test]
    async fn every_guest_evidence_variant_round_trips() {
        let (host, guest) = MockTransport::pair(3);
        let request_id = Uuid::new_v4();
        let messages = [
            GuestToHost::Response(Response::Err {
                req_id: request_id,
                error: ErrorReport::new("failed", "response failed"),
            }),
            GuestToHost::ExecutionReceipt(ExecutionReceipt {
                request_id,
                started_at: Utc::now(),
                finished_at: Utc::now(),
                outcome: ExecutionOutcome::Succeeded,
            }),
            GuestToHost::EffectTelemetry(EffectTelemetry {
                request_id,
                observed_at: Utc::now(),
                samples: vec![EffectSample {
                    name: "syscalls".to_owned(),
                    value: 1,
                    unit: "count".to_owned(),
                }],
                dropped_samples: 0,
            }),
        ];

        for message in &messages {
            guest.send(message).await.unwrap();
        }

        for _ in messages {
            assert_eq!(host.recv().await.unwrap().request_id(), request_id);
        }
    }

    #[tokio::test]
    async fn bounded_channels_apply_backpressure_independently() {
        let (host, guest) = MockTransport::pair(1);
        let first = HostToGuest::Request(Request {
            id: Uuid::new_v4(),
            body: RequestBody::Introspect { pid: 1 },
        });
        let second = HostToGuest::Request(Request {
            id: Uuid::new_v4(),
            body: RequestBody::Introspect { pid: 2 },
        });
        host.send(&first).await.unwrap();

        let second_send = host.send(&second);
        tokio::pin!(second_send);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut second_send)
                .await
                .is_err()
        );

        let evidence = GuestToHost::Response(Response::Err {
            req_id: Uuid::new_v4(),
            error: ErrorReport::new("failed", "independent direction"),
        });
        guest.send(&evidence).await.unwrap();
        assert_eq!(
            host.recv().await.unwrap().request_id(),
            evidence.request_id()
        );

        assert!(matches!(
            guest.recv().await.unwrap(),
            HostToGuest::Request(Request {
                body: RequestBody::Introspect { pid: 1 },
                ..
            })
        ));
        second_send.await.unwrap();
        assert!(matches!(
            guest.recv().await.unwrap(),
            HostToGuest::Request(Request {
                body: RequestBody::Introspect { pid: 2 },
                ..
            })
        ));
    }

    #[tokio::test]
    async fn peer_close_is_reported_for_send_and_receive() {
        let (host, guest) = MockTransport::pair(1);
        drop(guest);

        let send_error = host
            .send(&HostToGuest::Request(Request {
                id: Uuid::new_v4(),
                body: RequestBody::Introspect { pid: 1 },
            }))
            .await
            .unwrap_err();
        assert!(matches!(send_error, TransportError::PeerClosed));
        assert!(matches!(host.recv().await, Err(TransportError::PeerClosed)));
    }

    #[tokio::test]
    async fn shared_endpoint_remains_directional() {
        let (host, guest) = MockTransport::pair(1);
        let host: Arc<dyn HostEndpoint> = Arc::new(host);
        let guest: Arc<dyn GuestEndpoint> = Arc::new(guest);

        host.send(&HostToGuest::Request(Request {
            id: Uuid::nil(),
            body: RequestBody::Introspect { pid: 1 },
        }))
        .await
        .unwrap();
        assert!(matches!(
            guest.recv().await.unwrap(),
            HostToGuest::Request(_)
        ));
    }

    #[test]
    #[should_panic(expected = "mock transport capacity must be greater than zero")]
    fn zero_capacity_is_rejected() {
        let _ = MockTransport::pair(0);
    }
}
