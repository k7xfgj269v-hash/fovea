//! 宿主↔靶机控制通道抽象（§13.2 / §13.6）。
//!
//! vsock = 信任边界的物理实现（§8.1）。guest-agent 把审计事件经 vsock ship 到
//! host-supervisor——不走靶机网络、不落靶机磁盘（AI 都能碰），已 ship 的宿主侧
//! 记录 AI 改不了。
//!
//! 本 crate 只定义**抽象** + 一个 in-memory `MockTransport`（单测用）。
//! 真 vsock 实现等 M0 VM 基座搭起来后补，见 `TODO(vsock)`。
//!
//! 线格式：JSON lines（§13.6，可 grep 可投影，token 友好）。
//! 每条消息 = 一行 UTF-8 JSON，以 `\n` 分隔。

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

use crate::model::Message;

pub mod model;

/// vsock 上的传输失败。
///
/// 设计原则（§13.3 控制面）：vsock 是信任边界，跨边界的失败要能精确区分，
/// 别让一个模糊的 `io::Error` 把「靶机被 AI 接管了」这种事实吞掉。
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum TransportError {
    #[error("对端在传输中途关闭连接")]
    PeerClosed,
    #[error("JSON 行解析失败：{msg}")]
    Decode { msg: String },
    #[error("JSON 序列化失败：{msg}")]
    Encode { msg: String },
    #[error("底层 I/O：{0}")]
    Io(String),
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

/// vsock 上一条连接：能收 `Message`、能发 `Message`。
///
/// 实现方负责 framing（JSON lines）+ 错误翻译成 [`TransportError`]。
/// 真实 vsock 实现见 `TODO(vsock)`；单测用 [`MockTransport`]。
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, msg: &Message) -> Result<(), TransportError>;
    async fn recv(&self) -> Result<Message, TransportError>;
}

/// 把任意 `Transport` 包成一个能共享给多 task 的 `Arc<dyn Transport>`。
///
/// 控制面常被多个 task 持有（审计 sink task + 仲裁器 task 同时用同一条 vsock），
/// 这个 helper 把构造 `Arc<..>` 这点样板代码集中起来，别在每个 crate 复制。
pub fn shared<T: Transport + 'static>(t: T) -> Arc<dyn Transport> {
    Arc::new(t)
}

/// In-memory 双向通道，单测唯一可用、真 vsock 缺席时的占位实现。
///
/// 构造时＝一对套接字：A 端发的，B 端收；反之亦然。
/// 行为模仿 `tokio::sync::mpsc`：容量有界，背压让生产者 await。
pub struct MockTransport {
    pub(crate) tx: Mutex<tokio::sync::mpsc::UnboundedSender<Message>>,
    pub(crate) rx: Mutex<tokio::sync::mpsc::UnboundedReceiver<Message>>,
}

impl MockTransport {
    /// 构造一对：返回 (a, b)，a 发的 b 收、b 发的 a 收。
    pub fn pair() -> (Self, Self) {
        let (tx_a, rx_a) = tokio::sync::mpsc::unbounded_channel();
        let (tx_b, rx_b) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                tx: Mutex::new(tx_b),
                rx: Mutex::new(rx_a),
            },
            Self {
                tx: Mutex::new(tx_a),
                rx: Mutex::new(rx_b),
            },
        )
    }
}

#[async_trait]
impl Transport for MockTransport {
    async fn send(&self, msg: &Message) -> Result<(), TransportError> {
        let tx = self.tx.lock().await;
        tx.send(msg.clone())
            .map_err(|_| TransportError::PeerClosed)
    }

    async fn recv(&self) -> Result<Message, TransportError> {
        let mut rx = self.rx.lock().await;
        rx.recv().await.ok_or(TransportError::PeerClosed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuditEvent, IntentRecord, Message, Request, RequestBody};

    #[tokio::test]
    async fn pair_roundtrips_request_and_audit() {
        let (a, b) = MockTransport::pair();

        // a 端发一个 introspect 请求（§10）
        let req = Message::Request(Request {
            id: uuid::Uuid::new_v4(),
            body: RequestBody::Introspect { pid: 1 },
        });
        a.send(&req).await.unwrap();
        // b 端应该收到同一个请求
        let got = b.recv().await.unwrap();
        match got {
            Message::Request(r) => match r.body {
                RequestBody::Introspect { pid } => assert_eq!(pid, 1),
            },
            _ => panic!("期望 Request，收到其它"),
        }

        // b 端ship 一条审计事件回 a（§13.6）
        let ev = Message::AuditEvent(AuditEvent {
            seq: 1,
            ts: chrono::Utc::now(),
            intent: IntentRecord::sample(),
        });
        b.send(&ev).await.unwrap();
        let got_ev = a.recv().await.unwrap();
        match got_ev {
            Message::AuditEvent(e) => assert_eq!(e.seq, 1),
            _ => panic!("期望 AuditEvent"),
        }
    }

    #[tokio::test]
    async fn peer_closed_when_dropped() {
        let (a, b) = MockTransport::pair();
        drop(b);
        // 对端 drop 后，a 再 send 应该报 PeerClosed
        let err = a
            .send(&Message::Request(Request {
                id: uuid::Uuid::new_v4(),
                body: RequestBody::Introspect { pid: 1 },
            }))
            .await
            .unwrap_err();
        matches!(err, TransportError::PeerClosed);
    }
}

// TODO(vsock): 真 virtio-vsock 实现（开 /dev/vsock，绑 CID， tokio 异步读写）。
// 等 M0 VM 基座搭起来后补。在此之前，host-supervisor / guest-agent 的跨边界通路
// 全部用 MockTransport 在单测里跑。
