//! Linux virtio-vsock adapters for the directional transport ports.

use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use tokio::{
    io::{split, BufReader, ReadHalf, WriteHalf},
    sync::Mutex,
};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream};

use crate::{
    codec::JsonLinesCodec,
    model::{GuestToHost, HostToGuest},
    GuestEndpoint, HostEndpoint, TransportError,
};

/// A virtio-vsock address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockEndpoint {
    pub cid: u32,
    pub port: u32,
}

/// Host side of one Linux virtio-vsock connection.
pub struct HostVsockEndpoint {
    io: EndpointIo,
}

impl HostVsockEndpoint {
    /// Connect to a guest virtio-vsock endpoint.
    pub async fn connect(
        endpoint: VsockEndpoint,
        max_frame: usize,
    ) -> Result<Self, TransportError> {
        let stream = VsockStream::connect(VsockAddr::new(endpoint.cid, endpoint.port))
            .await
            .map_err(TransportError::io)?;

        Ok(Self {
            io: EndpointIo::new(stream, max_frame),
        })
    }
}

#[async_trait]
impl HostEndpoint for HostVsockEndpoint {
    async fn send(&self, message: &HostToGuest) -> Result<(), TransportError> {
        self.io.write_host_to_guest(message).await
    }

    async fn recv(&self) -> Result<GuestToHost, TransportError> {
        self.io.read_guest_to_host().await
    }
}

/// Guest-side listener for Linux virtio-vsock connections.
pub struct GuestVsockListener {
    listener: VsockListener,
    max_frame: usize,
}

impl GuestVsockListener {
    /// Bind a guest virtio-vsock listener.
    pub async fn bind(
        endpoint: VsockEndpoint,
        max_frame: usize,
    ) -> Result<Self, TransportError> {
        let listener = VsockListener::bind(VsockAddr::new(endpoint.cid, endpoint.port))
            .map_err(TransportError::io)?;

        Ok(Self {
            listener,
            max_frame,
        })
    }

    /// Accept one guest-side virtio-vsock connection.
    pub async fn accept(&self) -> Result<GuestVsockEndpoint, TransportError> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(TransportError::io)?;

        Ok(GuestVsockEndpoint {
            io: EndpointIo::new(stream, self.max_frame),
        })
    }
}

/// Guest side of one Linux virtio-vsock connection.
pub struct GuestVsockEndpoint {
    io: EndpointIo,
}

#[async_trait]
impl GuestEndpoint for GuestVsockEndpoint {
    async fn recv(&self) -> Result<HostToGuest, TransportError> {
        self.io.read_host_to_guest().await
    }

    async fn send(&self, message: &GuestToHost) -> Result<(), TransportError> {
        self.io.write_guest_to_host(message).await
    }
}

type VsockReader = BufReader<ReadHalf<VsockStream>>;
type VsockWriter = WriteHalf<VsockStream>;

struct EndpointIo {
    reader: Mutex<VsockReader>,
    writer: Mutex<VsockWriter>,
    codec: JsonLinesCodec,
    closed: AtomicBool,
}

impl EndpointIo {
    fn new(stream: VsockStream, max_frame: usize) -> Self {
        let (reader, writer) = split(stream);

        Self {
            reader: Mutex::new(BufReader::new(reader)),
            writer: Mutex::new(writer),
            codec: JsonLinesCodec::new(max_frame),
            closed: AtomicBool::new(false),
        }
    }

    async fn read_host_to_guest(&self) -> Result<HostToGuest, TransportError> {
        ensure_open(&self.closed)?;
        let mut reader = self.reader.lock().await;
        ensure_open(&self.closed)?;
        close_on_error(
            &self.closed,
            self.codec.read_host_to_guest(&mut *reader).await,
        )
    }

    async fn read_guest_to_host(&self) -> Result<GuestToHost, TransportError> {
        ensure_open(&self.closed)?;
        let mut reader = self.reader.lock().await;
        ensure_open(&self.closed)?;
        close_on_error(
            &self.closed,
            self.codec.read_guest_to_host(&mut *reader).await,
        )
    }

    async fn write_host_to_guest(&self, message: &HostToGuest) -> Result<(), TransportError> {
        ensure_open(&self.closed)?;
        let mut writer = self.writer.lock().await;
        ensure_open(&self.closed)?;
        close_on_error(
            &self.closed,
            self.codec.write_host_to_guest(&mut *writer, message).await,
        )
    }

    async fn write_guest_to_host(&self, message: &GuestToHost) -> Result<(), TransportError> {
        ensure_open(&self.closed)?;
        let mut writer = self.writer.lock().await;
        ensure_open(&self.closed)?;
        close_on_error(
            &self.closed,
            self.codec
                .write_guest_to_host(&mut *writer, message)
                .await,
        )
    }
}

fn ensure_open(closed: &AtomicBool) -> Result<(), TransportError> {
    if closed.load(Ordering::Acquire) {
        Err(TransportError::PeerClosed)
    } else {
        Ok(())
    }
}

fn close_on_error<T>(
    closed: &AtomicBool,
    result: Result<T, TransportError>,
) -> Result<T, TransportError> {
    if result.is_err() {
        closed.store(true, Ordering::Release);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_config_preserves_cid_and_port() {
        let endpoint = VsockEndpoint {
            cid: 42,
            port: 9000,
        };

        assert_eq!(endpoint.cid, 42);
        assert_eq!(endpoint.port, 9000);
    }

    #[test]
    fn terminal_error_makes_future_operations_peer_closed() {
        let closed = AtomicBool::new(false);
        let error = close_on_error::<()>(&closed, Err(TransportError::InvalidUtf8)).unwrap_err();

        assert_eq!(error, TransportError::InvalidUtf8);
        assert_eq!(ensure_open(&closed), Err(TransportError::PeerClosed));
    }

    #[test]
    fn successful_operation_keeps_connection_open() {
        let closed = AtomicBool::new(false);

        assert_eq!(close_on_error(&closed, Ok(7)), Ok(7));
        assert_eq!(ensure_open(&closed), Ok(()));
    }
}
