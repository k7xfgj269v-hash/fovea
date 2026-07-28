//! Linux virtio-vsock adapters for the directional transport ports.

use std::{
    io,
    net::Shutdown,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    task::{Context, Poll},
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, ReadBuf},
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

#[derive(Clone)]
struct SharedVsockStream {
    inner: Arc<StdMutex<VsockStream>>,
}

impl SharedVsockStream {
    fn new(stream: VsockStream) -> Self {
        Self {
            inner: Arc::new(StdMutex::new(stream)),
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, VsockStream>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("vsock stream mutex poisoned"))
    }
}

impl AsyncRead for SharedVsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_read(cx, buffer),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

impl AsyncWrite for SharedVsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_write(cx, buffer),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_flush(cx),
            Err(error) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.lock() {
            Ok(mut stream) => Pin::new(&mut *stream).poll_shutdown(cx),
            Err(error) => Poll::Ready(Err(error)),
        }
    }
}

trait ShutdownBoth {
    fn shutdown_both(&self) -> io::Result<()>;
}

impl ShutdownBoth for SharedVsockStream {
    fn shutdown_both(&self) -> io::Result<()> {
        self.lock()?.shutdown(Shutdown::Both)
    }
}

struct TerminalClose<S> {
    closed: AtomicBool,
    shutdown: S,
}

impl<S> TerminalClose<S>
where
    S: ShutdownBoth,
{
    fn new(shutdown: S) -> Self {
        Self {
            closed: AtomicBool::new(false),
            shutdown,
        }
    }

    fn ensure_open(&self) -> Result<(), TransportError> {
        if self.closed.load(Ordering::Acquire) {
            Err(TransportError::PeerClosed)
        } else {
            Ok(())
        }
    }

    fn finish<T>(&self, result: Result<T, TransportError>) -> Result<T, TransportError> {
        match result {
            Ok(value) => {
                self.ensure_open()?;
                Ok(value)
            }
            Err(error) => {
                if self
                    .closed
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    let _ = self.shutdown.shutdown_both();
                    Err(error)
                } else {
                    Err(TransportError::PeerClosed)
                }
            }
        }
    }
}

type VsockReader = BufReader<SharedVsockStream>;
type VsockWriter = SharedVsockStream;

struct EndpointIo {
    reader: Mutex<VsockReader>,
    writer: Mutex<VsockWriter>,
    codec: JsonLinesCodec,
    terminal: TerminalClose<SharedVsockStream>,
}

impl EndpointIo {
    fn new(stream: VsockStream, max_frame: usize) -> Self {
        let stream = SharedVsockStream::new(stream);

        Self {
            reader: Mutex::new(BufReader::new(stream.clone())),
            writer: Mutex::new(stream.clone()),
            codec: JsonLinesCodec::new(max_frame),
            terminal: TerminalClose::new(stream),
        }
    }

    async fn read_host_to_guest(&self) -> Result<HostToGuest, TransportError> {
        self.terminal.ensure_open()?;
        let mut reader = self.reader.lock().await;
        self.terminal.ensure_open()?;
        self.terminal
            .finish(self.codec.read_host_to_guest(&mut *reader).await)
    }

    async fn read_guest_to_host(&self) -> Result<GuestToHost, TransportError> {
        self.terminal.ensure_open()?;
        let mut reader = self.reader.lock().await;
        self.terminal.ensure_open()?;
        self.terminal
            .finish(self.codec.read_guest_to_host(&mut *reader).await)
    }

    async fn write_host_to_guest(&self, message: &HostToGuest) -> Result<(), TransportError> {
        self.terminal.ensure_open()?;
        let mut writer = self.writer.lock().await;
        self.terminal.ensure_open()?;
        self.terminal
            .finish(self.codec.write_host_to_guest(&mut *writer, message).await)
    }

    async fn write_guest_to_host(&self, message: &GuestToHost) -> Result<(), TransportError> {
        self.terminal.ensure_open()?;
        let mut writer = self.writer.lock().await;
        self.terminal.ensure_open()?;
        self.terminal.finish(
            self.codec
                .write_guest_to_host(&mut *writer, message)
                .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, Barrier};
    use tokio::sync::watch;

    #[derive(Clone)]
    struct TestShutdown {
        calls: Arc<AtomicUsize>,
        closed: watch::Sender<bool>,
    }

    impl ShutdownBoth for TestShutdown {
        fn shutdown_both(&self) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            self.closed.send_replace(true);
            Ok(())
        }
    }

    #[test]
    fn endpoint_config_preserves_cid_and_port() {
        let endpoint = VsockEndpoint {
            cid: 42,
            port: 9000,
        };

        assert_eq!(endpoint.cid, 42);
        assert_eq!(endpoint.port, 9000);
    }

    #[tokio::test]
    async fn terminal_error_physically_closes_and_wakes_opposite_direction() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (closed, mut closed_rx) = watch::channel(false);
        let terminal = Arc::new(TerminalClose::new(TestShutdown {
            calls: Arc::clone(&calls),
            closed,
        }));
        let opposite_terminal = Arc::clone(&terminal);
        let opposite = tokio::spawn(async move {
            while !*closed_rx.borrow() {
                closed_rx.changed().await.unwrap();
            }
            opposite_terminal
                .finish::<()>(Err(TransportError::Io {
                    msg: "woken opposite direction".to_owned(),
                }))
                .unwrap_err()
        });

        let error = terminal
            .finish::<()>(Err(TransportError::InvalidUtf8))
            .unwrap_err();
        assert_eq!(error, TransportError::InvalidUtf8);
        assert_eq!(opposite.await.unwrap(), TransportError::PeerClosed);
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(terminal.ensure_open(), Err(TransportError::PeerClosed));
    }

    #[test]
    fn racing_terminal_errors_shutdown_once_and_preserve_only_winner() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (closed, _) = watch::channel(false);
        let terminal = Arc::new(TerminalClose::new(TestShutdown {
            calls: Arc::clone(&calls),
            closed,
        }));
        let barrier = Arc::new(Barrier::new(3));

        let left_terminal = Arc::clone(&terminal);
        let left_barrier = Arc::clone(&barrier);
        let left = std::thread::spawn(move || {
            left_barrier.wait();
            left_terminal
                .finish::<()>(Err(TransportError::InvalidUtf8))
                .unwrap_err()
        });

        let right_terminal = Arc::clone(&terminal);
        let right_barrier = Arc::clone(&barrier);
        let right = std::thread::spawn(move || {
            right_barrier.wait();
            right_terminal
                .finish::<()>(Err(TransportError::TruncatedFrame))
                .unwrap_err()
        });

        barrier.wait();
        let left_error = left.join().unwrap();
        let right_error = right.join().unwrap();

        assert!(
            (left_error == TransportError::InvalidUtf8
                && right_error == TransportError::PeerClosed)
                || (left_error == TransportError::PeerClosed
                    && right_error == TransportError::TruncatedFrame)
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(terminal.ensure_open(), Err(TransportError::PeerClosed));
    }

    #[test]
    fn successful_operation_keeps_connection_open() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (closed, _) = watch::channel(false);
        let terminal = TerminalClose::new(TestShutdown {
            calls: Arc::clone(&calls),
            closed,
        });

        assert_eq!(terminal.finish(Ok(7)), Ok(7));
        assert_eq!(terminal.ensure_open(), Ok(()));
        assert_eq!(calls.load(Ordering::Acquire), 0);
    }
}
