//! Bounded directional JSON Lines codec for the host/guest trust boundary.

use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    model::{GuestToHost, HostToGuest},
    TransportError,
};

/// Default maximum JSON payload size, excluding the line delimiter.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

/// A bounded JSON Lines codec for directional control messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonLinesCodec {
    max_frame_bytes: usize,
}

impl JsonLinesCodec {
    /// Construct a codec with the given maximum JSON payload size.
    pub const fn new(max_frame_bytes: usize) -> Self {
        Self { max_frame_bytes }
    }

    /// Read one trusted host-to-guest message.
    pub async fn read_host_to_guest<R>(&self, reader: &mut R) -> Result<HostToGuest, TransportError>
    where
        R: AsyncBufRead + Unpin,
    {
        self.read_direction::<HostToGuest, GuestToHost, R>(reader, "host_to_guest", "guest_to_host")
            .await
    }

    /// Read one untrusted guest-to-host evidence message.
    pub async fn read_guest_to_host<R>(&self, reader: &mut R) -> Result<GuestToHost, TransportError>
    where
        R: AsyncBufRead + Unpin,
    {
        self.read_direction::<GuestToHost, HostToGuest, R>(reader, "guest_to_host", "host_to_guest")
            .await
    }

    /// Write one trusted host-to-guest message and its newline delimiter.
    pub async fn write_host_to_guest<W>(
        &self,
        writer: &mut W,
        message: &HostToGuest,
    ) -> Result<(), TransportError>
    where
        W: AsyncWrite + Unpin,
    {
        self.write_frame(writer, message).await
    }

    /// Write one untrusted guest-to-host evidence message and its newline delimiter.
    pub async fn write_guest_to_host<W>(
        &self,
        writer: &mut W,
        message: &GuestToHost,
    ) -> Result<(), TransportError>
    where
        W: AsyncWrite + Unpin,
    {
        self.write_frame(writer, message).await
    }

    async fn read_direction<Expected, Opposite, R>(
        &self,
        reader: &mut R,
        expected: &'static str,
        received: &'static str,
    ) -> Result<Expected, TransportError>
    where
        Expected: DeserializeOwned,
        Opposite: DeserializeOwned,
        R: AsyncBufRead + Unpin,
    {
        let frame = self.read_frame(reader).await?;
        let text = std::str::from_utf8(&frame).map_err(|_| TransportError::InvalidUtf8)?;

        match serde_json::from_str(text) {
            Ok(message) => Ok(message),
            Err(expected_error) => {
                if serde_json::from_str::<Opposite>(text).is_ok() {
                    Err(TransportError::WrongDirection {
                        expected: expected.to_owned(),
                        received: received.to_owned(),
                    })
                } else {
                    Err(TransportError::malformed_decode(expected_error))
                }
            }
        }
    }

    async fn read_frame<R>(&self, reader: &mut R) -> Result<Vec<u8>, TransportError>
    where
        R: AsyncBufRead + Unpin,
    {
        let owned_limit = self.max_frame_bytes.saturating_add(1);
        let mut frame = Vec::new();

        loop {
            let available = reader.fill_buf().await.map_err(TransportError::io)?;
            if available.is_empty() {
                return if frame.is_empty() {
                    Err(TransportError::PeerClosed)
                } else {
                    Err(TransportError::TruncatedFrame)
                };
            }

            if let Some(newline_index) = available.iter().position(|byte| *byte == b'\n') {
                let total_before_newline = frame.len().saturating_add(newline_index);
                let copy_len = newline_index.min(owned_limit.saturating_sub(frame.len()));
                frame.extend_from_slice(&available[..copy_len]);
                reader.consume(newline_index + 1);

                if total_before_newline > owned_limit {
                    return Err(self.frame_too_large());
                }

                if frame.last() == Some(&b'\r') {
                    frame.pop();
                }
                if frame.len() > self.max_frame_bytes {
                    return Err(self.frame_too_large());
                }
                if frame.is_empty() {
                    return Err(TransportError::EmptyFrame);
                }

                return Ok(frame);
            }

            let available_len = available.len();
            let remaining = owned_limit.saturating_sub(frame.len());
            if available_len > remaining {
                return Err(self.frame_too_large());
            }

            frame.extend_from_slice(available);
            reader.consume(available_len);

            if frame.len() == owned_limit && frame.last() != Some(&b'\r') {
                return Err(self.frame_too_large());
            }
        }
    }

    async fn write_frame<W, T>(&self, writer: &mut W, message: &T) -> Result<(), TransportError>
    where
        W: AsyncWrite + Unpin,
        T: Serialize + ?Sized,
    {
        let encoded = serde_json::to_vec(message).map_err(TransportError::encode)?;
        if encoded.len() > self.max_frame_bytes {
            return Err(self.frame_too_large());
        }

        writer
            .write_all(&encoded)
            .await
            .map_err(TransportError::io)?;
        writer.write_all(b"\n").await.map_err(TransportError::io)?;
        writer.flush().await.map_err(TransportError::io)
    }

    fn frame_too_large(&self) -> TransportError {
        TransportError::FrameTooLarge {
            max_frame_bytes: self.max_frame_bytes,
        }
    }
}

impl Default for JsonLinesCodec {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FRAME_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ErrorReport, Request, RequestBody, Response};
    use tokio::io::{duplex, split, AsyncWriteExt, BufReader};
    use uuid::Uuid;

    fn request(pid: i32) -> HostToGuest {
        HostToGuest::Request(Request {
            id: Uuid::nil(),
            body: RequestBody::Introspect { pid },
        })
    }

    fn response() -> GuestToHost {
        GuestToHost::Response(Response::Err {
            req_id: Uuid::nil(),
            error: ErrorReport::new("failed", "test response"),
        })
    }

    #[tokio::test]
    async fn exact_frame_limit_round_trips() {
        let message = request(7);
        let encoded = serde_json::to_vec(&message).unwrap();
        let codec = JsonLinesCodec::new(encoded.len());
        let (mut writer, reader) = duplex(encoded.len() + 1);
        let mut reader = BufReader::new(reader);

        codec
            .write_host_to_guest(&mut writer, &message)
            .await
            .unwrap();
        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn over_limit_frame_is_rejected() {
        let encoded = serde_json::to_vec(&request(7)).unwrap();
        let codec = JsonLinesCodec::new(encoded.len() - 1);
        let (mut writer, reader) = duplex(encoded.len() + 1);
        let mut reader = BufReader::new(reader);

        writer.write_all(&encoded).await.unwrap();
        writer.write_all(b"\n").await.unwrap();

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::FrameTooLarge {
                max_frame_bytes: encoded.len() - 1
            }
        );
    }

    #[tokio::test]
    async fn malformed_json_is_distinct() {
        let codec = JsonLinesCodec::new(64);
        let (mut writer, reader) = duplex(64);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"{not json}\n").await.unwrap();

        assert!(matches!(
            codec.read_host_to_guest(&mut reader).await,
            Err(TransportError::MalformedDecode { .. })
        ));
    }

    #[tokio::test]
    async fn invalid_utf8_is_distinct() {
        let codec = JsonLinesCodec::new(64);
        let (mut writer, reader) = duplex(64);
        let mut reader = BufReader::new(reader);
        writer.write_all(&[0xff, b'\n']).await.unwrap();

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::InvalidUtf8
        );
    }

    #[tokio::test]
    async fn empty_frame_is_distinct() {
        let codec = JsonLinesCodec::new(64);
        let (mut writer, reader) = duplex(64);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"\n").await.unwrap();

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::EmptyFrame
        );
    }

    #[tokio::test]
    async fn crlf_is_accepted() {
        let message = request(11);
        let encoded = serde_json::to_vec(&message).unwrap();
        let codec = JsonLinesCodec::new(encoded.len());
        let (mut writer, reader) = duplex(encoded.len() + 2);
        let mut reader = BufReader::with_capacity(encoded.len() + 1, reader);

        writer.write_all(&encoded).await.unwrap();
        writer.write_all(b"\r\n").await.unwrap();

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap(),
            message
        );
    }

    #[tokio::test]
    async fn eof_after_bytes_is_truncated_frame() {
        let codec = JsonLinesCodec::new(64);
        let (mut writer, reader) = duplex(64);
        let mut reader = BufReader::new(reader);
        writer.write_all(b"{\"kind\":\"request\"}").await.unwrap();
        writer.shutdown().await.unwrap();

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::TruncatedFrame
        );
    }

    #[tokio::test]
    async fn eof_before_bytes_is_peer_closed() {
        let codec = JsonLinesCodec::new(64);
        let (writer, reader) = duplex(64);
        let mut reader = BufReader::new(reader);
        drop(writer);

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::PeerClosed
        );
    }

    #[tokio::test]
    async fn valid_opposite_direction_is_rejected() {
        let encoded = serde_json::to_vec(&response()).unwrap();
        let codec = JsonLinesCodec::new(encoded.len());
        let (mut writer, reader) = duplex(encoded.len() + 1);
        let mut reader = BufReader::new(reader);
        writer.write_all(&encoded).await.unwrap();
        writer.write_all(b"\n").await.unwrap();

        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::WrongDirection {
                expected: "host_to_guest".to_owned(),
                received: "guest_to_host".to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn oversize_encode_writes_nothing() {
        let message = request(13);
        let encoded = serde_json::to_vec(&message).unwrap();
        let codec = JsonLinesCodec::new(encoded.len() - 1);
        let (mut writer, reader) = duplex(encoded.len() + 1);
        let mut reader = BufReader::new(reader);

        assert_eq!(
            codec
                .write_host_to_guest(&mut writer, &message)
                .await
                .unwrap_err(),
            TransportError::FrameTooLarge {
                max_frame_bytes: encoded.len() - 1
            }
        );
        writer.shutdown().await.unwrap();
        assert_eq!(
            codec.read_host_to_guest(&mut reader).await.unwrap_err(),
            TransportError::PeerClosed
        );
    }

    #[tokio::test]
    async fn simultaneous_opposite_direction_traffic_round_trips() {
        let codec = JsonLinesCodec::default();
        let request = request(17);
        let response = response();
        let (host, guest) = duplex(4096);
        let (host_read, mut host_write) = split(host);
        let (guest_read, mut guest_write) = split(guest);
        let mut host_read = BufReader::new(host_read);
        let mut guest_read = BufReader::new(guest_read);

        let host_task = async {
            codec
                .write_host_to_guest(&mut host_write, &request)
                .await
                .unwrap();
            codec.read_guest_to_host(&mut host_read).await.unwrap()
        };
        let guest_task = async {
            codec
                .write_guest_to_host(&mut guest_write, &response)
                .await
                .unwrap();
            codec.read_host_to_guest(&mut guest_read).await.unwrap()
        };

        let (received_response, received_request) = tokio::join!(host_task, guest_task);
        assert_eq!(received_response.request_id(), Uuid::nil());
        assert_eq!(received_request, request);
    }
}
