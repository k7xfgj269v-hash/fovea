#[cfg(target_os = "linux")]
use std::{env, error::Error, io};

#[cfg(target_os = "linux")]
use uuid::Uuid;
#[cfg(target_os = "linux")]
use vsock::{
    codec::DEFAULT_MAX_FRAME_BYTES,
    linux::{HostVsockEndpoint, VsockEndpoint},
    model::{GuestToHost, HostToGuest, Request, RequestBody},
    HostEndpoint,
};

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let endpoint = parse_endpoint()?;
    let connection = HostVsockEndpoint::connect(endpoint, DEFAULT_MAX_FRAME_BYTES).await?;
    let request_id = Uuid::new_v4();

    connection
        .send(&HostToGuest::Request(Request {
            id: request_id,
            body: RequestBody::Introspect { pid: 1 },
        }))
        .await?;

    let mut saw_response = false;
    let mut saw_receipt = false;
    for _ in 0..2 {
        let evidence = connection.recv().await?;
        if evidence.request_id() != request_id {
            return Err(invalid_data(format!(
                "correlation mismatch: expected {request_id}, received {}",
                evidence.request_id()
            ))
            .into());
        }

        match evidence {
            GuestToHost::Response(_) if !saw_response => saw_response = true,
            GuestToHost::ExecutionReceipt(_) if !saw_receipt => saw_receipt = true,
            GuestToHost::Response(_) => {
                return Err(invalid_data("received duplicate response").into());
            }
            GuestToHost::ExecutionReceipt(_) => {
                return Err(invalid_data("received duplicate execution receipt").into());
            }
            GuestToHost::EffectTelemetry(_) => {
                return Err(invalid_data("received unexpected effect telemetry").into());
            }
        }
    }

    if !saw_response || !saw_receipt {
        return Err(invalid_data("round trip did not include response and receipt").into());
    }

    println!("vsock ping completed for request {request_id}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_endpoint() -> Result<VsockEndpoint, Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("usage: {} <cid> <port>", args[0]),
        )
        .into());
    }

    Ok(VsockEndpoint {
        cid: args[1].parse()?,
        port: args[2].parse()?,
    })
}

#[cfg(target_os = "linux")]
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vsock_host_ping: unsupported platform; Linux is required");
}
