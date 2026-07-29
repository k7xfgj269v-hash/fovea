#[cfg(target_os = "linux")]
use std::{env, error::Error, io};

#[cfg(target_os = "linux")]
use chrono::Utc;
#[cfg(target_os = "linux")]
use vsock::{
    codec::DEFAULT_MAX_FRAME_BYTES,
    linux::{GuestVsockListener, VsockEndpoint},
    model::{ErrorReport, ExecutionOutcome, ExecutionReceipt, GuestToHost, HostToGuest, Response},
    GuestEndpoint,
};

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let endpoint = parse_endpoint()?;
    let listener = GuestVsockListener::bind(endpoint, DEFAULT_MAX_FRAME_BYTES).await?;
    let connection = listener.accept().await?;
    let HostToGuest::Request(request) = connection.recv().await?;
    let request_id = request.id;
    let started_at = Utc::now();
    let error = ErrorReport::new(
        "vsock_ping_only",
        "the transport ping example does not execute introspection",
    );
    let response = GuestToHost::Response(Response::Err {
        req_id: request_id,
        error: error.clone(),
    });
    let receipt = GuestToHost::ExecutionReceipt(ExecutionReceipt {
        request_id,
        started_at,
        finished_at: Utc::now(),
        outcome: ExecutionOutcome::Failed { error },
    });

    send_correlated(&connection, request_id, &response).await?;
    send_correlated(&connection, request_id, &receipt).await?;
    println!("vsock ping handled for request {request_id}");
    Ok(())
}

#[cfg(target_os = "linux")]
async fn send_correlated(
    connection: &impl GuestEndpoint,
    request_id: uuid::Uuid,
    message: &GuestToHost,
) -> Result<(), Box<dyn Error>> {
    if message.request_id() != request_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "correlation mismatch: expected {request_id}, received {}",
                message.request_id()
            ),
        )
        .into());
    }

    connection.send(message).await?;
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("vsock_guest_ping: unsupported platform; Linux is required");
}
