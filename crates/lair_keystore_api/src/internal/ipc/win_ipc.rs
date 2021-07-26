//! Windows version of ipc stream tools using  tokio::net::windows::named_pipe

use crate::*;

use std::time::Duration;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::net::windows::named_pipe::*;
use tokio::time;
use winapi::shared::winerror;

enum NamedPipedKind {
    ServerRead(tokio::io::ReadHalf<NamedPipeServer>),
    ClientRead(tokio::io::ReadHalf<NamedPipeClient>),
    ServerWrite(tokio::io::WriteHalf<NamedPipeServer>),
    ClientWrite(tokio::io::WriteHalf<NamedPipeClient>),
}

#[allow(dead_code)]
pub(crate) struct IpcRead {
    config: Arc<Config>,
    read_half: NamedPipedKind,
}

impl tokio::io::AsyncRead for IpcRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        let r = &mut self.read_half;
        match r {
            NamedPipedKind::ServerRead(server) => {
                tokio::pin!(server);
                tokio::io::AsyncRead::poll_read(server, cx, buf)
            }
            NamedPipedKind::ClientRead(client) => {
                tokio::pin!(client);
                tokio::io::AsyncRead::poll_read(client, cx, buf)
            }
            _ => unreachable!(),
        }
    }
}

#[allow(dead_code)]
pub(crate) struct IpcWrite {
    config: Arc<Config>,
    write_half: NamedPipedKind,
}

impl tokio::io::AsyncWrite for IpcWrite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<tokio::io::Result<usize>> {
        let w = &mut self.write_half;
        match w {
            NamedPipedKind::ServerWrite(server) => {
                tokio::pin!(server);
                tokio::io::AsyncWrite::poll_write(server, cx, buf)
            }
            NamedPipedKind::ClientWrite(client) => {
                tokio::pin!(client);
                tokio::io::AsyncWrite::poll_write(client, cx, buf)
            }
            _ => unreachable!(),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        let w = &mut self.write_half;
        match w {
            NamedPipedKind::ServerWrite(server) => {
                //server.poll_read(cx, buf)
                tokio::pin!(server);
                tokio::io::AsyncWrite::poll_flush(server, cx)
            }
            NamedPipedKind::ClientWrite(client) => {
                // client.poll_read(cx, buf)
                tokio::pin!(client);
                tokio::io::AsyncWrite::poll_flush(client, cx)
            }
            _ => unreachable!(),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        let w = &mut self.write_half;
        match w {
            NamedPipedKind::ServerWrite(server) => {
                tokio::pin!(server);
                tokio::io::AsyncWrite::poll_shutdown(server, cx)
            }
            NamedPipedKind::ClientWrite(client) => {
                tokio::pin!(client);
                tokio::io::AsyncWrite::poll_shutdown(client, cx)
            }
            _ => unreachable!(),
        }
    }
}

/// Create a NamedPipe Client
/// Return its IPC halves
pub(crate) async fn ipc_connect(
    config: Arc<Config>,
) -> LairResult<(IpcRead, IpcWrite)> {
    let pipe_path = config.get_socket_path();
    trace!("*** win_ipc | ipc_connect() called with {:?}", pipe_path);
    // Create Client
    let client = loop {
        match ClientOptions::new().open(pipe_path) {
            Ok(client) => break client,
            Err(e)
                if e.raw_os_error()
                    == Some(winerror::ERROR_PIPE_BUSY as i32) =>
            {
                ()
            }
            Err(e) => {
                return Err(LairError::from(format!(
                    "NamedPipe IPC failed: {}",
                    e
                )))
            }
        }
        time::sleep(Duration::from_millis(50)).await;
    };
    // Split and return client
    let (read_half, write_half) = tokio::io::split(client);
    Ok((
        IpcRead {
            config: config.clone(),
            read_half: NamedPipedKind::ClientRead(read_half),
        },
        IpcWrite {
            config,
            write_half: NamedPipedKind::ClientWrite(write_half),
        },
    ))
}

#[allow(dead_code)]
pub(crate) struct IpcServer {
    config: Arc<Config>,
    server: Option<NamedPipeServer>,
}

impl IpcServer {
    /// Create the initial NamedPipe server for given socket_path
    pub fn bind(config: Arc<Config>) -> LairResult<Self> {
        let pipe_path = config.get_socket_path();
        let _ = std::fs::remove_file(pipe_path);
        let server = ServerOptions::new().create(pipe_path)?;
        trace!(
            "*** win_ipc | IpcServer::bind()    with {:?}",
            config.get_socket_path()
        );
        Ok(Self {
            config,
            server: Some(server),
        })
    }

    /// Connect Client to Server
    /// Return Server's IPC halves
    pub async fn accept(&mut self) -> LairResult<(IpcRead, IpcWrite)> {
        //let pipe_path: &str = r"\\.\pipe\tokio-named-pipe-disconnect";
        let pipe_path = self.config.get_socket_path();
        trace!("*** win_ipc | IpcServer.accept()   with {:?}", pipe_path);
        // Create new Server if initial one has already been taken
        if self.server.is_none() {
            self.server = Some(ServerOptions::new().create(pipe_path)?);
        }
        // Take and connect Server
        let server = self.server.take().unwrap();
        trace!("*** win_ipc | server_info = {:?}", server.info()?);
        server.connect().await?;
        // Split and return Server
        let (read_half, write_half) = tokio::io::split(server);

        Ok((
            IpcRead {
                config: self.config.clone(),
                read_half: NamedPipedKind::ServerRead(read_half),
            },
            IpcWrite {
                config: self.config.clone(),
                write_half: NamedPipedKind::ServerWrite(write_half),
            },
        ))
    }
}
