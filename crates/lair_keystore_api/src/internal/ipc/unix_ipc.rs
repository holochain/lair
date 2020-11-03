//! unix version of ipc stream tools

use crate::*;

#[allow(dead_code)]
pub(crate) struct IpcRead {
    config: Arc<Config>,
    //read_half: tokio::net::unix::OwnedReadHalf,
    read_half: tokio::io::ReadHalf<tokio::net::UnixStream>,
}

impl tokio::io::AsyncRead for IpcRead {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        let r = &mut self.read_half;
        tokio::pin!(r);
        tokio::io::AsyncRead::poll_read(r, cx, buf)
    }
}

#[allow(dead_code)]
pub(crate) struct IpcWrite {
    config: Arc<Config>,
    //write_half: tokio::net::unix::OwnedWriteHalf,
    write_half: tokio::io::WriteHalf<tokio::net::UnixStream>,
}

impl tokio::io::AsyncWrite for IpcWrite {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<tokio::io::Result<usize>> {
        let r = &mut self.write_half;
        tokio::pin!(r);
        tokio::io::AsyncWrite::poll_write(r, cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        let r = &mut self.write_half;
        tokio::pin!(r);
        tokio::io::AsyncWrite::poll_flush(r, cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<tokio::io::Result<()>> {
        let r = &mut self.write_half;
        tokio::pin!(r);
        tokio::io::AsyncWrite::poll_shutdown(r, cx)
    }
}

pub(crate) async fn ipc_connect(
    config: Arc<Config>,
) -> LairResult<(IpcRead, IpcWrite)> {
    let socket = tokio::net::UnixStream::connect(config.get_socket_path())
        .await
        .map_err(|e| {
            LairError::IpcClientConnectError(
                config.get_socket_path().to_string_lossy().to_string(),
                e.into(),
            )
        })?;
    //let (read_half, write_half) = socket.into_split();
    let (read_half, write_half) = tokio::io::split(socket);
    Ok((
        IpcRead {
            config: config.clone(),
            read_half,
        },
        IpcWrite { config, write_half },
    ))
}

#[allow(dead_code)]
pub(crate) struct IpcServer {
    config: Arc<Config>,
    socket: tokio::net::UnixListener,
}

impl IpcServer {
    pub fn bind(config: Arc<Config>) -> LairResult<Self> {
        let _ = std::fs::remove_file(config.get_socket_path());
        let socket = tokio::net::UnixListener::bind(config.get_socket_path())
            .map_err(LairError::other)?;
        Ok(Self { config, socket })
    }

    pub async fn accept(&mut self) -> LairResult<(IpcRead, IpcWrite)> {
        let (con, _) = self.socket.accept().await.map_err(LairError::other)?;
        //let (read_half, write_half) = con.into_split();
        let (read_half, write_half) = tokio::io::split(con);
        Ok((
            IpcRead {
                config: self.config.clone(),
                read_half,
            },
            IpcWrite {
                config: self.config.clone(),
                write_half,
            },
        ))
    }
}
