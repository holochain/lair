#![allow(dead_code)]
use super::*;

pub(crate) type IpcSend =
    Box<dyn tokio::io::AsyncWrite + 'static + Send + Unpin>;
pub(crate) type IpcRecv =
    Box<dyn tokio::io::AsyncRead + 'static + Send + Unpin>;
pub(crate) type IpcConRecv =
    futures::stream::BoxStream<'static, LairResult<(IpcSend, IpcRecv)>>;

// -- unix/macOs implementation -- //

#[cfg(not(windows))]
pub(crate) fn ipc_connect(
    connection_url: url::Url,
) -> impl Future<Output = LairResult<(IpcSend, IpcRecv)>> + 'static + Send {
    async move {
        if connection_url.scheme() != "unix" {
            return Err(
                "IpcKeystore connection on unix/macOs must be 'unix:' scheme."
                    .into(),
            );
        }

        // connect the socket
        let path = connection_url.path();
        let socket = tokio::net::UnixStream::connect(path)
            .await
            .map_err(one_err::OneErr::new)?;

        // split into send / recv halves
        let (recv, send) = socket.into_split();

        // box and return
        let send: IpcSend = Box::new(send);
        let recv: IpcRecv = Box::new(recv);
        Ok((send, recv))
    }
}

#[cfg(not(windows))]
pub(crate) fn ipc_bind(
    config: LairServerConfig,
) -> impl Future<Output = LairResult<IpcConRecv>> + 'static + Send {
    async move {
        if config.get_connection_scheme() != "unix" {
            return Err(
                "IpcKeystore connection on unix/macOs must be 'unix:' scheme."
                    .into(),
            );
        }

        let path = config.get_connection_path();

        // we've already acquired our pid_file
        // it's safe to say we own the domain socket
        // and can remove any previous remnant
        let _ = tokio::fs::remove_file(&path).await;

        // bind to the domain socket
        let socket = tokio::net::UnixListener::bind(path)?;

        // consecutively read incoming connections / forward them
        let recv: IpcConRecv =
            futures::stream::try_unfold(socket, |socket| async move {
                let (con, _) = socket.accept().await?;
                let (recv, send) = con.into_split();
                let send: IpcSend = Box::new(send);
                let recv: IpcRecv = Box::new(recv);
                Ok(Some(((send, recv), socket)))
            })
            .boxed();

        Ok(recv)
    }
}

// -- windows implementation -- //

#[cfg(windows)]
pub(crate) fn ipc_connect(
    connection_url: url::Url,
) -> impl Future<Output = LairResult<(IpcSend, IpcRecv)>> + 'static + Send {
    async move {
        if connection_url.scheme() != "named-pipe" {
            return Err("IpcKeystore connection on windows must be 'named-pipe:' scheme.".into());
        }

        // this loop is verbatim from the tokio docs
        let path = connection_url.path();
        let pipe = loop {
            match tokio::net::windows::named_pipe::ClientOptions::new()
                .open(path)
            {
                Ok(client) => break client,
                Err(e)
                    if e.raw_os_error()
                        == Some(
                            winapi::shared::winerror::ERROR_PIPE_BUSY as i32,
                        ) =>
                {
                    ()
                }
                Err(e) => return Err(one_err::OneErr::new(e)),
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };

        // split into send / recv halves
        let (recv, send) = tokio::io::split(pipe);

        // box and return
        let send: IpcSend = Box::new(send);
        let recv: IpcRecv = Box::new(recv);
        Ok((send, recv))
    }
}

#[cfg(windows)]
pub(crate) fn ipc_bind(
    config: LairServerConfig,
) -> impl Future<Output = LairResult<IpcConRecv>> + 'static + Send {
    async move {
        if config.get_connection_scheme() != "named-pipe" {
            return Err("IpcKeystore connection on windows must be 'named-pipe:' scheme.".into());
        }

        let path = config.get_connection_path().to_owned();

        // open the initial named pipe server-side acceptor
        // note the special first_pipe_instance flag.
        // windows named pipes are weird...
        let pipe = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)?;

        // loop on accepting incoming connections
        let recv: IpcConRecv = futures::stream::try_unfold(
            (path, pipe),
            |(path, pipe)| async move {
                // await a client connection
                pipe.connect().await?;

                // windows named pipes are weird...
                // you just make a successive stream of servers
                // with the same name...
                let next_pipe =
                    tokio::net::windows::named_pipe::ServerOptions::new()
                        .create(&path)?;

                // return the connection we established
                let (recv, send) = tokio::io::split(pipe);
                let send: IpcSend = Box::new(send);
                let recv: IpcRecv = Box::new(recv);
                Ok(Some(((send, recv), (path, next_pipe))))
            },
        )
        .boxed();

        Ok(recv)
    }
}
