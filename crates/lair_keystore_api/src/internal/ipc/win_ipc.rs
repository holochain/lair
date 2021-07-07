//! Windows version of ipc stream tools using  tokio::net::windows::named_pipe

use crate::*;

use std::sync::{Arc};
//use futures::lock::Mutex;
//use futures::future::FutureExt;
//use futures::future::BoxFuture;
//use std::cell::RefCell;
use std::time::Duration;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::time;
use winapi::shared::winerror;
//use std::os::windows::io::RawHandle;
//use std::os::windows::io::AsRawHandle;

//use tokio::net::windows::named_pipe::ClientOptions;
use tokio::net::windows::named_pipe::*;
//use tokio::runtime::Runtime;
//use tokio::doc::os::windows::io::RawHandle;


enum NamedPipedKind {
   //Server(Arc<Mutex<NamedPipeServer>>),
   //Client(Arc<Mutex<NamedPipeClient>>),
   ServerRead(tokio::io::ReadHalf<NamedPipeServer>),
   ClientRead(tokio::io::ReadHalf<NamedPipeClient>),
   ServerWrite(tokio::io::WriteHalf<NamedPipeServer>),
   ClientWrite(tokio::io::WriteHalf<NamedPipeClient>),
}

#[allow(dead_code)]
pub(crate) struct IpcRead {
   config: Arc<Config>,
   //read_half: tokio::io::ReadHalf<tokio::net::UnixStream>,
   //read_half: tokio::io::ReadHalf<Channel>,

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
         //NamedPipedKind::Server(locked_server) => {
         //       Runtime::new().unwrap().block_on(async {
         //          let mut server = locked_server.lock().await;
         //          //server.poll_read(cx, buf)
         //          tokio::pin!(server);
         //          tokio::io::AsyncRead::poll_read(server, cx, buf)
         //          //server.poll_read(cx, buf)
         //       })
         // },
         // NamedPipedKind::Client(locked_client) => {
         //    let client = Runtime::new().unwrap().block_on(async move {*locked_client.lock().await});
         //    //server.poll_read(cx, buf)
         //    tokio::pin!(client);
         //    tokio::io::AsyncRead::poll_read(client, cx, buf)
         // }
         NamedPipedKind::ServerRead(server) => {
            //server.poll_read(cx, buf)
            tokio::pin!(server);
            tokio::io::AsyncRead::poll_read(server, cx, buf)

         },
         NamedPipedKind::ClientRead(client) => {
            // client.poll_read(cx, buf)
            tokio::pin!(client);
            tokio::io::AsyncRead::poll_read(client, cx, buf)

         },
         _ => unreachable!(),
      }

      // let r = &mut self.read_half;
      // tokio::pin!(r);
      // tokio::io::AsyncRead::poll_read(r, cx, buf)
   }
}



#[allow(dead_code)]
pub(crate) struct IpcWrite {
   config: Arc<Config>,
   //write_half: tokio::io::WriteHalf<tokio::net::UnixStream>,
   //write_half: tokio::io::WriteHalf<Channel>,

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
            //server.poll_read(cx, buf)
            tokio::pin!(server);
            tokio::io::AsyncWrite::poll_write(server, cx, buf)

         },
         NamedPipedKind::ClientWrite(client) => {
            // client.poll_read(cx, buf)
            tokio::pin!(client);
            tokio::io::AsyncWrite::poll_write(client, cx, buf)
         },
         _ => unreachable!(),
      }

      // let r = &mut self.write_half;
      // tokio::pin!(r);
      // tokio::io::AsyncWrite::poll_write(r, cx, buf)
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

         },
         NamedPipedKind::ClientWrite(client) => {
            // client.poll_read(cx, buf)
            tokio::pin!(client);
            tokio::io::AsyncWrite::poll_flush(client, cx)
         },
         _ => unreachable!(),
      }

      // let r = &mut self.write_half;
      // tokio::pin!(r);
      // tokio::io::AsyncWrite::poll_flush(r, cx)
   }

   fn poll_shutdown(
      mut self: std::pin::Pin<&mut Self>,
      cx: &mut std::task::Context<'_>,
   ) -> std::task::Poll<tokio::io::Result<()>> {

      let w = &mut self.write_half;
      match w {
         NamedPipedKind::ServerWrite(server) => {
            //server.poll_read(cx, buf)
            tokio::pin!(server);
            tokio::io::AsyncWrite::poll_shutdown(server, cx)

         },
         NamedPipedKind::ClientWrite(client) => {
            // client.poll_read(cx, buf)
            tokio::pin!(client);
            tokio::io::AsyncWrite::poll_shutdown(client, cx)
         },
         _ => unreachable!(),
      }

      // let r = &mut self.write_half;
      // tokio::pin!(r);
      // tokio::io::AsyncWrite::poll_shutdown(r, cx)
   }
}


/// Create an IPC Client
pub(crate) async fn ipc_connect(
   config: Arc<Config>,
) -> LairResult<(IpcRead, IpcWrite)> {

   let pipe_path = config.get_socket_path(); //.to_string_lossy().to_string();

   // let socket = tokio::net::UnixStream::connect(config.get_socket_path())
   //    .await
   //    .map_err(|e| {
   //       LairError::IpcClientConnectError(
   //          config.get_socket_path().to_string_lossy().to_string(),
   //          e.into(),
   //       )
   //    })?;
   // let (read_half, write_half) = tokio::io::split(socket);

   let client = loop {
      match ClientOptions::new().open(pipe_path) {
         Ok(client) => break client,
         Err(e) if e.raw_os_error() == Some(winerror::ERROR_PIPE_BUSY as i32) => (),
         Err(_e) => return Err(LairError::from("TODO sorry!")),//Err(e),
      }

      time::sleep(Duration::from_millis(50)).await;
   };

   //let half = Arc::new(client.clone());

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
   //socket: tokio::net::UnixListener,
   //server: Arc<Mutex<NamedPipeServer>>,

   //handle: BoxFuture<'static, RawHandle>,
   //handle: RawHandle,
}

impl IpcServer {
   pub fn bind(config: Arc<Config>) -> LairResult<Self> {
      //let _pipe_path = std::fs::remove_file(config.get_socket_path());

      // let socket = tokio::net::UnixListener::bind(config.get_socket_path())
      //    .map_err(LairError::other)?;

      // const PIPE_NAME: &str = r"\\.\pipe\tokio-named-pipe-disconnect";
      //
      // let server =
      //    //Arc::new(Mutex::new(
      //    ServerOptions::new()
      //    .create(PIPE_NAME)?
      //    //))
      //    ;
      //
      // let handle = server.as_raw_handle();

      Ok(Self { config/*, handle*/})
   }


   pub async fn accept(&mut self) -> LairResult<(IpcRead, IpcWrite)> {
      //let (con, _) = self.server.accept().await.map_err(LairError::other)?;

      // {
      //    let server = self.server.lock().await;
      //
      //    let _connected = server.connect().await?;
      //
      //    server.readable().await?;
      //    server.writable().await?;
      // }

      //let server = NamedPipeServer::from_raw_handle(self.handle).unwrap();

      //const PIPE_NAME: &str = r"\\.\pipe\tokio-named-pipe-disconnect";
      let pipe_path = self.config.get_socket_path();
      let _ = std::fs::remove_file(pipe_path);

      let server = ServerOptions::new().create(pipe_path)?;

      server.readable().await?;
      server.writable().await?;

      let (read_half, write_half) = tokio::io::split(server);

      //let half = Arc::new(self.clone());

      Ok((
         IpcRead {
            config: self.config.clone(),
             read_half: NamedPipedKind::ServerRead(read_half),
            //read_half: NamedPipedKind::Server(self.server.clone()),
         },
         IpcWrite {
            config: self.config.clone(),
            write_half: NamedPipedKind::ServerWrite(write_half),
            //write_half: NamedPipedKind::Server(self.server.clone()),
         },
      ))
   }
}
