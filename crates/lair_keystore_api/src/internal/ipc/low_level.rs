use super::*;

ghost_actor::ghost_chan! {
    /// Low-level send api..
    pub(crate) chan LowLevelWireApi<LairError> {
        /// Send LairWire message somewhere.
        fn low_level_send(msg: LairWire) -> ();
    }
}

/// Low-level send api Sender.
pub(crate) type LowLevelWireSender =
    futures::channel::mpsc::Sender<LowLevelWireApi>;

/// Low-level send api Receiver.
pub(crate) type LowLevelWireReceiver =
    futures::channel::mpsc::Receiver<LowLevelWireApi>;

pub(crate) fn spawn_low_level_write_half(
    kill_switch: KillSwitch,
    mut write_half: IpcWrite,
) -> LairResult<LowLevelWireSender> {
    let (s, mut r) = futures::channel::mpsc::channel(10);

    err_spawn("ll-write", async move {
        while let Ok(msg) = kill_switch
            .mix(async {
                r.next()
                    .await
                    .ok_or_else::<LairError, _>(|| "stream end".into())
            })
            .await
        {
            match msg {
                LowLevelWireApi::LowLevelSend { respond, msg, .. } => {
                    let res = kill_switch
                        .mix(async {
                            let msg_enc = msg.encode()?;
                            write_half
                                .write_all(&msg_enc)
                                .await
                                .map_err(LairError::other)?;
                            trace!("ll wrote {:?}", msg);
                            Ok(())
                        })
                        .await;
                    let should_break = res.is_err();
                    respond.respond(Ok(async move { res }.boxed().into()));
                    if should_break {
                        // we care that the error is sent to the caller
                        // our only job is to stop looping
                        break;
                    }
                }
            }
        }
        LairResult::<()>::Ok(())
    });

    Ok(s)
}

pub(crate) fn spawn_low_level_read_half(
    kill_switch: KillSwitch,
    mut read_half: IpcRead,
) -> LairResult<LowLevelWireReceiver> {
    let (s, r) = futures::channel::mpsc::channel(10);

    err_spawn("ll-read", async move {
        let mut pending_data = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            trace!("ll read tick");
            let read = kill_switch
                .mix(async {
                    read_half.read(&mut buffer).await.map_err(LairError::other)
                })
                .await?;
            trace!(?read, "ll read count");
            if read == 0 {
                trace!("ll read end");
                return Err("read returned 0 bytes".into());
            }
            pending_data.extend_from_slice(&buffer[..read]);
            while let Ok(size) = LairWire::peek_size(&pending_data) {
                trace!(?size, "ll read peek size");
                if pending_data.len() < size {
                    break;
                }
                let msg = LairWire::decode(&pending_data)?;
                let _ = pending_data.drain(..size);
                trace!("ll read {:?}", msg);
                // run this in a task so we don't hold up the read loop
                let weak_kill_switch = kill_switch.weak();
                let task_sender = s.clone();
                tokio::task::spawn(async move {
                    let _ = weak_kill_switch
                        .mix(task_sender.low_level_send(msg))
                        .await;
                    trace!("ll read send done");
                });
            }
        }
    });

    Ok(r)
}
