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
        while let Some(msg) = r.next().await {
            match msg {
                LowLevelWireApi::LowLevelSend { respond, msg, .. } => {
                    let res = kill_switch
                        .mix(async {
                            tracing::trace!("ll write {:?}", msg);
                            let msg = msg.encode()?;
                            write_half
                                .write_all(&msg)
                                .await
                                .map_err(LairError::other)?;
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
            let read = kill_switch
                .mix(async {
                    read_half.read(&mut buffer).await.map_err(LairError::other)
                })
                .await?;
            pending_data.extend_from_slice(&buffer[..read]);
            while let Ok(size) = LairWire::peek_size(&pending_data) {
                if pending_data.len() < size {
                    break;
                }
                let msg = LairWire::decode(&pending_data)?;
                tracing::trace!("ll read {:?}", msg);
                let _ = pending_data.drain(..size);
                kill_switch.mix(s.low_level_send(msg)).await?;
            }
        }
    });

    Ok(r)
}
