#![allow(clippy::manual_async_fn)]
//! a test keystore that runs in-process

/*
use crate::lair_core::traits::*;
use crate::lair_core::*;
use crate::LairResult2 as LairResult;
use futures::future::{BoxFuture, FutureExt};
use parking_lot::RwLock;
use std::future::Future;
use std::sync::Arc;

/// a test keystore that runs in-process
pub fn create_test_keystore(
    store_factory: LairStoreFactory,
    unlock_passphrase: sodoken::BufRead,
) -> impl Future<Output = LairResult<LairClient>> + 'static + Send {
    async move {
        let store_context_key = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::hash::blake2b::hash(
            store_context_key.clone(),
            unlock_passphrase.clone(),
        )
        .await?;
        let store_context_key = store_context_key.to_read_sized();

        let store = store_factory
            .connect_to_store(store_context_key.clone())
            .await?;

        let cli_to_srv_key = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::random::bytes_buf(cli_to_srv_key.clone()).await?;

        let srv_to_cli_key = sodoken::BufWriteSized::new_mem_locked()?;
        sodoken::random::bytes_buf(srv_to_cli_key.clone()).await?;

        let sign_pk = sodoken::BufWriteSized::new_no_lock();
        let sign_sk = sodoken::BufWriteSized::new_mem_locked().unwrap();
        sodoken::sign::keypair(sign_pk.clone(), sign_sk.clone())
            .await
            .unwrap();

        let inner = PrivTestClientInner {
            store,
            unlock_passphrase,
            cli_to_srv_key: cli_to_srv_key.to_read_sized(),
            srv_to_cli_key: srv_to_cli_key.to_read_sized(),
            sign_pk: sign_pk.try_unwrap_sized().unwrap().into(),
            sign_sk: sign_sk.to_read_sized(),
        };

        let inner = Arc::new(RwLock::new(inner));

        Ok(LairClient(Arc::new(PrivTestClient(inner))))
    }
}

// -- private -- //

struct PrivTestClientInner {
    store: LairStore,
    unlock_passphrase: sodoken::BufRead,
    cli_to_srv_key: sodoken::BufReadSized<32>,
    srv_to_cli_key: sodoken::BufReadSized<32>,
    sign_pk: BinDataSized<32>,
    sign_sk: sodoken::BufReadSized<64>,
}

struct PrivTestClient(Arc<RwLock<PrivTestClientInner>>);

impl AsLairClient for PrivTestClient {
    fn get_enc_ctx_key(&self) -> sodoken::BufReadSized<32> {
        self.0.read().cli_to_srv_key.clone()
    }

    fn get_dec_ctx_key(&self) -> sodoken::BufReadSized<32> {
        self.0.read().srv_to_cli_key.clone()
    }

    fn request(
        &self,
        request: LairApiEnum,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        match request {
            LairApiEnum::ReqHello(req) => self.req_hello(req),
            LairApiEnum::ReqUnlock(req) => self.req_unlock(req),
            LairApiEnum::ReqListEntries(req) => self.req_list_entries(req),
            LairApiEnum::ReqNewSeed(req) => self.req_new_seed(req),
            // -- //
            LairApiEnum::ResError(_)
            | LairApiEnum::ResHello(_)
            | LairApiEnum::ResUnlock(_)
            | LairApiEnum::ResListEntries(_)
            | LairApiEnum::ResNewSeed(_) => async move {
                Err(format!("invalid request {:?}", request).into())
            }
            .boxed(),
        }
    }
}

impl PrivTestClient {
    fn req_hello(
        &self,
        req: LairApiReqHello,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        let inner = self.0.clone();
        async move {
            let (sign_pk, sign_sk) = {
                let lock = inner.read();
                (lock.sign_pk.clone(), lock.sign_sk.clone())
            };

            let sig = sodoken::BufWriteSized::new_no_lock();
            sodoken::sign::detached(
                sig.clone(),
                req.nonce.cloned_inner(),
                sign_sk,
            )
            .await?;

            let sig = sig.try_unwrap_sized().unwrap();
            Ok(LairApiResHello {
                msg_id: req.msg_id,
                name: "test-server".into(),
                version: "0.0.0".into(),
                server_pub_key: sign_pk,
                hello_sig: sig.into(),
            }
            .into_api_enum())
        }
        .boxed()
    }

    fn req_unlock(
        &self,
        req: LairApiReqUnlock,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        let inner = self.0.clone();
        async move {
            let (our_pass, in_key) = {
                let lock = inner.read();
                (lock.unlock_passphrase.clone(), lock.cli_to_srv_key.clone())
            };
            let their_pass = req.passphrase.decrypt(in_key).await?;
            if *our_pass.read_lock() == *their_pass.read_lock() {
                Ok(LairApiResUnlock { msg_id: req.msg_id }.into_api_enum())
            } else {
                Err("invalid passphrase".into())
            }
        }
        .boxed()
    }

    fn req_list_entries(
        &self,
        req: LairApiReqListEntries,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        let inner = self.0.clone();
        async move {
            let store = inner.read().store.clone();
            let entry_list = store.list_entries().await?;
            Ok(LairApiResListEntries {
                msg_id: req.msg_id,
                entry_list,
            }
            .into_api_enum())
        }
        .boxed()
    }

    fn req_new_seed(
        &self,
        req: LairApiReqNewSeed,
    ) -> BoxFuture<'static, LairResult<LairApiEnum>> {
        let inner = self.0.clone();
        async move {
            if req.deep_lock_passphrase.is_some() {
                return Err("deep_locked seeds not yet implemented".into());
            }
            let store = inner.read().store.clone();
            let seed_info = store.new_seed(req.tag.clone()).await?;
            Ok(LairApiResNewSeed {
                msg_id: req.msg_id,
                tag: req.tag,
                seed_info,
            }
            .into_api_enum())
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    async fn new_test_keystore() {
        let pass = sodoken::BufRead::from(&b"test"[..]);

        let store = crate::mem_store::create_mem_store_factory();
        let keystore = create_test_keystore(store, pass.clone()).await.unwrap();

        let nonce = sodoken::BufWrite::new_no_lock(24);
        sodoken::random::bytes_buf(nonce.clone()).await.unwrap();
        let nonce = nonce.try_unwrap().unwrap();

        let hello_res = keystore.hello(nonce.clone().into()).await.unwrap();
        println!("hello: {:#?}", hello_res);
        println!(
            "verify_sig: {:?}",
            hello_res
                .server_pub_key
                .verify_detached(hello_res.hello_sig.cloned_inner(), nonce)
                .await
        );

        println!(
            "unlock_bad: {:?}",
            keystore.unlock(sodoken::BufRead::from(&b"bad"[..])).await
        );
        println!("unlock_good: {:?}", keystore.unlock(pass).await);

        println!(
            "seed: {:#?}",
            keystore.new_seed("test-tag".into(), None).await
        );
        println!("list: {:#?}", keystore.list_entries().await);
    }
}
*/
