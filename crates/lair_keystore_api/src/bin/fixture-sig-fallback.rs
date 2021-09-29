//! fixture executable to be used in signature_fallback testing
//! This binary listens to stdin for newline delimited json signature requests
//! and alternates between "success" and "error" responses.
//! It doesn't do any actual signing, it always returns an all zeroes sig.

fn main() {
    use std::io::BufRead;

    // alternate between good and bad responses
    let mut bad = false;

    // using blocking reading -- if you were actually implementing this
    // it'd probably be better to use tokio::io::AsyncBufReadExt::lines()
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();

        // parse the msg_id out of the json
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        let msg_id = parsed
            .as_object()
            .unwrap()
            .get("msgId")
            .unwrap()
            .as_str()
            .unwrap();

        // send the signature response
        if bad {
            bad = false;
            println!(r#"{{"msgId":"{}","error":"internal"}}"#, msg_id);
        } else {
            bad = true;
            println!(
                r#"{{"msgId":"{}","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}"#,
                msg_id
            );
        }
    }
}
