//! fixture executable to be used in signature_fallback testing
//! This binary listens to stdin for newline delimited json signature requests
//! and performs specific test logic.
//! It doesn't do any actual signing, it always returns an all zeroes sig.
//!
//! - `alternate` - switch between success and error responses
//! - `one_and_done` - one success, then close executable
//! - `never_3` - takes 3 requests without responding and closes

fn print_err(msg_id: &str, err: &str) {
    println!(r#"{{"msgId":"{msg_id}","error":"{err}"}}"#);
}

fn print_sig(msg_id: &str) {
    println!(
        r#"{{"msgId":"{msg_id}","signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}}"#
    );
}

fn main() {
    use std::io::BufRead;

    let mut test: Box<dyn FnMut(&str)> =
        match std::env::args().nth(1).unwrap().as_str() {
            "alternate" => {
                // alternate between good and bad responses
                let mut bad = false;

                Box::new(move |msg_id: &str| {
                    // send the signature response
                    if bad {
                        bad = false;
                        print_err(msg_id, "internal");
                    } else {
                        bad = true;
                        print_sig(msg_id);
                    }
                })
            }
            "one_and_done" => {
                Box::new(|msg_id: &str| {
                    // send the signature response
                    print_sig(msg_id);

                    // then exit
                    std::process::exit(0);
                })
            }
            "never_3" => {
                let mut r_count = 0;
                Box::new(move |_msg_id: &str| {
                    r_count += 1;
                    if r_count >= 3 {
                        std::process::exit(0);
                    }
                })
            }
            oth => panic!("invalid test: '{}'", oth),
        };

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

        test(msg_id);
    }
}
