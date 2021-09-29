fn main() {
    use std::io::BufRead;

    let mut bad = false;

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        let msg_id = parsed
            .as_object()
            .unwrap()
            .get("msgId")
            .unwrap()
            .as_str()
            .unwrap();
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
