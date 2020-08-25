static NEXT_MSG_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Get a new process-unique u64 message id.
pub fn next_msg_id() -> u64 {
    NEXT_MSG_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
