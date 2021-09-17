/// Enum to specify limits (difficulty) for argon2id pwhashing algorithm.
///
/// Ops in this library don't take explicit limit parameters. Instead, they
/// check the current context, if not set using the default "Moderate" limits.
///
/// To set the context for the scope of the "with_exec" callback:
///
/// ```rust
/// # use hc_seed_bundle::*;
/// let _my_result = PwHashLimits::Interactive.with_exec(|| {
///   // execute my function that needs "interactive" limits
/// });
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwHashLimits {
    /// low cpu/mem limits
    Interactive,

    /// middle cpu/mem limits (default)
    Moderate,

    /// high cpu/mem limits
    Sensitive,
}

thread_local! {
    static PWHASH_LIMITS: std::cell::RefCell<PwHashLimits> = std::cell::RefCell::new(PwHashLimits::Moderate);
}

impl PwHashLimits {
    /// Get the current set limits
    /// or the default "Moderate" limits if none are set by `with_exec()`.
    pub fn current() -> Self {
        PWHASH_LIMITS.with(|s| *s.borrow())
    }

    /// Execute a closure with these pwhash limits set.
    pub fn with_exec<R, F>(self, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        PWHASH_LIMITS.with(move |s| {
            *s.borrow_mut() = self;
            let res = f();
            *s.borrow_mut() = PwHashLimits::Moderate;
            res
        })
    }

    /// translate into mem limit
    pub(crate) fn as_mem_limit(&self) -> u32 {
        match self {
            Self::Interactive => sodoken::hash::argon2id::MEMLIMIT_INTERACTIVE,
            Self::Moderate => sodoken::hash::argon2id::MEMLIMIT_MODERATE,
            Self::Sensitive => sodoken::hash::argon2id::MEMLIMIT_SENSITIVE,
        }
    }

    /// translate into cpu limit
    pub(crate) fn as_ops_limit(&self) -> u32 {
        match self {
            Self::Interactive => sodoken::hash::argon2id::OPSLIMIT_INTERACTIVE,
            Self::Moderate => sodoken::hash::argon2id::OPSLIMIT_MODERATE,
            Self::Sensitive => sodoken::hash::argon2id::OPSLIMIT_SENSITIVE,
        }
    }
}
