use parking_lot::Mutex;
use super::*;

/// For SeedCipherSecurityQuestions (and the "Locked" struct)
/// we need to be able to translate three answers into a semi-deterministic
/// passphrase. This process involves lower-casing, trimming, and concatenating.
pub(crate) fn process_security_answers<const N1: usize, const N2: usize, const N3: usize, const O: usize>(
    mut a1: sodoken::LockedArray<N1>,
    mut a2: sodoken::LockedArray<N2>,
    mut a3: sodoken::LockedArray<N3>,
) -> Result<sodoken::LockedArray<O>, OneErr>
{
    // first, get read-locks to all our input data
    let a1 = a1.lock();
    let a2 = a2.lock();
    let a3 = a3.lock();

    // careful not to move any bytes out of protected memory
    // convert to utf8 so we can use the rust trim / lcase functions.
    let a1 = std::str::from_utf8(a1.as_slice()).map_err(OneErr::new)?;
    let a2 = std::str::from_utf8(a2.as_slice()).map_err(OneErr::new)?;
    let a3 = std::str::from_utf8(a3.as_slice()).map_err(OneErr::new)?;

    // trim
    let a1 = a1.trim();
    let a2 = a2.trim();
    let a3 = a3.trim();

    // get the utf8 bytes
    let a1 = a1.as_bytes();
    let a2 = a2.as_bytes();
    let a3 = a3.as_bytes();

    // create the output buffer
    let out =
        sodoken::LockedArray::<{ a1.len() + a2.len() + a3.len() }>::new()?;

    {
        // output buffer write lock
        let mut out = out.write_lock();

        // copy / concatenate the three answers
        out[0..a1.len()].copy_from_slice(a1);
        out[a1.len()..a1.len() + a2.len()].copy_from_slice(a2);
        out[a1.len() + a2.len()..a1.len() + a2.len() + a3.len()]
            .copy_from_slice(a3);

        // we forced utf8 above, so safe to unwrap here
        let out = std::str::from_utf8_mut(&mut out).unwrap();

        // this needs a mutable buffer, so we have to do this in out memory
        out.make_ascii_lowercase();
    }

    // return the read-only concatonated passphrase
    Ok(out)
}

/// Use the given passphrase to generate a deterministic secret with argon.
/// Use that secret to secretstream encrypt the given seed.
/// Return the argon salt, and the secretstream header and cipher.
pub(crate) async fn pw_enc<const P: usize>(
    seed: Arc<Mutex<sodoken::LockedArray<32>>>,
    mut passphrase: sodoken::LockedArray<P>,
    limits: PwHashLimits,
) -> Result<(
    sodoken::LockedArray<{ sodoken::argon2::ARGON2_ID_SALTBYTES }>,
    sodoken::LockedArray<24>,
    sodoken::LockedArray<49>,
), OneErr> {
    // pre-hash the passphrase
    let mut pw_hash = sodoken::LockedArray::<64>::new()?;
    sodoken::blake2b::blake2b_hash(pw_hash.lock().as_mut_slice(), passphrase.lock().as_slice(), None)?;

    // generate a random salt
    let mut salt = sodoken::LockedArray::new()?;
    sodoken::random::randombytes_buf(salt.lock().as_mut_slice())?;

    // generate a secret using the passphrase with argon
    let ops_limit = limits.as_ops_limit();
    let mem_limit = limits.as_mem_limit();
    let mut secret = sodoken::LockedArray::new()?;
    tokio::task::spawn_blocking(|| {
        sodoken::argon2::blocking_argon2id(
            secret.lock().as_mut_slice(),
            pw_hash.lock().as_slice(),
            salt.lock().as_slice().try_into().unwrap(),
            ops_limit,
            mem_limit,
        )
    }).await??;

    // initialize the secret stream encrypt item
    let mut enc = sodoken::secretstream::State::default();
    let mut header = sodoken::LockedArray::<{ sodoken::secretstream::HEADERBYTES }>::new()?;
    sodoken::secretstream::init_push(&mut enc, header.lock().as_mut_slice().try_into().unwrap(), &secret.lock())?;

    // encrypt the seed
    let mut cipher = sodoken::LockedArray::<49>::new()?;
    sodoken::secretstream::push(
        &mut enc,
        cipher.lock().as_mut_slice(),
        seed.lock().lock().as_slice(),
        None,
        sodoken::secretstream::Tag::Final,
    )?;

    // Return the argon salt, and the secretstream header and cipher.
    Ok((
        salt,
        header,
        cipher,
    ))
}

/// Use the given passphrase, salt, and limits to generate a deterministic
/// secret with argon.
/// Use the secret to decrypt the given secretstream header and cipher into
/// a 32 byte secret seed.
/// Return that seed.
pub(crate) async fn pw_dec<const P: usize>(
    mut passphrase: sodoken::LockedArray<P>,
    mut salt: sodoken::LockedArray<{ sodoken::argon2::ARGON2_ID_SALTBYTES }>,
    mem_limit: u32,
    ops_limit: u32,
    mut header: sodoken::LockedArray<24>,
    cipher: sodoken::LockedArray<49>,
) -> Result<sodoken::LockedArray<32>, OneErr> {
    // pre-hash the passphrase
    let mut pw_hash = sodoken::LockedArray::<64>::new()?;
    sodoken::blake2b::blake2b_hash(pw_hash.lock().as_mut_slice(), passphrase.lock().as_slice(), None)?;

    // generate the argon secret
    let mut secret = sodoken::LockedArray::new()?;
    tokio::task::spawn_blocking(|| {
        sodoken::argon2::blocking_argon2id(
            secret.lock().as_mut_slice(),
            pw_hash.lock().as_slice(),
            salt.lock().as_slice().try_into().unwrap(),
            ops_limit,
            mem_limit,
        )
    })
    .await.map_err(|e| {
        OneErr::new(format!("argon2id blocking failed: {}", e))
    })??;

    // decrypt the seed
    let mut dec = sodoken::secretstream::State::default();
    sodoken::secretstream::init_pull(&mut dec, &header.lock(), &secret.lock())?;
    let cipher = vec![0; 32 + sodoken::secretstream::ABYTES];

    let mut seed = sodoken::LockedArray::new()?;
    let tag = sodoken::secretstream::pull(
        &mut dec,
        seed.lock().as_mut_slice(),
        &cipher,
        None,
    )?;

    if tag != sodoken::secretstream::Tag::Final {
        return Err(OneErr::new("secretstream pull did not return final tag"));
    }

    // return the seed
    Ok(seed)
}
