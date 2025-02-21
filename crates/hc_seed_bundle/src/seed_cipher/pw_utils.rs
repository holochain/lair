use super::*;

/// For SeedCipherSecurityQuestions (and the "Locked" struct)
/// we need to be able to translate three answers into a semi-deterministic
/// passphrase. This process involves lower-casing, trimming, and concatenating.
pub(crate) fn process_security_answers(
    mut a1: sodoken::LockedArray,
    mut a2: sodoken::LockedArray,
    mut a3: sodoken::LockedArray,
) -> Result<sodoken::LockedArray, OneErr> {
    // first, get read-locks to all our input data
    let a1 = a1.lock();
    let a2 = a2.lock();
    let a3 = a3.lock();

    // careful not to move any bytes out of protected memory
    // convert to utf8 so we can use the rust trim / lcase functions.
    let a1 = std::str::from_utf8(&a1).map_err(OneErr::new)?;
    let a2 = std::str::from_utf8(&a2).map_err(OneErr::new)?;
    let a3 = std::str::from_utf8(&a3).map_err(OneErr::new)?;

    // trim
    let a1 = a1.trim();
    let a2 = a2.trim();
    let a3 = a3.trim();

    // get the utf8 bytes
    let a1 = a1.as_bytes();
    let a2 = a2.as_bytes();
    let a3 = a3.as_bytes();

    // create the output buffer
    let mut out = sodoken::LockedArray::new(a1.len() + a2.len() + a3.len())?;

    {
        // output buffer write lock
        let mut lock = out.lock();

        // copy / concatenate the three answers
        (&mut *lock)[0..a1.len()].copy_from_slice(a1);
        (&mut *lock)[a1.len()..a1.len() + a2.len()].copy_from_slice(a2);
        (&mut *lock)[a1.len() + a2.len()..a1.len() + a2.len() + a3.len()]
            .copy_from_slice(a3);

        // we forced utf8 above, so safe to unwrap here
        let out_str = std::str::from_utf8_mut(&mut lock).unwrap();

        // this needs a mutable buffer, so we have to do this in out memory
        out_str.make_ascii_lowercase();
    }

    // return the read-only concatonated passphrase
    Ok(out)
}

/// Use the given passphrase to generate a deterministic secret with argon.
/// Use that secret to secretstream encrypt the given seed.
/// Return the argon salt, and the secretstream header and cipher.
pub(crate) async fn pw_enc(
    seed: SharedSizedLockedArray<32>,
    passphrase: SharedLockedArray,
    limits: PwHashLimits,
) -> Result<
    (
        [u8; sodoken::argon2::ARGON2_ID_SALTBYTES],
        [u8; 24],
        [u8; 49],
    ),
    OneErr,
> {
    // pre-hash the passphrase
    let mut pw_hash = sodoken::SizedLockedArray::<64>::new()?;
    sodoken::blake2b::blake2b_hash(
        pw_hash.lock().as_mut_slice(),
        &passphrase.lock().lock(),
        None,
    )?;

    // generate a secret using the passphrase with argon
    let ops_limit = limits.as_ops_limit();
    let mem_limit = limits.as_mem_limit();
    let (salt, mut secret) = tokio::task::spawn_blocking({
        move || -> Result<_, OneErr> {
            // generate a random salt
            let mut salt = [0; sodoken::argon2::ARGON2_ID_SALTBYTES];
            sodoken::random::randombytes_buf(&mut salt)?;

            let mut secret = sodoken::SizedLockedArray::new()?;
            sodoken::argon2::blocking_argon2id(
                &mut *secret.lock(),
                &*pw_hash.lock(),
                &salt,
                ops_limit,
                mem_limit,
            )?;

            Ok((salt, secret))
        }
    })
    .await
    .map_err(OneErr::new)??;

    // initialize the secret stream encrypt item
    let mut enc = sodoken::secretstream::State::default();
    let mut header = [0; sodoken::secretstream::HEADERBYTES];
    sodoken::secretstream::init_push(&mut enc, &mut header, &secret.lock())?;

    // encrypt the seed
    let mut cipher = [0; 49];
    sodoken::secretstream::push(
        &mut enc,
        &mut cipher,
        &*seed.lock().lock(),
        None,
        sodoken::secretstream::Tag::Final,
    )?;

    // Return the argon salt, and the secretstream header and cipher.
    Ok((salt, header, cipher))
}

/// Use the given passphrase, salt, and limits to generate a deterministic
/// secret with argon.
/// Use the secret to decrypt the given secretstream header and cipher into
/// a 32 byte secret seed.
/// Return that seed.
pub(crate) async fn pw_dec(
    passphrase: SharedLockedArray,
    salt: U8Array<{ sodoken::argon2::ARGON2_ID_SALTBYTES }>,
    mem_limit: u32,
    ops_limit: u32,
    header: U8Array<24>,
    cipher: U8Array<49>,
) -> Result<sodoken::SizedLockedArray<32>, OneErr> {
    // pre-hash the passphrase
    let mut pw_hash = sodoken::SizedLockedArray::<64>::new()?;
    sodoken::blake2b::blake2b_hash(
        pw_hash.lock().as_mut_slice(),
        &passphrase.lock().lock(),
        None,
    )?;

    // generate the argon secret
    let mut secret = tokio::task::spawn_blocking({
        move || -> Result<_, OneErr> {
            let mut secret = sodoken::SizedLockedArray::new()?;
            sodoken::argon2::blocking_argon2id(
                &mut *secret.lock(),
                &*pw_hash.lock(),
                &salt,
                ops_limit,
                mem_limit,
            )?;

            Ok(secret)
        }
    })
    .await
    .map_err(OneErr::new)??;

    // decrypt the seed
    let mut dec = sodoken::secretstream::State::default();
    sodoken::secretstream::init_pull(&mut dec, &header.0, &secret.lock())?;

    let mut seed = sodoken::SizedLockedArray::new()?;
    let tag = sodoken::secretstream::pull(
        &mut dec,
        &mut *seed.lock(),
        &cipher.0,
        None,
    )?;

    if tag != sodoken::secretstream::Tag::Final {
        return Err(OneErr::new("secretstream pull did not return final tag"));
    }

    // return the seed
    Ok(seed)
}
