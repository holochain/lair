use super::*;

/// For SeedCipherSecurityQuestions (and the "Locked" struct)
/// we need to be able to translate three answers into a semi-deterministic
/// passphrase. This process involves lower-casing, trimming, and concatenating.
pub(crate) fn process_security_answers<A1, A2, A3>(
    a1: A1,
    a2: A2,
    a3: A3,
) -> SodokenResult<sodoken::BufRead>
where
    A1: Into<sodoken::BufRead> + 'static + Send,
    A2: Into<sodoken::BufRead> + 'static + Send,
    A3: Into<sodoken::BufRead> + 'static + Send,
{
    // first, get read-locks to all our input data
    let a1 = a1.into();
    let a1 = a1.read_lock();
    let a2 = a2.into();
    let a2 = a2.read_lock();
    let a3 = a3.into();
    let a3 = a3.read_lock();

    // careful not to move any bytes out of protected memory
    // convert to utf8 so we can use the rust trim / lcase functions.
    let a1 = std::str::from_utf8(&*a1).map_err(SodokenError::other)?;
    let a2 = std::str::from_utf8(&*a2).map_err(SodokenError::other)?;
    let a3 = std::str::from_utf8(&*a3).map_err(SodokenError::other)?;

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
        sodoken::BufWrite::new_mem_locked(a1.len() + a2.len() + a3.len())?;

    {
        // output buffer write lock
        let mut out = out.write_lock();

        // copy / concatonate the three answers
        out[0..a1.len()].copy_from_slice(a1);
        out[a1.len()..a1.len() + a2.len()].copy_from_slice(a2);
        out[a1.len() + a2.len()..a1.len() + a2.len() + a3.len()]
            .copy_from_slice(a3);

        // we forced utf8 above, so safe to unwrap here
        let out = std::str::from_utf8_mut(&mut *out).unwrap();

        // this needs a mutable buffer, so we have to do this in out memory
        out.make_ascii_lowercase();
    }

    // return the read-only concatonated passphrase
    Ok(out.to_read())
}

/// Use the given passphrase to generate a deterministic secret with argon.
/// Use that secret to secretstream encrypt the given seed.
/// Return the argon salt, and the secretstream header and cipher.
pub(crate) async fn pw_enc(
    seed: sodoken::BufReadSized<32>,
    passphrase: sodoken::BufRead,
    limits: PwHashLimits,
) -> SodokenResult<(
    sodoken::BufReadSized<{ sodoken::argon2id::SALTBYTES }>,
    sodoken::BufReadSized<24>,
    sodoken::BufReadSized<49>,
)> {
    // generate a random salt
    let salt = sodoken::BufWriteSized::new_no_lock();
    sodoken::random::randombytes_buf(salt.clone()).await?;

    // generate a secret using the passphrase with argon
    let opslimit = limits.as_ops_limit();
    let memlimit = limits.as_mem_limit();
    let secret = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::argon2id::hash(
        secret.clone(),
        passphrase,
        salt.clone(),
        opslimit,
        memlimit,
    )
    .await?;

    // initialize the secret stream encrypt item
    use sodoken::secretstream_xchacha20poly1305::*;
    let header = sodoken::BufWriteSized::new_no_lock();
    let mut enc = SecretStreamEncrypt::new(secret, header.clone())?;

    // encrypt the seed
    let cipher = sodoken::BufWriteSized::new_no_lock();
    enc.push_final(seed, <Option<sodoken::BufRead>>::None, cipher.clone())
        .await?;

    // Return the argon salt, and the secretstream header and cipher.
    Ok((
        salt.to_read_sized(),
        header.to_read_sized(),
        cipher.to_read_sized(),
    ))
}

/// Use the given passphrase, salt, and limits to generate a deterministic
/// secret with argon.
/// Use the secret to decrypt the given secretstream header and cipher into
/// a 32 byte secret seed.
/// Return that seed.
pub(crate) async fn pw_dec(
    passphrase: sodoken::BufRead,
    salt: sodoken::BufReadSized<{ sodoken::argon2id::SALTBYTES }>,
    mem_limit: usize,
    ops_limit: u64,
    header: sodoken::BufReadSized<24>,
    cipher: sodoken::BufReadSized<49>,
) -> SodokenResult<sodoken::BufReadSized<32>> {
    // generate the argon secret
    let secret = sodoken::BufWriteSized::new_mem_locked()?;
    sodoken::argon2id::hash(
        secret.clone(),
        passphrase,
        salt,
        ops_limit,
        mem_limit,
    )
    .await?;

    // decrypt the seed
    use sodoken::secretstream_xchacha20poly1305::*;
    let mut dec = SecretStreamDecrypt::new(secret, header)?;
    let seed = sodoken::BufWriteSized::new_mem_locked()?;
    dec.pull(cipher, <Option<sodoken::BufRead>>::None, seed.clone())
        .await?;

    // return the seed
    Ok(seed.to_read_sized())
}
