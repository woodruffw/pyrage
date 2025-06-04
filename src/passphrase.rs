use std::{
    io::{Read, Write},
    iter,
};

use age::{
    armor::ArmoredReader, armor::ArmoredWriter, armor::Format, scrypt, Decryptor, Encryptor,
};
use pyo3::{prelude::*, types::PyBytes};

use crate::{DecryptError, EncryptError};

#[pyfunction]
#[pyo3(signature = (plaintext, passphrase, armored=false))]
fn encrypt<'p>(
    py: Python<'p>,
    plaintext: &[u8],
    passphrase: &str,
    armored: bool,
) -> PyResult<Bound<'p, PyBytes>> {
    let encryptor = Encryptor::with_user_passphrase(passphrase.into());
    let mut encrypted = vec![];

    let writer_result = match armored {
        true => encryptor.wrap_output(
            ArmoredWriter::wrap_output(&mut encrypted, Format::AsciiArmor)
                .map_err(|e| EncryptError::new_err(e.to_string()))?,
        ),
        false => encryptor.wrap_output(
            ArmoredWriter::wrap_output(&mut encrypted, Format::Binary)
                .map_err(|e| EncryptError::new_err(e.to_string()))?,
        ),
    };

    let mut writer = writer_result.map_err(|e| EncryptError::new_err(e.to_string()))?;

    writer
        .write_all(plaintext)
        .map_err(|e| EncryptError::new_err(e.to_string()))?;

    writer
        .finish()
        .map_err(|e| EncryptError::new_err(e.to_string()))?
        .finish()
        .map_err(|e| EncryptError::new_err(e.to_string()))?;

    Ok(PyBytes::new(py, &encrypted))
}

#[pyfunction]
fn decrypt<'p>(
    py: Python<'p>,
    ciphertext: &[u8],
    passphrase: &str,
) -> PyResult<Bound<'p, PyBytes>> {
    let decryptor = Decryptor::new_buffered(ArmoredReader::new(ciphertext))
        .map_err(|e| DecryptError::new_err(e.to_string()))?;
    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(iter::once(&scrypt::Identity::new(passphrase.into()) as _))
        .map_err(|e| DecryptError::new_err(e.to_string()))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;

    Ok(PyBytes::new(py, &decrypted))
}

pub(crate) fn module(py: Python) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new(py, "passphrase")?;

    module.add_wrapped(wrap_pyfunction!(encrypt))?;
    module.add_wrapped(wrap_pyfunction!(decrypt))?;

    Ok(module)
}
