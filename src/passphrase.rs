use std::io::{Read, Write};

use age::{secrecy::Secret, Decryptor, Encryptor};
use pyo3::{prelude::*, types::PyBytes};

use crate::{DecryptError, EncryptError};

#[pyfunction]
fn encrypt<'p>(py: Python<'p>, plaintext: &[u8], passphrase: &str) -> PyResult<Bound<'p, PyBytes>> {
    let encryptor = Encryptor::with_user_passphrase(Secret::new(passphrase.into()));
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| EncryptError::new_err(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| EncryptError::new_err(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::new_err(e.to_string()))?;

    Ok(PyBytes::new_bound(py, &encrypted))
}

#[pyfunction]
fn decrypt<'p>(
    py: Python<'p>,
    ciphertext: &[u8],
    passphrase: &str,
) -> PyResult<Bound<'p, PyBytes>> {
    let decryptor =
        match Decryptor::new(ciphertext).map_err(|e| DecryptError::new_err(e.to_string()))? {
            Decryptor::Passphrase(d) => d,
            _ => {
                return Err(DecryptError::new_err(
                    "invalid ciphertext (not passphrase encrypted)",
                ))
            }
        };
    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(&Secret::new(passphrase.into()), None)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;

    Ok(PyBytes::new_bound(py, &decrypted))
}

pub(crate) fn module(py: Python) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new_bound(py, "passphrase")?;

    module.add_wrapped(wrap_pyfunction!(encrypt))?;
    module.add_wrapped(wrap_pyfunction!(decrypt))?;

    Ok(module)
}
