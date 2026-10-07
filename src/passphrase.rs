use std::iter;

use age::{scrypt, Encryptor};
use pyo3::{prelude::*, types::PyBytes};

use crate::{decrypt_stream, encrypt_stream};

// scrypt is deliberately slow (on the order of a second), so both directions
// release the GIL for the whole operation, key derivation included.

#[pyfunction]
#[pyo3(signature = (plaintext, passphrase, armored=false))]
fn encrypt<'p>(
    py: Python<'p>,
    plaintext: &[u8],
    passphrase: &str,
    armored: bool,
) -> PyResult<Bound<'p, PyBytes>> {
    let encrypted = py.detach(|| {
        let encryptor = Encryptor::with_user_passphrase(passphrase.into());
        encrypt_stream(plaintext, vec![], encryptor, armored)
    })?;

    Ok(PyBytes::new(py, &encrypted))
}

// `max_work_factor` caps the scrypt work factor (`log2(N)`) `decrypt`
// accepts. By default age derives the cap from a timing benchmark (four
// above what takes ~1s here) and rejects anything more expensive; that
// benchmark can come out low on a busy machine, so callers may pass a fixed
// cap instead.
#[pyfunction]
#[pyo3(signature = (ciphertext, passphrase, max_work_factor=None))]
fn decrypt<'p>(
    py: Python<'p>,
    ciphertext: &[u8],
    passphrase: &str,
    max_work_factor: Option<u8>,
) -> PyResult<Bound<'p, PyBytes>> {
    let decrypted = py.detach(|| {
        let mut identity = scrypt::Identity::new(passphrase.into());
        if let Some(max_work_factor) = max_work_factor {
            identity.set_max_work_factor(max_work_factor);
        }
        let mut decrypted = vec![];
        decrypt_stream(ciphertext, &mut decrypted, iter::once(&identity as _))?;
        PyResult::Ok(decrypted)
    })?;

    Ok(PyBytes::new(py, &decrypted))
}

pub(crate) fn module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new(py, "passphrase")?;

    module.add_wrapped(wrap_pyfunction!(encrypt))?;
    module.add_wrapped(wrap_pyfunction!(decrypt))?;

    Ok(module)
}
