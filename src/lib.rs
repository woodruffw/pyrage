use std::io::Write;

use age::{Encryptor, Recipient};
use pyo3::{exceptions::PyValueError, prelude::*};

mod x25519;

trait PyrageRecipient: Recipient {
    fn as_recipient(&self) -> Box<dyn Recipient>;
}

impl<'source> FromPyObject<'source> for Box<dyn PyrageRecipient> {
    fn extract(_ob: &'source PyAny) -> PyResult<Self> {
        unimplemented!()
    }
}

#[pyfunction]
fn encrypt(plaintext: &[u8], recipients: Vec<Box<dyn PyrageRecipient>>) -> PyResult<Vec<u8>> {
    // Trait downcasting hell.
    let recipients = recipients
        .into_iter()
        .map(|r| PyrageRecipient::as_recipient(r.as_ref()))
        .collect();

    // TODO: More specific exceptions here, rather than ValueError for everything.
    let encryptor = Encryptor::with_recipients(recipients);
    let mut encrypted = vec![];
    let mut writer = encryptor
        .wrap_output(&mut encrypted)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    writer
        .write_all(plaintext)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| PyValueError::new_err(e.to_string()))?;

    Ok(encrypted)
}

#[pymodule]
fn pyrage(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_submodule(x25519::x25519(py)?)?;

    m.add_wrapped(wrap_pyfunction!(encrypt))?;

    Ok(())
}
