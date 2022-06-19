use std::io::Write;

use age::{EncryptError, Encryptor, Recipient};
use age_core::format::{FileKey, Stanza};
use pyo3::{
    exceptions::{PyTypeError, PyValueError},
    prelude::*,
    types::PyBytes,
};

mod x25519;

// This is a wrapper trait for age's `Recipient`, providing trait downcasting.
//
// We need this so that we can pass multiple different types of recipients
// into the Python-level `encrypt` API.
trait PyrageRecipient: Recipient {
    fn as_recipient(self: Box<Self>) -> Box<dyn Recipient>;
}

// This macro generates two trait impls for each passed in type:
//
// * An age `Receipient` impl, using the underlying trait impl.
// * A `PyrageRecipient` impl, by consuming the instance and downcasting.
macro_rules! trait_wrappers {
    ($($t:ty),+) => {
        $(
            impl Recipient for $t {
                fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, EncryptError> {
                    self.0.wrap_file_key(file_key)
                }
            }

            impl PyrageRecipient for $t {
                fn as_recipient(self: Box<Self>) -> Box<dyn Recipient> {
                    self as Box<dyn Recipient>
                }
            }
        )*
    }
}

trait_wrappers!(x25519::Recipient);

// This is where the magic happens, and why we need to do the trait dance
// above: `FromPyObject` is a third-party trait, so we need to implement it
// for `Box<dyn PyrageRecipient>` instead of `Box<dyn Recipient>`.
//
// The implementation itself is straightforward: we try to turn the
// `PyAny` into each concrete recipient type, which we then perform the trait
// cast on.
impl<'source> FromPyObject<'source> for Box<dyn PyrageRecipient> {
    fn extract(ob: &'source PyAny) -> PyResult<Self> {
        if let Ok(recipient) = ob.extract::<x25519::Recipient>() {
            Ok(Box::new(recipient) as Box<dyn PyrageRecipient>)
        } else {
            Err(PyTypeError::new_err(
                "invalid type (expected a recipient type)",
            ))
        }
    }
}

#[pyfunction]
fn encrypt<'p>(
    py: Python<'p>,
    plaintext: &[u8],
    recipients: Vec<Box<dyn PyrageRecipient>>,
) -> PyResult<&'p PyBytes> {
    // This turns each `dyn PyrageRecipient` into a `dyn Recipient`, which
    // is what the underlying `age` API expects.
    let recipients = recipients.into_iter().map(|pr| pr.as_recipient()).collect();

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

    Ok(PyBytes::new(py, &encrypted))
}

#[pymodule]
fn pyrage(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_submodule(x25519::x25519(py)?)?;

    m.add_wrapped(wrap_pyfunction!(encrypt))?;

    Ok(())
}
