#![deny(unsafe_code)]

use std::{
    fs::File,
    io::{Read, Write},
};

use age::{
    DecryptError as RageDecryptError, EncryptError as RageEncryptError, Encryptor, Identity,
    Recipient,
};
use age_core::format::{FileKey, Stanza};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyTypeError},
    prelude::*,
    py_run,
    types::PyBytes,
};
use pyo3_file::PyFileLikeObject;

mod passphrase;
mod plugin;
mod ssh;
mod x25519;

// These exceptions are raised by the `pyrage.ssh` and `pyrage.x25519` APIs,
// where appropriate.
create_exception!(pyrage, RecipientError, PyException);
create_exception!(pyrage, IdentityError, PyException);

// This is a wrapper trait for age's `Recipient`, providing trait downcasting.
//
// We need this so that we can pass multiple different types of recipients
// into the Python-level `encrypt` API.
trait PyrageRecipient: Recipient {
    fn as_recipient(self: Box<Self>) -> Box<dyn Recipient + Send>;
}

// This is a wrapper trait for age's `Identity`, providing trait downcasting.
//
// We need this so that we can pass multiple different types of identities
// into the Python-level `decrypt` API.
trait PyrageIdentity: Identity {
    fn as_identity(&self) -> &dyn Identity;
}

// This macro generates two trait impls for each passed in type:
//
// * An age `Receipient` impl, using the underlying trait impl.
// * A `PyrageRecipient` impl, by consuming the instance and downcasting.
macro_rules! recipient_traits {
    ($($t:ty),+) => {
        $(
            impl Recipient for $t {
                fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, RageEncryptError> {
                    self.0.wrap_file_key(file_key)
                }
            }

            impl PyrageRecipient for $t {
                fn as_recipient(self: Box<Self>) -> Box<dyn Recipient + Send> {
                    self as Box<dyn Recipient + Send>
                }
            }
        )*
    }
}

recipient_traits!(ssh::Recipient, x25519::Recipient, plugin::RecipientPluginV1);

// This macro generates two trait impls for each passed in type:
//
// * An age `Identity` impl, using the underlying trait impl.
// * A `PyrageIdentity` impl, by borrowing the instance and downcasting.
macro_rules! identity_traits {
    ($($t:ty),+) => {
        $(
            impl Identity for $t {
                fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, RageDecryptError>> {
                    self.0.unwrap_stanza(stanza)
                }
            }

            impl PyrageIdentity for $t {
                fn as_identity(&self) -> &dyn Identity {
                    self as &dyn Identity
                }
            }
        )*
    }
}

identity_traits!(ssh::Identity, x25519::Identity, plugin::IdentityPluginV1);

// This is where the magic happens, and why we need to do the trait dance
// above: `FromPyObject` is a third-party trait, so we need to implement it
// for `Box<dyn PyrageRecipient>` instead of `Box<dyn Recipient>`.
//
// The implementation itself is straightforward: we try to turn the
// `PyAny` into each concrete recipient type, which we then perform the trait
// cast on.
impl<'source> FromPyObject<'source> for Box<dyn PyrageRecipient> {
    fn extract_bound(ob: &Bound<'source, PyAny>) -> PyResult<Self> {
        if let Ok(recipient) = ob.extract::<x25519::Recipient>() {
            Ok(Box::new(recipient) as Box<dyn PyrageRecipient>)
        } else if let Ok(recipient) = ob.extract::<ssh::Recipient>() {
            Ok(Box::new(recipient) as Box<dyn PyrageRecipient>)
        } else if let Ok(recipient) = ob.extract::<plugin::RecipientPluginV1>() {
            Ok(Box::new(recipient) as Box<dyn PyrageRecipient>)
        } else {
            Err(PyTypeError::new_err(
                "invalid type (expected a recipient type)",
            ))
        }
    }
}

// Similar to the above: we try to turn the `PyAny` into a concrete identity type,
// which we then perform the trait cast on.
impl<'source> FromPyObject<'source> for Box<dyn PyrageIdentity> {
    fn extract_bound(ob: &Bound<'source, PyAny>) -> PyResult<Self> {
        if let Ok(identity) = ob.extract::<x25519::Identity>() {
            Ok(Box::new(identity) as Box<dyn PyrageIdentity>)
        } else if let Ok(identity) = ob.extract::<ssh::Identity>() {
            Ok(Box::new(identity) as Box<dyn PyrageIdentity>)
        } else if let Ok(identity) = ob.extract::<plugin::IdentityPluginV1>() {
            Ok(Box::new(identity) as Box<dyn PyrageIdentity>)
        } else {
            Err(PyTypeError::new_err(
                "invalid type (expected an identity type)",
            ))
        }
    }
}

create_exception!(pyrage, EncryptError, PyException);

#[pyfunction]
fn encrypt<'p>(
    py: Python<'p>,
    plaintext: &[u8],
    recipients: Vec<Box<dyn PyrageRecipient>>,
) -> PyResult<Bound<'p, PyBytes>> {
    // This turns each `dyn PyrageRecipient` into a `dyn Recipient`, which
    // is what the underlying `age` API expects.
    let recipients = recipients.into_iter().map(|pr| pr.as_recipient()).collect();

    let encryptor = Encryptor::with_recipients(recipients)
        .ok_or_else(|| EncryptError::new_err("expected at least one recipient"))?;
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

    // TODO: Avoid this copy. Maybe PyBytes::new_with?
    Ok(PyBytes::new_bound(py, &encrypted))
}

#[pyfunction]
fn encrypt_file(
    infile: String,
    outfile: String,
    recipients: Vec<Box<dyn PyrageRecipient>>,
) -> PyResult<()> {
    // This turns each `dyn PyrageRecipient` into a `dyn Recipient`, which
    // is what the underlying `age` API expects.
    let recipients = recipients.into_iter().map(|pr| pr.as_recipient()).collect();

    let reader = File::open(infile)?;
    let writer = File::create(outfile)?;

    let mut reader = std::io::BufReader::new(reader);
    let mut writer = std::io::BufWriter::new(writer);

    let encryptor = Encryptor::with_recipients(recipients)
        .ok_or_else(|| EncryptError::new_err("expected at least one recipient"))?;
    let mut writer = encryptor
        .wrap_output(&mut writer)
        .map_err(|e| EncryptError::new_err(e.to_string()))?;

    std::io::copy(&mut reader, &mut writer).map_err(|e| EncryptError::new_err(e.to_string()))?;

    writer
        .finish()
        .map_err(|e| EncryptError::new_err(e.to_string()))?;

    Ok(())
}

create_exception!(pyrage, DecryptError, PyException);

#[pyfunction]
fn decrypt<'p>(
    py: Python<'p>,
    ciphertext: &[u8],
    identities: Vec<Box<dyn PyrageIdentity>>,
) -> PyResult<Bound<'p, PyBytes>> {
    let identities = identities.iter().map(|pi| pi.as_ref().as_identity());

    let decryptor =
        match age::Decryptor::new(ciphertext).map_err(|e| DecryptError::new_err(e.to_string()))? {
            age::Decryptor::Recipients(d) => d,
            age::Decryptor::Passphrase(_) => {
                return Err(DecryptError::new_err(
                    "invalid ciphertext (encrypted with passphrase, not identities)",
                ))
            }
        };

    let mut decrypted = vec![];
    let mut reader = decryptor
        .decrypt(identities)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;
    reader
        .read_to_end(&mut decrypted)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;

    // TODO: Avoid this copy. Maybe PyBytes::new_with?
    Ok(PyBytes::new_bound(py, &decrypted))
}

#[pyfunction]
fn decrypt_file(
    infile: String,
    outfile: String,
    identities: Vec<Box<dyn PyrageIdentity>>,
) -> PyResult<()> {
    let identities = identities.iter().map(|pi| pi.as_ref().as_identity());

    let reader = File::open(infile)?;
    let writer = File::create(outfile)?;

    let reader = std::io::BufReader::new(reader);
    let mut writer = std::io::BufWriter::new(writer);

    let decryptor = match age::Decryptor::new_buffered(reader)
        .map_err(|e| DecryptError::new_err(e.to_string()))?
    {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => {
            return Err(DecryptError::new_err(
                "invalid ciphertext (encrypted with passphrase, not identities)",
            ))
        }
    };

    let mut reader = decryptor
        .decrypt(identities)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;

    std::io::copy(&mut reader, &mut writer)?;

    Ok(())
}

fn from_pyobject(file: PyObject, read_only: bool) -> PyResult<PyFileLikeObject> {
    // is a file-like
    PyFileLikeObject::with_requirements(file, read_only, !read_only, false, false)
}

#[pyfunction]
fn encrypt_io(
    reader: PyObject,
    writer: PyObject,
    recipients: Vec<Box<dyn PyrageRecipient>>,
) -> PyResult<()> {
    // This turns each `dyn PyrageRecipient` into a `dyn Recipient`, which
    // is what the underlying `age` API expects.
    let recipients = recipients.into_iter().map(|pr| pr.as_recipient()).collect();
    let reader = from_pyobject(reader, true)?;
    let writer = from_pyobject(writer, false)?;
    let mut reader = std::io::BufReader::new(reader);
    let mut writer = std::io::BufWriter::new(writer);
    let encryptor = Encryptor::with_recipients(recipients)
        .ok_or_else(|| EncryptError::new_err("expected at least one recipient"))?;
    let mut writer = encryptor
        .wrap_output(&mut writer)
        .map_err(|e| EncryptError::new_err(e.to_string()))?;
    std::io::copy(&mut reader, &mut writer).map_err(|e| EncryptError::new_err(e.to_string()))?;
    writer
        .finish()
        .map_err(|e| EncryptError::new_err(e.to_string()))?;
    Ok(())
}

#[pyfunction]
fn decrypt_io(
    reader: PyObject,
    writer: PyObject,
    identities: Vec<Box<dyn PyrageIdentity>>,
) -> PyResult<()> {
    let identities = identities.iter().map(|pi| pi.as_ref().as_identity());
    let reader = from_pyobject(reader, true)?;
    let writer = from_pyobject(writer, false)?;
    let reader = std::io::BufReader::new(reader);
    let mut writer = std::io::BufWriter::new(writer);
    let decryptor = match age::Decryptor::new_buffered(reader)
        .map_err(|e| DecryptError::new_err(e.to_string()))?
    {
        age::Decryptor::Recipients(d) => d,
        age::Decryptor::Passphrase(_) => {
            return Err(DecryptError::new_err(
                "invalid ciphertext (encrypted with passphrase, not identities)",
            ))
        }
    };
    let mut reader = decryptor
        .decrypt(identities)
        .map_err(|e| DecryptError::new_err(e.to_string()))?;
    std::io::copy(&mut reader, &mut writer)?;
    Ok(())
}

#[pymodule]
fn pyrage(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // HACK(ww): pyO3 modules are not packages, so we need this nasty
    // `py_run!` hack to support `from pyrage import ...` and similar
    // import patterns.
    let x25519 = x25519::module(py)?;
    py_run!(
        py,
        x25519,
        "import sys; sys.modules['pyrage.x25519'] = x25519"
    );
    m.add_submodule(&x25519)?;

    let ssh = ssh::module(py)?;
    py_run!(py, ssh, "import sys; sys.modules['pyrage.ssh'] = ssh");
    m.add_submodule(&ssh)?;

    let passphrase = passphrase::module(py)?;
    py_run!(
        py,
        passphrase,
        "import sys; sys.modules['pyrage.passphrase'] = passphrase"
    );
    m.add_submodule(&passphrase)?;

    let plugin = plugin::module(py)?;
    py_run!(
        py,
        plugin,
        "import sys; sys.modules['pyrage.plugin'] = plugin"
    );
    m.add_submodule(&plugin)?;

    m.add("IdentityError", py.get_type_bound::<IdentityError>())?;
    m.add("RecipientError", py.get_type_bound::<RecipientError>())?;

    m.add("EncryptError", py.get_type_bound::<EncryptError>())?;
    m.add_wrapped(wrap_pyfunction!(encrypt))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_file))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_io))?;
    m.add("DecryptError", py.get_type_bound::<DecryptError>())?;
    m.add_wrapped(wrap_pyfunction!(decrypt))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_file))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_io))?;

    Ok(())
}
