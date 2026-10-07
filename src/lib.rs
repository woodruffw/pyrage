#![deny(unsafe_code)]

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read, Write};

use age::{
    armor::ArmoredReader, armor::ArmoredWriter, armor::Format, DecryptError as RageDecryptError,
    EncryptError as RageEncryptError, Encryptor, Identity, Recipient,
};
use age_core::format::{FileKey, Stanza};
use pyo3::{
    create_exception,
    exceptions::{PyException, PyTypeError},
    impl_::extract_argument::argument_extraction_error,
    prelude::*,
    py_run,
    types::{PyBool, PyBytes, PyCFunction, PyTuple},
    Borrowed,
};
use pyo3_file::PyFileLikeObject;

mod passphrase;
mod plugin;
mod ssh;
mod tag;
mod tagpq;
mod x25519;

// These exceptions are raised by the `pyrage.[x25519|ssh|plugin|tag|tagpq]` APIs,
// where appropriate.
create_exception!(pyrage, RecipientError, PyException);
create_exception!(pyrage, IdentityError, PyException);

// This is a wrapper trait for age's `Recipient`, providing trait downcasting.
//
// We need this so that we can pass multiple different types of recipients
// into the Python-level `encrypt` API.
//
// `Send` is required so that recipients can be moved across a GIL release.
trait PyrageRecipient: Recipient + Send {
    fn as_recipient(self: Box<Self>) -> Box<dyn Recipient + Send>;
}

// This is a wrapper trait for age's `Identity`, providing trait downcasting.
//
// We need this so that we can pass multiple different types of identities
// into the Python-level `decrypt` API.
//
// `Send` is required so that identities can be moved across a GIL release.
trait PyrageIdentity: Identity + Send {
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
                fn wrap_file_key(&self, file_key: &FileKey) -> Result<(Vec<Stanza>, HashSet<String>), RageEncryptError> {
                    self.0.wrap_file_key(file_key)
                }
            }

            impl PyrageRecipient for $t {
                fn as_recipient(self: Box<Self>) -> Box<dyn Recipient + Send> {
                    self
                }
            }
        )*
    }
}

recipient_traits!(
    ssh::Recipient,
    tag::Recipient,
    tagpq::Recipient,
    x25519::Recipient,
    plugin::RecipientPluginV1
);

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
impl<'py> FromPyObject<'_, 'py> for Box<dyn PyrageRecipient> {
    type Error = PyErr;

    fn extract(ob: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(recipient) = ob.extract::<x25519::Recipient>() {
            Ok(Box::new(recipient) as Box<dyn PyrageRecipient>)
        } else if let Ok(recipient) = ob.extract::<tag::Recipient>() {
            Ok(Box::new(recipient) as Box<dyn PyrageRecipient>)
        } else if let Ok(recipient) = ob.extract::<tagpq::Recipient>() {
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
impl<'py> FromPyObject<'_, 'py> for Box<dyn PyrageIdentity> {
    type Error = PyErr;

    fn extract(ob: Borrowed<'_, 'py, PyAny>) -> PyResult<Self> {
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

// Buffer size for streaming I/O. This matches age's STREAM chunk size, and
// for Python file-likes it bounds how often we have to re-acquire the GIL.
const IO_BUF_SIZE: usize = 64 * 1024;

// Converts an I/O error from a streaming operation into a Python error.
//
// Errors raised by a Python file-like are passed through unchanged, so the
// caller sees their own exception, and OS errors become the matching
// `OSError` (as for opening a file); everything else (age's own stream
// errors, e.g. truncated or corrupt input) is wrapped in the given type.
fn io_error(e: io::Error, wrap: impl FnOnce(String) -> PyErr) -> PyErr {
    if e.raw_os_error().is_some() || e.get_ref().is_some_and(|inner| inner.is::<PyErr>()) {
        PyErr::from(e)
    } else {
        wrap(e.to_string())
    }
}

// Same as `io_error`, for age's error types: their `Io` variants may carry a
// Python exception from a file-like, which we unwrap rather than stringify.
fn encrypt_error(e: RageEncryptError) -> PyErr {
    match e {
        RageEncryptError::Io(e) => io_error(e, EncryptError::new_err),
        e => EncryptError::new_err(e.to_string()),
    }
}

fn decrypt_error(e: RageDecryptError) -> PyErr {
    match e {
        RageDecryptError::Io(e) => io_error(e, DecryptError::new_err),
        e => DecryptError::new_err(e.to_string()),
    }
}

// Builds an `Encryptor` for pyrage's recipient types. Wrapping the file key
// can be slow (plugins run external binaries), so call this without the GIL.
fn recipients_encryptor(recipients: Vec<Box<dyn PyrageRecipient>>) -> PyResult<Encryptor> {
    // This turns each `dyn PyrageRecipient` into a `dyn Recipient`, which
    // is what the underlying `age` API expects.
    let recipients = recipients
        .into_iter()
        .map(|pr| pr.as_recipient())
        .collect::<Vec<_>>();

    Encryptor::with_recipients(recipients.iter().map(|r| r.as_ref() as _)).map_err(encrypt_error)
}

// Encrypts everything from `reader` into `writer`. This is pure Rust and
// does not touch the GIL, so callers run it inside `Python::detach`.
pub(crate) fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    writer: W,
    encryptor: Encryptor,
    armored: bool,
) -> PyResult<W> {
    let format = match armored {
        true => Format::AsciiArmor,
        false => Format::Binary,
    };
    let armored_writer = ArmoredWriter::wrap_output(writer, format)
        .map_err(|e| io_error(e, EncryptError::new_err))?;
    let mut writer = encryptor
        .wrap_output(armored_writer)
        .map_err(|e| io_error(e, EncryptError::new_err))?;

    io::copy(&mut reader, &mut writer).map_err(|e| io_error(e, EncryptError::new_err))?;

    let writer = writer
        .finish()
        .map_err(|e| io_error(e, EncryptError::new_err))?
        .finish()
        .map_err(|e| io_error(e, EncryptError::new_err))?;

    Ok(writer)
}

fn as_identities(identities: &[Box<dyn PyrageIdentity>]) -> impl Iterator<Item = &dyn Identity> {
    identities.iter().map(|pi| pi.as_ref().as_identity())
}

// Decrypts everything from `reader` into `writer`. Like `encrypt_stream`,
// this is meant to run without the GIL held.
pub(crate) fn decrypt_stream<'a, R: io::BufRead, W: Write>(
    reader: R,
    writer: &mut W,
    identities: impl Iterator<Item = &'a dyn Identity>,
) -> PyResult<()> {
    let decryptor =
        age::Decryptor::new_buffered(ArmoredReader::new(reader)).map_err(decrypt_error)?;

    let mut reader = decryptor.decrypt(identities).map_err(decrypt_error)?;

    io::copy(&mut reader, writer).map_err(|e| io_error(e, DecryptError::new_err))?;

    Ok(())
}

#[pyfunction]
#[pyo3(signature = (plaintext, recipients, armored=false))]
fn encrypt<'p>(
    py: Python<'p>,
    plaintext: &[u8],
    recipients: Vec<Box<dyn PyrageRecipient>>,
    armored: bool,
) -> PyResult<Bound<'p, PyBytes>> {
    let encrypted = py.detach(|| {
        encrypt_stream(
            plaintext,
            vec![],
            recipients_encryptor(recipients)?,
            armored,
        )
    })?;

    // TODO: Avoid this copy. Maybe PyBytes::new_with?
    Ok(PyBytes::new(py, &encrypted))
}

#[pyfunction]
#[pyo3(signature = (infile, outfile, recipients, armored=false))]
fn encrypt_file(
    py: Python<'_>,
    infile: String,
    outfile: String,
    recipients: Vec<Box<dyn PyrageRecipient>>,
    armored: bool,
) -> PyResult<()> {
    py.detach(|| {
        let reader = File::open(infile)?;
        let writer = File::create(outfile)?;

        let reader = io::BufReader::with_capacity(IO_BUF_SIZE, reader);
        let writer = io::BufWriter::with_capacity(IO_BUF_SIZE, writer);

        encrypt_stream(reader, writer, recipients_encryptor(recipients)?, armored)?
            .flush()
            .map_err(|e| io_error(e, EncryptError::new_err))
    })
}

create_exception!(pyrage, DecryptError, PyException);

#[pyfunction]
fn decrypt<'p>(
    py: Python<'p>,
    ciphertext: &[u8],
    identities: Vec<Box<dyn PyrageIdentity>>,
) -> PyResult<Bound<'p, PyBytes>> {
    let decrypted = py.detach(move || {
        let mut decrypted = vec![];
        decrypt_stream(ciphertext, &mut decrypted, as_identities(&identities))?;
        PyResult::Ok(decrypted)
    })?;

    // TODO: Avoid this copy. Maybe PyBytes::new_with?
    Ok(PyBytes::new(py, &decrypted))
}

#[pyfunction]
fn decrypt_file(
    py: Python<'_>,
    infile: String,
    outfile: String,
    identities: Vec<Box<dyn PyrageIdentity>>,
) -> PyResult<()> {
    py.detach(move || {
        let reader = File::open(infile)?;
        let writer = File::create(outfile)?;

        let reader = io::BufReader::with_capacity(IO_BUF_SIZE, reader);
        let mut writer = io::BufWriter::with_capacity(IO_BUF_SIZE, writer);

        decrypt_stream(reader, &mut writer, as_identities(&identities))?;
        writer
            .flush()
            .map_err(|e| io_error(e, DecryptError::new_err))
    })
}

fn from_pyobject(file: Py<PyAny>, read_only: bool) -> PyResult<PyFileLikeObject> {
    // is a file-like
    PyFileLikeObject::with_requirements(file, read_only, !read_only, false, false)
}

// NOTE: `PyFileLikeObject` re-acquires the GIL for each read/write, so the
// crypto work in the `_io` variants still runs with the GIL released.
#[pyfunction]
#[pyo3(signature = (reader, writer, recipients, armored=false))]
fn encrypt_io(
    py: Python<'_>,
    reader: Py<PyAny>,
    writer: Py<PyAny>,
    recipients: Vec<Box<dyn PyrageRecipient>>,
    armored: bool,
) -> PyResult<()> {
    // The file-likes are created (and dropped) while holding the GIL; only
    // borrows of them cross into the detached section.
    let mut reader = io::BufReader::with_capacity(IO_BUF_SIZE, from_pyobject(reader, true)?);
    let mut writer = io::BufWriter::with_capacity(IO_BUF_SIZE, from_pyobject(writer, false)?);

    py.detach(|| {
        encrypt_stream(
            &mut reader,
            &mut writer,
            recipients_encryptor(recipients)?,
            armored,
        )?
        .flush()
        .map_err(|e| io_error(e, EncryptError::new_err))
    })
}

#[pyfunction]
fn decrypt_io(
    py: Python<'_>,
    reader: Py<PyAny>,
    writer: Py<PyAny>,
    identities: Vec<Box<dyn PyrageIdentity>>,
) -> PyResult<()> {
    // See `encrypt_io`: the file-likes never get dropped without the GIL.
    let mut reader = io::BufReader::with_capacity(IO_BUF_SIZE, from_pyobject(reader, true)?);
    let mut writer = io::BufWriter::with_capacity(IO_BUF_SIZE, from_pyobject(writer, false)?);

    py.detach(|| {
        // Move the identities in (they're only `Send`); the file-likes stay
        // borrowed so they are dropped with the GIL held.
        let identities = identities;
        decrypt_stream(&mut reader, &mut writer, as_identities(&identities))?;
        writer
            .flush()
            .map_err(|e| io_error(e, DecryptError::new_err))
    })
}

// Checks that `arg` converts to `T`, failing with the same error pyo3 raises
// when extracting a typed argument, so `*_async` type errors are
// indistinguishable from the sync API's.
//
// `argument_extraction_error` lives in pyo3's `impl_` module, which pyo3
// may change without a semver bump; a pyo3 upgrade that breaks it fails to
// compile, and `test_type_errors_match_sync` catches any drift in behavior.
fn validate_arg<'a, 'py, T>(arg: &'a Bound<'py, PyAny>, name: &str) -> PyResult<()>
where
    T: FromPyObject<'a, 'py>,
{
    arg.extract::<T>()
        .map(drop)
        .map_err(|e| argument_extraction_error(arg.py(), name, e.into()))
}

// Like `validate_arg` for a sequence argument, but also returns a tuple
// snapshot of it to hand to the executor: otherwise the caller could mutate
// the (validated) list before the worker gets to it.
fn validate_seq<'py, T>(arg: &Bound<'py, PyAny>, name: &str) -> PyResult<Bound<'py, PyAny>>
where
    for<'a> T: FromPyObject<'a, 'py>,
{
    validate_arg::<Vec<T>>(arg, name)?;
    let items = arg.extract::<Vec<Bound<'py, PyAny>>>()?;
    Ok(PyTuple::new(arg.py(), items)?.into_any())
}

// Schedules a synchronous pyrage function on the running event loop's
// executor (its default one unless `executor` is given) and returns the
// resulting `asyncio.Future`.
//
// Since the synchronous APIs release the GIL, this gives real concurrency
// with other Python threads and with the event loop itself.
//
// The `*_async` functions below take their arguments as `PyAny` (they have
// to hand Python objects to the executor), so each one validates them up
// front: type errors surface at the call site, like the sync API, rather
// than when the future is awaited.
fn run_in_executor<'p>(
    py: Python<'p>,
    func: Bound<'p, PyCFunction>,
    executor: Option<Bound<'p, PyAny>>,
    args: Vec<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    // The executor must run work on threads of this interpreter: neither the
    // function nor the recipients/identities can be pickled for a process
    // pool, and pyo3 modules can't be loaded in subinterpreters. Reject those
    // here rather than with an obscure error on `await`.
    if let Some(executor) = &executor {
        let futures = py.import("concurrent.futures")?;
        for name in ["ProcessPoolExecutor", "InterpreterPoolExecutor"] {
            // `InterpreterPoolExecutor` is new in Python 3.14.
            if let Some(cls) = futures.getattr_opt(name)? {
                if executor.is_instance(&cls)? {
                    return Err(PyTypeError::new_err(format!(
                        "{name} is not supported; executor must be thread-based"
                    )));
                }
            }
        }
    }

    let event_loop = py.import("asyncio")?.call_method0("get_running_loop")?;

    // Like `asyncio.to_thread`, run in a copy of the caller's context so
    // that context variables (e.g. read by plugin callbacks) carry over.
    let context = py.import("contextvars")?.call_method0("copy_context")?;

    let executor = executor.unwrap_or_else(|| py.None().into_bound(py));
    let mut call_args = vec![executor, context.getattr("run")?, func.into_any()];
    call_args.extend(args);

    event_loop.call_method1("run_in_executor", PyTuple::new(py, call_args)?)
}

#[pyfunction]
#[pyo3(signature = (plaintext, recipients, armored=false, *, executor=None))]
fn encrypt_async<'p>(
    py: Python<'p>,
    plaintext: Bound<'p, PyAny>,
    recipients: Bound<'p, PyAny>,
    armored: bool,
    executor: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    validate_arg::<&[u8]>(&plaintext, "plaintext")?;
    let recipients = validate_seq::<Box<dyn PyrageRecipient>>(&recipients, "recipients")?;

    let armored = PyBool::new(py, armored).to_owned().into_any();
    run_in_executor(
        py,
        wrap_pyfunction!(encrypt, py)?,
        executor,
        vec![plaintext, recipients, armored],
    )
}

#[pyfunction]
#[pyo3(signature = (infile, outfile, recipients, armored=false, *, executor=None))]
fn encrypt_file_async<'p>(
    py: Python<'p>,
    infile: Bound<'p, PyAny>,
    outfile: Bound<'p, PyAny>,
    recipients: Bound<'p, PyAny>,
    armored: bool,
    executor: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    validate_arg::<String>(&infile, "infile")?;
    validate_arg::<String>(&outfile, "outfile")?;
    let recipients = validate_seq::<Box<dyn PyrageRecipient>>(&recipients, "recipients")?;

    let armored = PyBool::new(py, armored).to_owned().into_any();
    run_in_executor(
        py,
        wrap_pyfunction!(encrypt_file, py)?,
        executor,
        vec![infile, outfile, recipients, armored],
    )
}

#[pyfunction]
#[pyo3(signature = (reader, writer, recipients, armored=false, *, executor=None))]
fn encrypt_io_async<'p>(
    py: Python<'p>,
    reader: Bound<'p, PyAny>,
    writer: Bound<'p, PyAny>,
    recipients: Bound<'p, PyAny>,
    armored: bool,
    executor: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let recipients = validate_seq::<Box<dyn PyrageRecipient>>(&recipients, "recipients")?;
    from_pyobject(reader.clone().unbind(), true)?;
    from_pyobject(writer.clone().unbind(), false)?;

    let armored = PyBool::new(py, armored).to_owned().into_any();
    run_in_executor(
        py,
        wrap_pyfunction!(encrypt_io, py)?,
        executor,
        vec![reader, writer, recipients, armored],
    )
}

#[pyfunction]
#[pyo3(signature = (ciphertext, identities, *, executor=None))]
fn decrypt_async<'p>(
    py: Python<'p>,
    ciphertext: Bound<'p, PyAny>,
    identities: Bound<'p, PyAny>,
    executor: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    validate_arg::<&[u8]>(&ciphertext, "ciphertext")?;
    let identities = validate_seq::<Box<dyn PyrageIdentity>>(&identities, "identities")?;

    run_in_executor(
        py,
        wrap_pyfunction!(decrypt, py)?,
        executor,
        vec![ciphertext, identities],
    )
}

#[pyfunction]
#[pyo3(signature = (infile, outfile, identities, *, executor=None))]
fn decrypt_file_async<'p>(
    py: Python<'p>,
    infile: Bound<'p, PyAny>,
    outfile: Bound<'p, PyAny>,
    identities: Bound<'p, PyAny>,
    executor: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    validate_arg::<String>(&infile, "infile")?;
    validate_arg::<String>(&outfile, "outfile")?;
    let identities = validate_seq::<Box<dyn PyrageIdentity>>(&identities, "identities")?;

    run_in_executor(
        py,
        wrap_pyfunction!(decrypt_file, py)?,
        executor,
        vec![infile, outfile, identities],
    )
}

#[pyfunction]
#[pyo3(signature = (reader, writer, identities, *, executor=None))]
fn decrypt_io_async<'p>(
    py: Python<'p>,
    reader: Bound<'p, PyAny>,
    writer: Bound<'p, PyAny>,
    identities: Bound<'p, PyAny>,
    executor: Option<Bound<'p, PyAny>>,
) -> PyResult<Bound<'p, PyAny>> {
    let identities = validate_seq::<Box<dyn PyrageIdentity>>(&identities, "identities")?;
    from_pyobject(reader.clone().unbind(), true)?;
    from_pyobject(writer.clone().unbind(), false)?;

    run_in_executor(
        py,
        wrap_pyfunction!(decrypt_io, py)?,
        executor,
        vec![reader, writer, identities],
    )
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

    let tag = tag::module(py)?;
    py_run!(py, tag, "import sys; sys.modules['pyrage.tag'] = tag");
    m.add_submodule(&tag)?;

    let tagpq = tagpq::module(py)?;
    py_run!(py, tagpq, "import sys; sys.modules['pyrage.tagpq'] = tagpq");
    m.add_submodule(&tagpq)?;

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

    m.add("IdentityError", py.get_type::<IdentityError>())?;
    m.add("RecipientError", py.get_type::<RecipientError>())?;

    m.add("EncryptError", py.get_type::<EncryptError>())?;
    m.add_wrapped(wrap_pyfunction!(encrypt))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_file))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_io))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_async))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_file_async))?;
    m.add_wrapped(wrap_pyfunction!(encrypt_io_async))?;
    m.add("DecryptError", py.get_type::<DecryptError>())?;
    m.add_wrapped(wrap_pyfunction!(decrypt))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_file))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_io))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_async))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_file_async))?;
    m.add_wrapped(wrap_pyfunction!(decrypt_io_async))?;

    Ok(())
}
