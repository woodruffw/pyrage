use std::str::FromStr;
use std::sync::Arc;

use pyo3::{prelude::*, types::PyType};

use crate::{DecryptError, EncryptError, IdentityError, RecipientError};

/// Hack, because the orphan rule would prevent us from deriving a
/// foreign trait on a foreign object. Instead, define a newtype.
///
/// Inner type is PyAny, because we do duck-typing at runtime, and
/// declaring a protocol in the type stubs.
#[derive(Clone)]
pub(crate) struct PyCallbacks(Py<PyAny>);

impl PyCallbacks {
    fn new(inner: Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self(inner.unbind()))
    }
}

// Since we have no way to pass errors from these callbacks, we might
// as well panic.
//
// These callbacks don't look like they're supposed to fail anyway.
impl age::Callbacks for PyCallbacks {
    fn display_message(&self, message: &str) {
        Python::with_gil(|py| {
            self.0
                .call_method1(py, pyo3::intern!(py, "display_message"), (message,))
                .expect("`display_message` callback error")
        });
    }
    fn confirm(&self, message: &str, yes_string: &str, no_string: Option<&str>) -> Option<bool> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    pyo3::intern!(py, "confirm"),
                    (message, yes_string, no_string),
                )
                .expect("`confirm` callback error")
                .extract::<Option<bool>>(py)
        })
        .expect("type error in `confirm` callback")
    }
    fn request_public_string(&self, description: &str) -> Option<String> {
        Python::with_gil(|py| {
            self.0
                .call_method1(
                    py,
                    pyo3::intern!(py, "request_public_string"),
                    (description,),
                )
                .expect("`request_public_string` callback error")
                .extract::<Option<String>>(py)
        })
        .expect("type error in `request_public_string` callback")
    }
    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretString> {
        Python::with_gil(|py| {
            self.0
                .call_method1(py, pyo3::intern!(py, "request_passphrase"), (description,))
                .expect("`request_passphrase` callback error")
                .extract::<Option<String>>(py)
        })
        .expect("type error in `request_passphrase` callback")
        .map(age::secrecy::SecretString::from)
    }
}

#[pyclass(module = "pyrage.plugin")]
#[derive(Clone)]
pub(crate) struct Recipient(pub(crate) age::plugin::Recipient);

#[pymethods]
impl Recipient {
    #[classmethod]
    fn from_str(_cls: &Bound<'_, PyType>, v: &str) -> PyResult<Self> {
        age::plugin::Recipient::from_str(v)
            .map(Self)
            .map_err(RecipientError::new_err)
    }

    fn plugin(&self) -> String {
        self.0.plugin().to_owned()
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }
}

#[pyclass(module = "pyrage.plugin")]
#[derive(Clone)]
pub(crate) struct Identity(pub(crate) age::plugin::Identity);

#[pymethods]
impl Identity {
    #[classmethod]
    fn from_str(_cls: &Bound<'_, PyType>, v: &str) -> PyResult<Self> {
        age::plugin::Identity::from_str(v)
            .map(Self)
            .map_err(|e| IdentityError::new_err(e.to_string()))
    }

    #[classmethod]
    fn default_for_plugin(_cls: &Bound<'_, PyType>, plugin: &str) -> Self {
        Self(age::plugin::Identity::default_for_plugin(plugin))
    }

    fn plugin(&self) -> String {
        self.0.plugin().to_owned()
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }
}

#[pyclass(module = "pyrage.plugin")]
#[derive(Clone)]
pub(crate) struct RecipientPluginV1(pub(crate) Arc<age::plugin::RecipientPluginV1<PyCallbacks>>);

#[pymethods]
impl RecipientPluginV1 {
    #[new]
    #[pyo3(
        text_signature = "(plugin_name: str, recipients: typing.Sequence[Recipient], identities: typing.Sequence[Identity], callbacks: Callbacks)"
    )]
    fn new(
        _py: Python<'_>,
        plugin_name: &str,
        recipients: Vec<Recipient>,
        identities: Vec<Identity>,
        callbacks: Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        age::plugin::RecipientPluginV1::new(
            plugin_name,
            recipients
                .into_iter()
                .map(|i| i.0)
                .collect::<Vec<_>>()
                .as_slice(),
            identities
                .into_iter()
                .map(|i| i.0)
                .collect::<Vec<_>>()
                .as_slice(),
            PyCallbacks::new(callbacks)?,
        )
        .map(Arc::new)
        .map(Self)
        .map_err(|err| EncryptError::new_err(err.to_string()))
    }
}

#[pyclass(module = "pyrage.plugin")]
#[derive(Clone)]
pub(crate) struct IdentityPluginV1(pub(crate) Arc<age::plugin::IdentityPluginV1<PyCallbacks>>);

#[pymethods]
impl IdentityPluginV1 {
    #[new]
    #[pyo3(
        text_signature = "(plugin_name: str, identities: typing.Sequence[Identity], callbacks: Callbacks)"
    )]
    fn new(
        _py: Python<'_>,
        plugin_name: &str,
        identities: Vec<Identity>,
        callbacks: Bound<'_, PyAny>,
    ) -> PyResult<Self> {
        age::plugin::IdentityPluginV1::new(
            plugin_name,
            identities
                .into_iter()
                .map(|i| i.0)
                .collect::<Vec<_>>()
                .as_slice(),
            PyCallbacks::new(callbacks)?,
        )
        .map(Arc::new)
        .map(Self)
        .map_err(|err| DecryptError::new_err(err.to_string()))
    }
}

pub(crate) fn module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new_bound(py, "plugin")?;

    module.add_class::<Recipient>()?;
    module.add_class::<Identity>()?;
    module.add_class::<RecipientPluginV1>()?;
    module.add_class::<IdentityPluginV1>()?;

    Ok(module)
}
