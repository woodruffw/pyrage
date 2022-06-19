use std::str::FromStr;

use age::secrecy::ExposeSecret;
use pyo3::{exceptions::PyValueError, prelude::*, types::PyType};

#[pyclass]
#[derive(Clone)]
pub(crate) struct Recipient(pub(crate) age::x25519::Recipient);

#[pymethods]
impl Recipient {
    #[classmethod]
    fn from_string(_cls: &PyType, v: &str) -> PyResult<Self> {
        age::x25519::Recipient::from_str(v)
            .map(Self)
            .map_err(PyValueError::new_err)
    }

    fn to_string(&self) -> String {
        self.0.to_string()
    }
}

#[pyclass]
#[derive(Clone)]
pub(crate) struct Identity(pub(crate) age::x25519::Identity);

#[pymethods]
impl Identity {
    #[classmethod]
    fn generate(_cls: &PyType) -> Self {
        Self(age::x25519::Identity::generate())
    }

    fn to_string(&self) -> String {
        self.0.to_string().expose_secret().into()
    }

    fn to_public(&self) -> Recipient {
        Recipient(self.0.to_public())
    }
}

pub(crate) fn x25519(py: Python) -> PyResult<&PyModule> {
    let module = PyModule::new(py, "x25519")?;

    module.add_class::<Recipient>()?;
    module.add_class::<Identity>()?;

    Ok(&module)
}
