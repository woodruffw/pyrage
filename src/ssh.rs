use std::str::FromStr;

use pyo3::{exceptions::PyValueError, prelude::*, types::PyType};

#[pyclass(module = "pyrage.ssh")]
#[derive(Clone)]
pub(crate) struct Recipient(pub(crate) age::ssh::Recipient);

#[pymethods]
impl Recipient {
    #[classmethod]
    fn from_str(_cls: &PyType, v: &str) -> PyResult<Self> {
        let recipient = age::ssh::Recipient::from_str(v)
            .map_err(|e| PyValueError::new_err(format!("invalid public key: {:?}", e)))?;

        Ok(Self(recipient))
    }
}

#[pyclass(module = "pyrage.ssh")]
#[derive(Clone)]
pub(crate) struct Identity(pub(crate) age::ssh::Identity);

#[pymethods]
impl Identity {
    #[classmethod]
    fn from_buffer(_cls: &PyType, buf: &[u8]) -> PyResult<Self> {
        let identity = age::ssh::Identity::from_buffer(buf, None)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;

        match identity {
            age::ssh::Identity::Unencrypted(_) => Ok(Self(identity)),
            age::ssh::Identity::Encrypted(_) => {
                Err(PyValueError::new_err("ssh key must be decrypted first"))
            }
            age::ssh::Identity::Unsupported(uk) => {
                // Unsupported doesn't have a Display impl, only a hardcoded `display` function.
                Err(PyValueError::new_err(format!("unsupported key: {:?}", uk)))
            }
        }
    }
}

pub(crate) fn module(py: Python) -> PyResult<&PyModule> {
    let module = PyModule::new(py, "ssh")?;

    module.add_class::<Recipient>()?;
    module.add_class::<Identity>()?;

    Ok(module)
}
