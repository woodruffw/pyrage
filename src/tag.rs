use std::str::FromStr;

use pyo3::{prelude::*, types::PyType};

use crate::RecipientError;

#[pyclass(module = "pyrage.tag")]
#[derive(Clone)]
pub(crate) struct Recipient(pub(crate) age::tag::Recipient);

#[pymethods]
impl Recipient {
    #[classmethod]
    fn from_str(_cls: &Bound<'_, PyType>, v: &str) -> PyResult<Self> {
        age::tag::Recipient::from_str(v)
            .map(Self)
            .map_err(RecipientError::new_err)
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }
}

pub(crate) fn module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    let module = PyModule::new(py, "tag")?;

    module.add_class::<Recipient>()?;

    Ok(module)
}
