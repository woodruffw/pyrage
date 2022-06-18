use pyo3::prelude::*;

mod x25519;

#[pymodule]
fn pyrage(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_submodule(x25519::x25519(py)?)
}
