from setuptools import setup, find_packages
from setuptools_rust import RustExtension

setup(
    name="pyspector",
    version="0.1.0-beta",
    rust_extensions=[
        RustExtension("pyspector._rust_core", path="src/pyspector/_rust_core/Cargo.toml")
    ],
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    package_data={
        "pyspector.rules": ["*.toml"],
    },
    include_package_data=True,
    zip_safe=False,
)