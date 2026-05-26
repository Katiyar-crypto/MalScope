"""
MalScope setup script.
"""

from pathlib import Path
from setuptools import setup, find_packages


ROOT = Path(__file__).parent


def read_requirements():
    req_file = ROOT / "requirements.txt"
    if not req_file.exists():
        return []
    requirements = []
    for line in req_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("("):
            requirements.append(line)
    return requirements


setup(
    name="malscope",
    version="2.1.0",
    description="AI-powered universal malware reverse engineering framework",
    author="MalScope Project",
    packages=find_packages(),
    py_modules=["main"],
    include_package_data=True,
    package_data={"gui": ["assets/*.svg"]},
    python_requires=">=3.8",
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "malscope=main:main",
        ],
    },
)
