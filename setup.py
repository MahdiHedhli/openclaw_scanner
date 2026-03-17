from pathlib import Path

from setuptools import find_packages, setup


setup(
    name="openclaw-scanner",
    version="0.1.0",
    description="Fingerprint OpenClaw gateways from direct probes or Shodan exports.",
    long_description=Path("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    packages=find_packages(include=["openclaw_scanner", "openclaw_scanner.*"]),
    package_data={"openclaw_scanner": ["data/*.json"]},
    include_package_data=True,
    entry_points={
        "console_scripts": ["openclaw-scanner=openclaw_scanner.cli:main"],
    },
)
