from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="crafy-captcha",
    version="1.0.5",
    author="CrafyCAPTCHA",
    author_email="hello@captcha.crafy.net",
    description="Official CrafyCAPTCHA Backend SDK for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/crafycaptcha/crafy-captcha-python",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=[
        "requests>=2.25.1",
        "PyNaCl>=1.4.0",
        "cryptography>=3.4.0"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)