import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cybereason",
    version="1.0",
    author="Vectra AI, Inc",
    author_email="mp@vectra.ai",
    description="Cybereason API to Cognito Detect API integration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/vectranetworks/cybereason",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
    python_requires='>=3.5',
)