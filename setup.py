import setuptools

setuptools.setup(
    name="cybereason",
    version="1.0",
    author="Vectra AI, Inc",
    author_email="mp@vectra.ai",
    description="Cybereason API to Cognito Detect API integration",
    url="https://github.com/vectranetworks/cybereason",
    packages=setuptools.find_packages(),
    install_requires=['vectra-api-tools', 'requests'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
    python_requires='>=3.5',
)