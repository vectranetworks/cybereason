import setuptools

with open('requirements.txt') as f:
    required = f.read().splitlines()

setuptools.setup(
    name="cybereason",
    version="1.0",
    author="Vectra AI, Inc",
    author_email="mp@vectra.ai",
    description="Cybereason API to Cognito Detect API integration",
    url="https://github.com/vectranetworks/cybereason",
    package_dir={'': 'lib'},
    packages=setuptools.find_packages(),
    install_requires=required,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security"
    ],
    entry_points={
          'console_scripts': [
            'cybereason = cybereason.cybereason:main',
          ],
    },
    python_requires='>=3.5',
)
