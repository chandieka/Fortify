import pathlib

from setuptools import find_packages, setup

here = pathlib.Path(__file__).parent.resolve()

install_requires = (here / 'requirements.txt').read_text(encoding='utf-8').splitlines()

setup(
    name="fortify",
    version="1.2.3",
    install_requires=install_requires,
    packages=find_packages(where='lib'),
    package_dir={
        '' : "lib"
    },
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'fortify-benchmark=fortify.cli.benchmark:main'
        ]
    },
)