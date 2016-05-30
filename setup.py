from setuptools import find_packages, setup

setup(
    name = "peepdf",
    version = "0.3-r235",
    author = "Jose Miguel Esparza",
    license = "GNU GPLv3",
    url = "http://eternal-todo.com",
    install_requires = [ "jsbeautifier==1.6.2", "colorama", "pythonaes==1.0" ],
    dependency_links = ["git+https://github.com/serprex/pythonaes.git@setup#egg=pythonaes-1.0"],
    packages = find_packages(),
)
