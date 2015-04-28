===
Mai
===

.. image:: https://travis-ci.org/zalando-stups/mai.svg?branch=master
   :target: https://travis-ci.org/zalando-stups/mai
   :alt: Build Status

.. image:: https://coveralls.io/repos/zalando-stups/mai/badge.svg
   :target: https://coveralls.io/r/zalando-stups/mai
   :alt: Code Coverage

.. image:: https://img.shields.io/pypi/dw/stups-mai.svg
   :target: https://pypi.python.org/pypi/stups-mai/
   :alt: PyPI Downloads

.. image:: https://img.shields.io/pypi/v/stups-mai.svg
   :target: https://pypi.python.org/pypi/stups-mai/
   :alt: Latest PyPI version

.. image:: https://img.shields.io/pypi/l/stups-mai.svg
   :target: https://pypi.python.org/pypi/stups-mai/
   :alt: License

AWS SAML login command line utility.

.. code-block:: bash

    $ sudo pip3 install --upgrade stups-mai

Usage
=====

.. code-block:: bash

    $ mai create my-profile
    $ mai # short for "mai login my-profile"

See the `STUPS documentation on Mai`_ for details.

Running Unit Tests
==================

.. code-block:: bash

    $ python3 setup.py test --cov-html=true

.. _STUPS documentation on Mai: http://stups.readthedocs.org/en/latest/components/mai.html

Releasing
=========

.. code-block:: bash

    $ ./release.sh <NEW-VERSION>
