.. Reflective Polymorphism documentation master file, created by
   sphinx-quickstart on Sun Jun 24 00:56:14 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Reflective Polymorphism's documentation!
===================================================
This project provides various utilities for the self-modification of PE images
ith the intention that they can be incorporated into external projects.

The source code is available on the `GitHub homepage`_.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   reflective_transformer.rst
   reflective_unloader.rst

Proof of Concept
----------------

The proof of concept included in the project is the ``Main.c`` file. This can be
compiled into a ``ReflectivePolymorphism.dll`` which is compatible with
`Reflective DLL Injection`_. The resulting executable can then be injected into
an arbitrary process (assuming premissions and architecture constraints are met)
with the `inject.exe`_ utility. Take note of the hash of the DLL file before
proceeding. See the `releases page`_ for pre-built binaries.

Once the DLL is injected into a process, it will display a message box. This is
used to present the user with an opportunity to delete the original PE file from
disk. After the message box is closed, the following two new files will be
created on the user's desktop.

**ReflectivePolymorphism.dll**
   This is an identical copy of the injected DLL.

**ReflectivePolymorphism.exe**
   This is an EXE version of the original, injected DLL.

The user can then compare the hashes of the two DLL files to determine that they
are identical. At that point the user can delete the DLLs an run the EXE version
which will create the DLL version again at the same path.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. _GitHub homepage: https://github.com/zeroSteiner/reflective-polymorphism
.. _inject.exe: https://github.com/stephenfewer/ReflectiveDLLInjection/tree/master/bin
.. _Reflective DLL Injection: https://github.com/stephenfewer/ReflectiveDLLInjection
.. _releases page: https://github.com/zeroSteiner/reflective-unloader/releases
