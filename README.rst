This project provides various utilities for the self-modification of PE images
ith the intention that they can be incorporated into external projects.

The documentation is available `online`_.

Overview
--------
The Reflective Polymorphism projects is currently composed of the following two
components each of which are contained within their respective ``.c`` / ``.h``
files and are capabile of operating independently.

**ReflectiveTransformer**
   Functionality to transform PE files between DLL and EXE formats.

**ReflectiveUnloader**
   Functionality to copy a loaded PE image out of memory and reconstruct a byte
   for byte copy of the PE image as it would exist on disk.

License
-------
This project is released under the BSD 3-clause license, for more details see
the `LICENSE`_ file.

.. _online: https://zeroSteiner.github.io/reflective-polymorphism/
.. _LICENSE: https://github.com/zeroSteiner/reflective-unloader/blob/master/LICENSE
