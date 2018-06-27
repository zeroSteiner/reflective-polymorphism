.. _Reflective Transformer:

Reflective Transformer
======================

This is code that can be used to transform a PE image between the Dynamic Link
Library (DLL) and Executable (EXE) formats. This can be combined with the
:ref:`Reflective Unloader` to allow code to transform itself into another
format.

Usage
-----

1. The build environment is Visual Studio 2017.
2. Add the following files to the project:

   - ReflectivePolymorphism.c
   - ReflectivePolymorphism.h
   - ReflectiveTransformer.c
   - ReflectiveTransformer.h

3. Set the "Configuration Type" to "Dynamic Library (.dll)".

API Reference
-------------

DOSHeaderIsDLL
^^^^^^^^^^^^^^

.. code-block:: c

    BOOL DOSHeaderIsDLL(
      _In_  PDOS_HEADER pDosHeader
    );

*pDosHeader* [in]
   A pointer to the DOS header to check.

**Return value**
   The function returns ``TRUE`` if pDosHeader appears to be representative of a
   DLL file.

DOSHeaderIsEXE
^^^^^^^^^^^^^^

.. code-block:: c

    BOOL DOSHeaderIsEXE(
      _In_  PDOS_HEADER pDosHeader
    );

*pDosHeader* [in]
   A pointer to the DOS header to check.

**Return value**
   The function returns ``TRUE`` if pDosHeader appears to be representative of
   an EXE file.

RVAFromExportName
^^^^^^^^^^^^^^^^^

.. code-block:: c

    DWORD RVAFromExportName(
      _In_ PDOS_HEADER pDosHeader,
      _In_ LPCSTR      lpProcName
    );

*pDosHeader* [in]
   A pointer to the DOS header of the PE image to resolve the export from.

*lpProcName* [in]
   A pointer to the name of the exported function to resolve the RVA for.

**Return value**
   The function returns a non-zero value on success.

ReflectiveTransformerToDLL
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

    BOOL ReflectiveTransformerToDLL(
      _In_ PDOS_HEADER pDosHeader,
      _In_ DWORD dwAddressOfEntryPoint
    );

*pDosHeader* [in]
   A pointer to the DOS header transform.

*dwAddressOfEntryPoint* [in]
    The RVA of the new entry point for the PE image.

**Return value**
   The function returns ``TRUE`` on success.

ReflectiveTransformerToEXE
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: c

    BOOL ReflectiveTransformerToEXE(
      _In_ PDOS_HEADER pDosHeader,
      _In_ DWORD dwAddressOfEntryPoint
    );

*pDosHeader* [in]
   A pointer to the DOS header transform.

*dwAddressOfEntryPoint* [in]
    The RVA of the new entry point for the PE image.

**Return value**
   The function returns ``TRUE`` on success.
