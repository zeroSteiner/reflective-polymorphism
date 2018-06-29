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

.. c:function:: BOOL DOSHeaderIsDLL(PDOS_HEADER pDosHeader)

    Check the FileHeader Characteristics field to determine whether the PE image
    is marked as both executable (IMAGE_FILE_EXECUTABLE_IMAGE) and a DLL
    (IMAGE_FILE_DLL).

    :param PDOS_HEADER pDosHeader: A pointer to the DOS header to analyze.
    :return: ``TRUE`` if *pDosHeader* is a DLL.
    :rtype: BOOL

.. c:function:: BOOL DOSHeaderIsEXE(PDOS_HEADER pDosHeader)

    Check the FileHeader Characteristics field to determine whether the PE image
    is marked as both executable (IMAGE_FILE_EXECUTABLE_IMAGE) and not a DLL
    (IMAGE_FILE_DLL).

    :param PDOS_HEADER pDosHeader: A pointer to the DOS header to analyze.
    :return: ``TRUE`` if *pDosHeader* is an EXE.
    :rtype: BOOL

.. c:function:: BOOL ReflectiveTransformerToDLL(PDOS_HEADER pDosHeader, DWORD dwAddressOfEntryPoint)

    Transform the PE image pDosHeader into a DLL. This updates the FileHeader
    Characteristics field as necessary, updates the OptionalHeader ImageBase to
    the default value for DLL files and sets a new entry point.

    :param PDOS_HEADER pDosHeader: A pointer to the DOS header transform.
    :param DWORD dwAddressOfEntryPoint: The RVA of the new entry point for the PE image.
    :return: ``TRUE`` on success.
    :rtype: BOOL

.. c:function:: BOOL ReflectiveTransformerToEXE(PDOS_HEADER pDosHeader, DWORD dwAddressOfEntryPoint)

    Transform the PE image pDosHeader into an EXE. This updates the FileHeader
    Characteristics field as necessary, updates the OptionalHeader ImageBase to
    the default value for EXE files and sets a new entry point.

    :param PDOS_HEADER pDosHeader: A pointer to the DOS header transform.
    :param DWORD dwAddressOfEntryPoint: The RVA of the new entry point for the PE image.
    :return: ``TRUE`` on success.
    :rtype: BOOL

.. c:function:: DWORD RVAFromExportName(PDOS_HEADER pDosHeader, LPCSTR lpProcName)

    Get the relative virtual address (RVA) of an exported function by it's name
    from an unloaded PE image. The return value can then be used as the
    *dwAddressOfEntryPoint* argument to the ``ReflectiveTransformerTo*`` set of
    functions.

    :param PDOS_HEADER pDosHeader: A pointer to the DOS header of the PE image to resolve the export from.
    :param LPCSTR lpProcName: A pointer to the name of the exported function to resolve the RVA for.
    :return: The function returns a non-zero value on success.
    :rtype: DWORD
