.. _Reflective Polymorphism:

Reflective Polymorphism
=======================

The ``ReflectivePolymorphism.c`` and ``ReflectivePolymorphism.h`` contain common
functionality for use by other components in the project. This reduces the
amount of code duplication but also requires users of other components to
include these sources files.

API Reference
-------------

.. c:function:: DWORD ImageSizeFromHeaders(PDOS_HEADER pDosHeader)

    Calculate the size of of a PE image from the specified DOS headers.

    :param PDOS_HEADER pDosHeader: The headers to use for the calculation.
    :return: The size of the PE image.
    :rtype: DWORD

.. c:function:: BOOL RebaseImage(PDOS_HEADER pDosHeader, ULONG_PTR uiBaseFrom, ULONG_PTR uiBaseTo)

    Rebase the specified PE image by processing the relocation data as
    necessary.

    :param PDOS_HEADER pDosHeader: Pointer to the DOS header of the blob to patch.
    :param ULONG_PTR uiBaseFrom: The address to rebase the image from.
    :param ULONG_PTR uiBaseTo: The address to rebase the image to.
    :return: The function returns ``TRUE`` on success.
    :rtype: BOOL

.. c:function:: BOOL ShadowSectionCopy(PDOS_HEADER pDosHeader, BOOL bCopyTo)

    Copy data to or from the shadow section. Copying data from the shadow
    section effectively restores content from the backup. Copying data to the
    shadow section effectively updates backup content.

    :param PDOS_HEADER pDosHeader: Pointer to the DOS header of the blob to patch.
    :param BOOL bCopyTo: Whether to copy to or from the shadow section.
    :return: The function returns ``TRUE`` on success.
    :rtype: BOOL

.. c:function:: PIMAGE_SECTION_HEADER SectionHeaderFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress)

    Retrieve the section header for the specified Relative Virtual Address
    (RVA).

    :param PDOS_HEADER pDosHeader: A pointer to the associated DOS header.
    :param ULONG_PTR pVirtualAddress: The RVA of the section header to retrieve.
    :return: A pointer to the section header or ``NULL`` if it could not be found.
    :rtype: PIMAGE_SECTION_HEADER

.. c:function:: PIMAGE_SECTION_HEADER SectionHeaderFromName(PDOS_HEADER pDosHeader, PVOID pName)

    Retrieve the section header for the specified name.

    :param PDOS_HEADER pDosHeader: A pointer to the associated DOS header.
    :param PVOID pName: A pointer to the section header name to retrieve.
    :return: A pointer to the section header or ``NULL`` if it could not be found.
    :rtype: PIMAGE_SECTION_HEADER

.. c:funtion:: ULONG_PTR PAFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress)

    Calculate the Physical Address (VA) from the specified Relative Virtual
    Address (RVA). The Physical Address is the offset within the PE image in
    relation to the DOS header.

    :param PDOS_HEADER pDosHeader: A pointer to the associated DOS header.
    :param ULONG_PTR pVirtualAddress: The RVA to convert to a PA.
    :return: The physical address of the specified relative virtual address or 0 on failure.
    :rtype: ULONG_PTR

.. c:funtion:: ULONG_PTR VAFromRVA(PDOS_HEADER pDosHeader, ULONG_PTR pVirtualAddress)

    Calculate the Virtual Address (VA) from the specified Relative Virtual
    Address (RVA).

    :param PDOS_HEADER pDosHeader: A pointer to the associated DOS header.
    :param ULONG_PTR pVirtualAddress: The RVA to convert to a VA.
    :return: The virtual address of the specified relative virtual address or 0 on failure.
    :rtype: ULONG_PTR
