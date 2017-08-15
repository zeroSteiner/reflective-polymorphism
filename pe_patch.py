#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  pe_patch.py
#
#  Copyright 2017 Spencer McIntyre <zeroSteiner@gmail.com>
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the  nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import argparse
import copy
import math
import sys

import pefile

__version__ = '1.0'

# .restore section contents:
#   IMAGE_SECTION_HEADER (Name: .data\x00)
#   IMAGE_SECTION_HEADER (Name: \x00)
#   [ .data backup ]

IMAGE_SCN_CNT_INITLIALIZED_DATA = 1 << 6
IMAGE_SCN_MEM_DISCARDABLE = 1 << 25
IMAGE_SCN_MEM_READ = 1 << 30
IMAGE_SCN_MEM_WRITE = 1 << 31
SIZEOF_SECTION_HEADER = 40

def align_up(number, multiple):
	return math.ceil(number / multiple) * multiple

def pe_insert(pe, data, offset):
	pe.__data__ = pe.__data__[:offset] + data + pe.__data__[offset:]
	return pe

def pe_patch(pe):
	writable_sections = []
	for section in pe.sections:
		if section.Name == b'.restore':
			raise RuntimeError('the .restore section is already present in the file')
		if section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE:
			section.Characteristics ^= IMAGE_SCN_MEM_DISCARDABLE
		if section.Characteristics & IMAGE_SCN_MEM_WRITE and section.SizeOfRawData:
			writable_sections.append(section)

	if not writable_sections:
		raise RuntimeError('no writable sections were found')

	first_raw_section = sorted([s for s in pe.sections if s.SizeOfRawData], key=lambda s: s.PointerToRawData)[0]
	last_raw_section = next(reversed(sorted([s for s in pe.sections if s.SizeOfRawData], key=lambda s: s.PointerToRawData)))  # as the data is ordered in the file
	last_vir_section = next(reversed(sorted([s for s in pe.sections if s.SizeOfRawData], key=lambda s: s.VirtualAddress)))    # as the data is ordered in memory
	backup_section = pefile.SectionStructure(
		pefile.PE.__IMAGE_SECTION_HEADER_format__,
		file_offset=pe.sections[-1].get_file_offset() + SIZEOF_SECTION_HEADER,
		pe=pe
	)
	backup_section.Name = b'.restore'
	backup_section.Misc = 0
	backup_section.VirtualAddress = align_up(last_vir_section.VirtualAddress + last_vir_section.SizeOfRawData, pe.OPTIONAL_HEADER.SectionAlignment)
	backup_section.SizeOfRawData = 0
	backup_section.PointerToRawData = last_raw_section.PointerToRawData + last_raw_section.SizeOfRawData
	backup_section.PointerToRelocations = 0
	backup_section.PointerToLinenumbers = 0
	backup_section.NumberOfRelocations = 0
	backup_section.NumberOfLinenumbers = 0
	backup_section.Characteristics = (IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITLIALIZED_DATA)

	if last_raw_section.__file_offset__ + (SIZEOF_SECTION_HEADER * 2) > first_raw_section.PointerToRawData:
		offset = align_up(last_raw_section.__file_offset__ + (SIZEOF_SECTION_HEADER * 2), pe.OPTIONAL_HEADER.FileAlignment) - first_raw_section.PointerToRawData
		pe.OPTIONAL_HEADER.SizeOfImage += SIZEOF_SECTION_HEADER
		# need to insert data here to make room for the new section, then update
		# each section
		raise RuntimeError('insufficient space for the new section header')

	pe.sections.append(backup_section)
	pe.__structures__.append(backup_section)
	pe.FILE_HEADER.NumberOfSections += 1

	new_section = b''
	for section_idx, section in enumerate(writable_sections, -1):  # start at -1 to account for the null-terminator section header
		section = copy.copy(section)
		section.Characteristics ^= IMAGE_SCN_MEM_WRITE
		section.PointerToRawData = backup_section.PointerToRawData + ((len(writable_sections) - section_idx) * SIZEOF_SECTION_HEADER)
		new_section += section.__pack__()
	new_section += b'\x00' * SIZEOF_SECTION_HEADER  # add the null-terminator section header
	for section in writable_sections:
		new_section += section.get_data()
	backup_section.Misc = len(new_section)
	new_section += b'\x00' * (align_up(len(new_section), pe.OPTIONAL_HEADER.FileAlignment) - len(new_section))
	pe_insert(pe, new_section, backup_section.PointerToRawData)
	backup_section.SizeOfRawData = len(new_section)
	pe.OPTIONAL_HEADER.SizeOfImage = align_up(pe.OPTIONAL_HEADER.SizeOfImage + len(new_section), pe.OPTIONAL_HEADER.SectionAlignment)
	return pe

def main():
	parser = argparse.ArgumentParser(description='ReflectiveUnloader PE Patcher', conflict_handler='resolve')
	parser.add_argument('-v', '--version', action='version', version='%(prog)s Version: ' + __version__)
	parser.add_argument('input_file', help='the pe file to patch')
	parser.add_argument('output_file', help='the path to write the patched file to')
	arguments = parser.parse_args()

	pe_patch(pefile.PE(arguments.input_file)).write(arguments.output_file)
	return 0

if __name__ == '__main__':
	sys.exit(main())
