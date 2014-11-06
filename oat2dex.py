#!/usr/bin/env python
# oat2dex
# Copyright 2014 Jake Valletta (@jake_valletta)
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Extract DEX from an ART ELF file
from re import finditer
from sys import argv, exc_info
import struct

__NAME__ = "oat2dex"
__VERSION__ = "1.0"

def usage():
    print "Usage: %s [oat_file] ..." % __NAME__

def getSize(f, offset):

    f.seek(offset)
    try:
        size = struct.unpack('i', f.read(4))[0]
    except:
        print "Unexpected error getting size:", exc_info()[0]
        return -1

    return size

def carveDex(oat_file, dex_offset, oat_file_name):

    print "Found DEX signature at offset 0x%x" % dex_offset

    size_offset = dex_offset + 32

    dex_size = getSize(oat_file, size_offset)

    if dex_size < 0:
        print "Unable to get DEX size."
        return -1

    print "Got DEX size: 0x%x" % dex_size

    carved_name = "%s.%s.odex" % (oat_file_name, hex(dex_offset))

    print "Carving to: \'%s\'" % carved_name

    try:
        out_file = open(carved_name, 'wb')

        oat_file.seek(dex_offset)
        out_file.write(oat_file.read(dex_size))
        out_file.close()
    except(IOError, OSError) as e:
        print "[ERROR] Unable to open output file!"
        return -2

    return 0

def processOat(oat_file_name):

    rtn = 0

    print "Processing \'%s\'" % oat_file_name
    try:
        f = open(oat_file_name, 'r')

        try:
            s = f.read()
            hits = [m.start() for m in finditer('dex\n035', s)]

            for dex_addr in hits:
                rtn |= carveDex(f, dex_addr, oat_file_name)
        finally:
            f.close()

    except (IOError, OSError) as e:
        print "[ERROR] Unable to open file \'%s\'" % oat_file_name
        return -1

    return rtn

def main(args):
    
    rtn = 0

    for oat in args:
        rtn |= processOat(oat)

    return rtn

if __name__ == "__main__":

    if len(argv) < 2:
        print "[Error] You must specify at least 1 OAT file."
        exit(usage())

    exit(main(argv[1:]))
