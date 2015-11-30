#!/usr/bin/env pypy

import sys
import datetime

from binascii import crc32
from struct import pack
from hashlib import md5

BLOCK_SIZE = 16


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: {} <file0,file1,fileN>'.format(sys.argv[0]))

    fnames = sys.argv[1].split(',')
    parts = []
    for fname in fnames:
        data = open(fname, 'rb').read()
        parts.append(data)

    data = ''.join(parts) 
    dlen = len(data)

    candidates = set()
    for offset in xrange(0, dlen, BLOCK_SIZE):
        candidates.add(data[offset: offset + BLOCK_SIZE])

    for i in xrange(0, dlen, BLOCK_SIZE):
        d = datetime.datetime.now().strftime("%H:%M:%S.%f")
        print('{}: current range [{}:{}]'.format(d, i, dlen)) 
        for j in xrange(i + BLOCK_SIZE, dlen + BLOCK_SIZE, BLOCK_SIZE):
            chunk = data[i:j]
            h = md5(chunk).digest()
            if h in candidates:
                d = datetime.datetime.now().strftime("%H:%M:%S.%f")
                print('{}: {} is a possible MD5 hash for range [{}:{}]'.
                      format(d, h.encode('hex'), i, j))

if __name__ == '__main__':
    main()

