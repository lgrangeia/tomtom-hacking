#!/usr/bin/env pypy

import sys
import hashlib
import hmac
import datetime

from binascii import crc32
from struct import pack
 
KEY = 'deadbeefdeadbeefdeadbeefdeadbeef'
KEY_BYTES = KEY.decode('hex')
BLOCK_SIZE = 16
TARGETS = frozenset((
    '5c1090ea90411712f3dfa54d38bf3bd3'.decode('hex'), # plaintext[0:16]
    '33567dd599bf6d53b3191bc10c6f0dfe'.decode('hex'), # ciphertext[0:16]
    '63d896d4baa9486288cdfd6045604fb0'.decode('hex'), # ciphertext[16:32]
))

def sxor(s1, s2):    
    # convert strings to a list of character pair tuples
    # go through each tuple, converting them to ASCII code (ord)
    # perform exclusive or on the ASCII code
    # then convert the result back to ASCII (chr)
    # merge the resulting array of characters as a string
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def sxor_mask(s, mask):
    assert(len(mask) == 1)
    mask = len(s) * mask
    return sxor(s, mask)


def md5it(data):
    return hashlib.md5(data).digest()


def hmacit(data):
    h = hmac.new(KEY_BYTES, msg=data, digestmod=hashlib.md5)
    return h.digest()


def xormask_blob(data):
    i = 0
    blocksz = 16
    output = []
    extra = 0x7C
    while i < len(data):
        output.append(chr(ord(data[i])^extra) + data[i+1:i+blocksz])
        extra += 0x4
        extra &= 0x7f
        i += blocksz

    return''.join(output)

def test_pipeline(data):
    md5h = md5it(data)
    md5hmac = hmacit(data)
    candidates = [ 
        md5h,
        md5it(KEY_BYTES + data),
        md5it(data + KEY_BYTES),
        sxor(KEY_BYTES, md5h),
        md5hmac,
        sxor(KEY_BYTES, md5hmac),
        md5h[::-1],
        md5hmac[::-1],
        xormask_blob(md5h),
        xormask_blob(md5hmac),
        xormask_blob(md5h[::-1]),
    ]

    for i, c in enumerate(candidates):
        if c in TARGETS:
            d = datetime.datetime.now().strftime('%H:%M:%S.%f')
            print('{}: pipeline stage {} has matched: {}'.
                  format(d, i, c.encode('hex')))
            return True

        for mask in xrange(256):
            masked = sxor_mask(c, chr(mask))
            if masked in TARGETS:
                d = datetime.datetime.now().strftime('%H:%M:%S.%f')
                print('{}: pipeline stage {} has matched: xor({}, {})'.
                      format(d, i, mask, c.encode('hex')))
                return True

    return False


def search_range(data, begin, end):
    for i in xrange(begin, end, BLOCK_SIZE):
        d = datetime.datetime.now().strftime('%H:%M:%S.%f')
        print('{}: current range [{}:{}]'.format(d, i, end))
        for j in xrange(i + BLOCK_SIZE, end + BLOCK_SIZE, BLOCK_SIZE):
            chunk = data[i:j]
            if test_pipeline(chunk):
                print('Found match for range [{}:{}]'.format(i, j))


def main():
    if len(sys.argv) < 2:
        sys.exit('usage: {} <input_file>'.format(sys.argv[0]))

    fname = sys.argv[1]
    data = open(fname, 'rb').read()
    dlen = len(data)

    search_range(data, BLOCK_SIZE, dlen)

if __name__ == '__main__':
    main()

