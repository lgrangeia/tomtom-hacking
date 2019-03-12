#!/usr/bin/env python
import sys
from Crypto.Cipher import AES
import hashlib

# change this with the real key
key = "0400112233445566778800AABBCCDDEE"

# block size
bsize = 16

# flash sector block size
flash_sector = 256

def decrypt_blob(key, data):
   aes = AES.new(key, AES.MODE_ECB, '')
   return aes.decrypt(data)

def encrypt_blob(key, data):
   aes = AES.new(key, AES.MODE_ECB, '')
   return aes.encrypt(data)

def xormask_blob(data):
   i = 0
   output = ''
   extra = 0
   while i < len(data):
      output = output + chr(ord(data[i])^extra) + data[i+1:i+bsize]
      extra += 0x4
      extra &= 0x7f
      i += bsize
   return output

## Main:

if (len(sys.argv) != 4):
   print ('usage: {:s} d|e <inputfile> <outputfile>'.format(sys.argv[0]))
   sys.exit(-1)

# DECRYPT:
if (sys.argv[1] == 'd'): 
   inputdata = file(sys.argv[2], 'rb').read()
   decrypted = xormask_blob(decrypt_blob(key.decode('hex'), inputdata[bsize:]))

   # File format is [HASHMAC][ENCRYPTEDDATA]
   # HASHMAC == md5sum(ENCRYPTEDDATA + key)

   # Verify outer MD5 (keyed Hash)
   md5sum = inputdata[:bsize]
   msg = inputdata[bsize:]

   offset = 0
   while (offset <= len(msg)):
      m = hashlib.md5()
      m.update(msg[0:offset])
      m.update(key.decode('hex'))

      if (m.digest() == md5sum):
         print('correct OUTER md5 at start of file {:s}, hashes (with password) offset 0-{:d}'.format(md5sum.encode('hex'),offset))
         break
      offset = offset + bsize

   # find and verify inner MD5
   m = hashlib.md5()
   
   i = 0
   while (i < len(decrypted)):
      thisblock = decrypted[i:i+bsize]
      if (m.digest() == thisblock):
         print('found correct INNER md5 {:s} at offset {:d}'.format(thisblock.encode('hex'),i))
         break
      m.update(decrypted[i:i+bsize])
      i = i + bsize
      
   print("size of extra trash: %i" % (len(decrypted[i+bsize:])))
   outputfile = file(sys.argv[3], 'wb')
   outputfile.write(decrypted[:i])
   outputfile.close()

# ENCRYPT:
if (sys.argv[1] == 'e'): 

   inputdata = file(sys.argv[2], 'rb').read()

   # Compute inner MD5
   m = hashlib.md5()
   m.update(inputdata)
   newmd5 = m.digest()
   print(newmd5.encode('hex'))
   inputdata += newmd5

   # padding issues... this works
   extra = (len(inputdata) + flash_sector) % (flash_sector*2) - 32

   print('rom: {:d} bytes, will add {:d} bytes more'.format(len(inputdata), extra))
   inputdata += extra*'00'.decode('hex')

   encrypted = encrypt_blob(key.decode('hex'), xormask_blob(inputdata))

   m = hashlib.md5()
   m.update(encrypted)
   m.update(key.decode('hex'))

   outtermd5 = m.digest()
   print('outer md5:')
   print(outtermd5.encode('hex'))

   encmd5 = outtermd5 + encrypted

   outputfile = file(sys.argv[3], 'wb')
   outputfile.write(encmd5)
   outputfile.close()
