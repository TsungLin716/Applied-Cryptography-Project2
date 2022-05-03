import codecs
#import chardet
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# both parties have to generate keys using the same parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

alice_secret_key = parameters.generate_private_key()
alice_public_key = parameters.generate_private_key().public_key()
bob_public_key = parameters.generate_private_key().public_key()
shared_key = alice_secret_key.exchange(bob_public_key)

# public/private keys give you a special key object that this library created

# shared key gives you a really big byte object that looks like: 
#b'\xc5P\xccm\x0e\xc8\x92\x81\x8c\xf9}\xe4\x9a\x9a\n\xd5~\xe7%FK\t\xa2\xdc\xf9O
# \xb1_\xbac\x1a,\x81/\xaad\x97e\xf5\xe5\xb7\x1aH=2\xd360\xb2f\xdb(1\x82\xa4!Y\
# xabei\xdbD?\x07\xf9v\xb8\x8dT\xbel\x85m\xdf\x93\x18\xf0\xb7\xf9B\xd6\xad\x15Y
# \x8a\xfd^\x1e<\xc8\xa2\xa8y@\x8f\x7f\xa5\x0fO\x19H\x96\x10\xd4\xd0\xf5\xbeF\x
# 00)\xb2TuZ\xc4Vc\x99\xe8\x9c0\xc8R\xe8nE\x0e\x81\xb6\x0c\x08Y\x19b\x14?\x06\x
# a5\xac\xc9\x951\xe0\xb3S\x95\xfa\xf6\xfc\xb8.\x9d%c\x03\x90\x17\x9cY\xb9\x8a\
# xdb?!X\x9f}VJ\xe7%\x9a1\x049\x1b\xb1N\x1f\xbd\xf2\x01\x1e\xb1\xa7\x02\xba5\xd
# 17\x83\x08\xa1\xd87\xdb\x15\xde\xd6\x8c\x97\xdb\x8f\x1c\x9dE\x1d\x15\x15o\xfa
# G\xd0\xa3-6\x82\x0f\x0bQ\xc6[|\x95\xb6[\x92I1\xaaL\x7f{\xef\x04-\x1a\x83\xfa\
# x03\xb30_\xa79\xfb\x04\xdc!\xd4\x92\xc7E\n9d'

print(alice_secret_key)
print(alice_public_key)
#print(shared_key)

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data',
).derive(shared_key)

# key derivation gives you a smaller byte object that looks like: 
# b'\xce\x11S!\xaf\xff\xf3\x03,\xf2V}54\xa7\x9cY6\xf3\xe2k\xb2\x9fJ\xcb\x8c\xf0\x1eZYWB'

#encoding_type = chardet.detect(derived_key)['encoding']
encoding_type = json.detect_encoding(derived_key)
print(encoding_type)

print(derived_key)
#str_derived_key = ''.join(map(chr, derived_key))
str_derived_key = str(derived_key, 'UTF-8')

print(str_derived_key)