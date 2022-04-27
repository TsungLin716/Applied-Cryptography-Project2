import random
import cryptography
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

ALPHABET = ["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z",
            "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
            "1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]


def keygen(key_size):
    key = []

    # generate the key
    while len(key) < key_size:
        x = random.randint(0, 61)           # ALPHABET list has 62 elements, pick one of them
        
        key.append(ALPHABET[x])             # convert to bytes type to work with wrapping function
    
    # join key list, then convert to byte type for library function compatibility
    key_joined = ''.join(key)
    key_bytes = key_joined.encode('UTF-8')
    
    return key_bytes

# generate public and secret keys, then generate wrapping keys for each
# have to use 32 characters (1 byte per char) to match up with 256-bit AES key size, largest supported by library
public_key = keygen(32)
secret_key = keygen(32)
public_wrapping = keygen(32)
secret_wrapping = keygen(32)

# wrap the public and secret keys - wrapping key, key to wrap
public_wrapped = aes_key_wrap(public_wrapping, public_key)
secret_wrapped = aes_key_wrap(secret_wrapping, secret_key)

# unwrapping works in reverse - wrapping key, key to unwrap
public_unwrapped = aes_key_unwrap(public_wrapping, public_wrapped)
secret_unwrapped = aes_key_unwrap(secret_wrapping, secret_wrapped)

# unwrapped key looks like this: 
# b'jD3coOw0UicLvEjNYlNDo2g5xZdYJpl4'
# the b at the beginning indicates it's a byte object
# to convert back to a string, do key_byte_format.decode("UTF-8")

# wrapped key looks like this: 
# b'0\xb5v\xaf\xfa\xaf\xacc\x1c\x92\x96I}S\xde\xe3q]\xb3\xf6T\xb1U\xa9\x95\xa7\x02\x17m\x9bF\x81?\x97}\xa9\xb8{\xc0s'