import random
from re import X
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# both parties have to generate keys using the same parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

bob_secret_key = parameters.generate_private_key()
alice_public_key = parameters.generate_private_key().public_key()
shared_key = bob_secret_key.exchange(alice_public_key)

#print(type(bob_secret_key))
#print(type(alice_public_key))
#print(type(shared_key))

print(str(bob_secret_key))
print(str(bob_secret_key.private_bytes('pem', 'pkcs8', 'noencryption')))

derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake'
).derive(shared_key)

file = open("public_bob.txt", "w")
file.write(str(derived_key))
file.close()

pubkey = open("public_bob.txt", "r")
print(pubkey)