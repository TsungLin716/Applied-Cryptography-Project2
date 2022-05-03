import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# both parties have to generate keys using the same parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

# this example scenario will take place from Bob's perspective
bob_secret_key = parameters.generate_private_key()
bob_public_key = parameters.generate_private_key().public_key()
alice_secret_key = parameters.generate_private_key()
alice_public_key = parameters.generate_private_key().public_key()
shared_key = parameters.generate_private_key(alice_public_key)

derived_key = HKDF(
	algorithm=hashes.SHA256(),
	length=32,
	salt=None,
	info=b'handshake data',
).derive(shared_key)

# have to generate another set of keys for next part of the exchange
bob_secret_key2 = parameters.generate_private_key()
alice_public_key2 = parameters.generate_private_key().public_key()
shared_key2 = parameters.generate_private_key(alice_public_key2)

derived_key2 = HKDF(
	algorithm=hashes.SHA256(),
	length=32,
	salt=None,
	info=b'handshake data',
).derive(shared_key2)