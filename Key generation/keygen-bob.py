import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# both parties have to generate keys using the same parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

