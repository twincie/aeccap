import os
import hashlib
import random
from tinyec import registry
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import time
import psutil
from memory_profiler import profile


# Generate ECC key pair

def generate_key_pair():
    curve = registry.get_curve('brainpoolP256r1')  # Select the desired curve
    private_key = random.randint(1, curve.field.n - 1)  # Private key in the range of field size
    public_key = private_key * curve.g  # Compute public key
    private_key_hex = hex(private_key)[2:].upper()  # Convert private key to hexadecimal string
    public_key_hex = hex(public_key.x)[2:].upper()  # Convert public key x-coordinate to hexadecimal string
    return private_key_hex, public_key_hex, curve  # Also return the curve object

# Conversion functions
def int_to_bytes(value):
    value_hex = hex(value)[2:]  # Remove '0x' prefix
    if len(value_hex) % 2 != 0:
        value_hex = '0' + value_hex  # Ensure even length
    return bytes.fromhex(value_hex)
def bytes_to_int(value_bytes):
    return int.from_bytes(value_bytes, 'big')

# Encryption
def ecc_encrypt(plaintext, recipient_public_key, provided_ephemeral_public_key=None, provided_iv=None):
    curve = registry.get_curve('brainpoolP256r1')
    if provided_ephemeral_public_key is None:
        k = random.randint(1, curve.field.n - 1)  # Random value within the curve's range
        ephemeral_public_key = k * curve.g
    else:
        x_ephemeral, y_ephemeral = map(int, bytes.fromhex(provided_ephemeral_public_key))
        ephemeral_public_key = curve.point(x_ephemeral, y_ephemeral)
    shared_secret = recipient_public_key * k  # Use recipient private key here
    shared_secret_bytes = int_to_bytes(shared_secret.x)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_secret_bytes)
    if provided_iv is not None:
        iv = bytes.fromhex(provided_iv)
    else:
        iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, ephemeral_public_key, iv.hex()

# Decryption
def ecc_decrypt(ciphertext, ephemeral_public_key, iv, recipient_private_key):
    curve = registry.get_curve('brainpoolP256r1')
    shared_secret = ephemeral_public_key * recipient_private_key  # Use recipient private key here
    shared_secret_bytes = int_to_bytes(shared_secret.x)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_secret_bytes)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(bytes.fromhex(iv)))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# Signature Generation
def ecc_sign(message, private_key, curve):
    message_hash = hashlib.sha256(message).digest()
    k = random.randint(1, curve.field.n - 1)  # Random value within the curve's range
    r = (k * curve.g).x % curve.field.n
    k_inv = pow(k, -1, curve.field.n)
    s = (k_inv * (bytes_to_int(message_hash) + r * private_key)) % curve.field.n
    return r, s

# Signature Verification
def ecc_verify(message, signature, public_key, curve):
    r, s = signature
    if r < 1 or r > curve.field.n - 1 or s < 1 or s > curve.field.n - 1:
        return False
    message_hash = hashlib.sha256(message).digest()
    w = pow(s, -1, curve.field.n)
    u1 = (bytes_to_int(message_hash) * w) % curve.field.n
    u2 = (r * w) % curve.field.n
    verification_point = u1 * curve.g + u2 * public_key
    return r == verification_point.x % curve.field.n

# testing algorithms above

# User Input for Keys
print("Generating Alice's key pair...")
alice_private_key_hex, alice_public_key_hex, curve = generate_key_pair()
print("Generating Bob's key pair...")
bob_private_key_hex, bob_public_key_hex, curve = generate_key_pair()
print("\nAlice's Private Key (Hexadecimal):", alice_private_key_hex)
print("Alice's Public Key (Hexadecimal):", alice_public_key_hex)
print("Bob's Private Key (Hexadecimal):", bob_private_key_hex)
print("Bob's Public Key (Hexadecimal):", bob_public_key_hex)
print("Enter Provided Ephemeral Public Key in Hex (or leave empty for random generation):")
ephemeral_public_key_hex = input().strip()
print("Enter Provided IV in Hex (or leave empty for random generation):")
iv_hex = input().strip()

# Get the base point (generator) of the curve
g = curve.g

# Convert hexadecimal keys to integers for encryption and decryption
alice_private_key = int(alice_private_key_hex, 16)
alice_public_key_x = int(alice_public_key_hex, 16)
bob_private_key = int(bob_private_key_hex, 16)
bob_public_key_x = int(bob_public_key_hex, 16)

# Calculate the public keys for Alice and Bob
alice_public_key = alice_private_key * g
bob_public_key = bob_private_key * g

# Convert hexadecimal ephemeral public key and IV to Point and bytes respectively for encryption
if ephemeral_public_key_hex == '':
    ephemeral_public_key_hex = None
else:
    ephemeral_public_key_hex = ephemeral_public_key_hex

if iv_hex == '':
    iv_hex = None
else:
    iv_hex = iv_hex

# Step 2: Alice Sends an Encrypted Message to Bob
# message = b"Hello, Bob! This is a secure message from Alice."
# message = b"Message"
# message = b"secure Message"
# message = b"Message from Alice"
# message = b"This is a message"
# message = b"This is a secure message"
# message = b"This is a secure message alice"
# message = b"This is a secure message from Alice."
# message = b"Bob! This is a secure message from Alice."
message = b"Hello, Bob! This is a secure message from Alice."

start_time = time.time()
ciphertext, ephemeral_public_key, iv = ecc_encrypt(
    message, bob_public_key,
    provided_ephemeral_public_key=ephemeral_public_key_hex,
    provided_iv=iv_hex
)
encryption_time = time.time() - start_time


# Step 3: Bob Receives and Decrypts the Message
start_time = time.time()
decrypted_message = ecc_decrypt(ciphertext, ephemeral_public_key, iv, bob_private_key)
decryption_time = time.time() - start_time

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss

# @profile
# def profile_encryption():
#     ecc_encrypt(
#         message, bob_public_key,
#         provided_ephemeral_public_key=ephemeral_public_key_hex,
#         provided_iv=iv_hex
#     )

# @profile
# def profile_decryption():
#     ecc_decrypt(ciphertext, ephemeral_public_key, iv, bob_private_key)


# Profile memory usage for encryption and decryption
def profile_encryption():
    before_memory = get_memory_usage()
    ecc_encrypt(
        message, bob_public_key,
        provided_ephemeral_public_key=ephemeral_public_key_hex,
        provided_iv=iv_hex
    )
    after_memory = get_memory_usage()
    return after_memory - before_memory

def profile_decryption():
    before_memory = get_memory_usage()
    ecc_decrypt(ciphertext, ephemeral_public_key, iv, bob_private_key)
    after_memory = get_memory_usage()
    return after_memory - before_memory

# Step 4 (Optional): Signature Generation and Verification
signature = ecc_sign(message, alice_private_key, curve)
verified_message = ecc_verify(message, signature, alice_public_key, curve)

# Profile memory usage for encryption and decryption
encryption_memory = profile_encryption()
decryption_memory = profile_decryption()

# Print the collected information
print("Plaintext:", message)

# print("signature:", signature)
# print("ephemeral_public_key:", ephemeral_public_key)
# print("iv:", iv)

print("Ciphertext:", ciphertext)
print("Decrypted Message:", decrypted_message)
print("Encryption Time:", encryption_time, "seconds")
print("Decryption Time:", decryption_time, "seconds")
print("Encryption Memory Usage:", encryption_memory, "bytes")
print("Decryption Memory Usage:", decryption_memory, "bytes")
print("Verified Message:", verified_message)