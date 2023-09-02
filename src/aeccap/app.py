"""
cryptoapp
"""
import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW

import os
from os.path import join
import hashlib
import random
import tinyec
from tinyec import registry
import cryptography
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
# Generate ECC key pair

curve = registry.get_curve('brainpoolP256r1')
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
    provided_ephemeral_public_key = None
    provided_iv = None
    curve = registry.get_curve('brainpoolP256r1')
    if provided_ephemeral_public_key is None or provided_ephemeral_public_key == '':
        num_bytes = 32
        random_bytes = bytes(random.randint(0, 255) for _ in range(num_bytes))
        ephemeral_key = random_bytes.hex()
        k = int(ephemeral_key, 16)
        ephemeral_public_key = k * curve.g
        # k = random.randint(1, curve.field.n - 1)  # Random value within the curve's range
        # ephemeral_public_key = k * curve.g
        # ephemeral_public_key = '(1591462014330830979848810844462451042259120341821163110163063690890048273699, 63902384522923108216681659644935075878854045904470747621348670476080546380434) on "brainpoolP256r1" => y^2 = x^3 + 56698187605326110043627228396178346077120614539475214109386828188763884139993x + 17577232497321838841075697789794520262950426058923084567046852300633325438902 (mod 76884956397045344220809746629001649093037950200943055203735601445031516197751)'
    else:
        try:
            provided_ephemeral_public_key = bytes.fromhex(provided_ephemeral_public_key)
            k = int(provided_ephemeral_public_key, 16)
            ephemeral_public_key = k * curve.g
            # x_ephemeral, y_ephemeral = map(int, bytes.fromhex(provided_ephemeral_public_key))
            # ephemeral_public_key = curve.point(x_ephemeral, y_ephemeral)
        except ValueError:
            # Handle invalid input for provided_ephemeral_public_key
            raise ValueError("Invalid provided_ephemeral_public_key")

    shared_secret = recipient_public_key * k  # Use recipient private key here
    shared_secret_bytes = int_to_bytes(shared_secret.x)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'',
    ).derive(shared_secret_bytes)

    if provided_iv is None or provided_iv == '':
        # iv = bytes.fromhex(provided_iv)
        # iv = os.urandom(16)
        iv = b'\xbcU\x05\x1d\x9e\xfa7\xb6\x8d\x1d\xbb\xa0\xca\xa8\x9f\x18' #default iv
    else:
        iv = bytes.fromhex(provided_iv)
        # iv = b'\xbcU\x05\x1d\x9e\xfa7\xb6\x8d\x1d\xbb\xa0\xca\xa8\x9f\x18' #default iv
        # iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext, ephemeral_public_key, ephemeral_key ,iv.hex()

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

class aeccap(toga.App):

    def startup(self):
        self.main_box = toga.Box(style=Pack(direction=COLUMN))
        self.current_view = None
        self.generate_view = None
        self.encrypt_view = None

        # Create the generate view with navigation buttons
        self.generate_view = toga.Box()
        self.generate_view.style = Pack(direction=COLUMN, padding=10)

        # alice_private_key_label = toga.Label("Alice's Private Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        # self.alice_private_key_input = toga.TextInput(style=Pack(flex=1))
        # alice_public_key_label = toga.Label("Alice's Public Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        # self.alice_public_key_input = toga.TextInput(style=Pack(flex=1))
        # bob_private_key_label = toga.Label("Bob's Private Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        # self.bob_private_key_input = toga.TextInput(style=Pack(flex=1))
        # bob_public_key_label = toga.Label("Bob's Public Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        # self.bob_public_key_input = toga.TextInput(style=Pack(flex=1))
        # ephemeral_key_label = toga.Label("Ephemeral Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        # self.ephemeral_key_input = toga.TextInput(style=Pack(flex=1))
        # iv_label = toga.Label("IV Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        # self.iv_input = toga.TextInput(style=Pack(flex=1))

        # name_box1 = toga.Box(style=Pack(direction=ROW, padding=5))
        # name_box2 = toga.Box(style=Pack(direction=ROW, padding=5))
        # name_box3 = toga.Box(style=Pack(direction=ROW, padding=5))
        # name_box4 = toga.Box(style=Pack(direction=ROW, padding=5))
        # name_box5 = toga.Box(style=Pack(direction=ROW, padding=5))
        # name_box6 = toga.Box(style=Pack(direction=ROW, padding=5))
        
        back_button_generate = toga.Button('Back', on_press=self.show_main_view, style=Pack(padding=5))
        self.generate_label = toga.Label("",style=Pack(flex=1))
        # name_box1.add(alice_private_key_label)
        # name_box1.add(self.alice_private_key_input)
        # name_box2.add(alice_public_key_label)
        # name_box2.add(self.alice_public_key_input)
        # name_box3.add(bob_private_key_label)
        # name_box3.add(self.bob_private_key_input)
        # name_box4.add(bob_public_key_label)
        # name_box4.add(self.bob_public_key_input)
        # name_box5.add(ephemeral_key_label)
        # name_box5.add(self.ephemeral_key_input)
        # name_box6.add(iv_label)
        # name_box6.add(self.iv_input)

        genButton = toga.Button("Generate", on_press=self.generate_keys, style=Pack(padding=5))
        next_button = toga.Button('Next', on_press=self.show_encrypt_view, style=Pack(padding=5))
        
        self.generate_view.add(back_button_generate)
        self.generate_view.add(self.generate_label)
        # self.generate_view.add(name_box1)
        # self.generate_view.add(name_box2)
        # self.generate_view.add(name_box3)
        # self.generate_view.add(name_box4)
        # self.generate_view.add(name_box5)
        # self.generate_view.add(name_box6)
        self.generate_view.add(genButton)
        self.generate_view.add(next_button)

        # Create the encrypt view
        self.encrypt_view = toga.Box()
        self.encrypt_view.style = Pack(direction=COLUMN, padding=10)
        
        back_button_encrypt = toga.Button('Back', on_press=self.show_generate_view, style=Pack(padding=5))
        self.encrypt_label = toga.Label("",style=Pack(flex=1))
        self.message_input = toga.TextInput("Enter message here... ", style=Pack(flex=1))
        encryptButton = toga.Button("Encrypt", on_press=self.encrypt_message, style=Pack(flex=1))
        self.decrypted_label = toga.Label("",style=Pack(flex=1))
        saveButton = toga.Button("save", on_press=self.save_ciphertext_and_keys, style=Pack(padding=5,flex=1))
        
        inner_box1 = toga.Box(style=Pack(direction=ROW, padding=5))
        inner_box2 = toga.Box(style=Pack(direction=ROW, padding=5))
        inner_box3 = toga.Box(style=Pack(direction=ROW, padding=5))
        inner_box4 = toga.Box(style=Pack(direction=ROW, padding=5))
        inner_box5 = toga.Box(style=Pack(direction=ROW, padding=5))

        inner_box1.add(self.message_input)
        inner_box2.add(self.encrypt_label)
        inner_box3.add(encryptButton)
        inner_box4.add(self.decrypted_label)
        inner_box5.add(saveButton)

        self.encrypt_view.add(back_button_encrypt)
        self.encrypt_view.add(inner_box1)
        self.encrypt_view.add(inner_box2)
        self.encrypt_view.add(inner_box3)
        self.encrypt_view.add(inner_box4)
        self.encrypt_view.add(inner_box5)


        # Create the decrypt view
        self.decrypt_view = toga.Box()
        self.decrypt_view.style = Pack(direction=COLUMN, padding=10)
        
        back_button_decrypt = toga.Button('Back', on_press=self.show_main_view, style=Pack(padding=5))
        loadButton = toga.Button("Load Ciphertext and Keys", on_press=self.load_ciphertext_and_keys, style=Pack(flex=1))
        self.decrypted_label = toga.Label("",style=Pack(flex=1))
        self.decrypt_label = toga.Label("",style=Pack(flex=1))
        decryptButton = toga.Button("Decrypt", on_press=self.decrypt_message, style=Pack(flex=1))

        ciphertext_label = toga.Label("Ciphertext: ", style=Pack(padding=(0,5)))
        self.ciphertext_input = toga.TextInput(style=Pack(flex=1))
        alice_private_key_label = toga.Label("Alice's Private Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        self.alice_private_key_input = toga.TextInput(style=Pack(flex=1))
        alice_public_key_label = toga.Label("Alice's Public Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        self.alice_public_key_input = toga.TextInput(style=Pack(flex=1))
        bob_private_key_label = toga.Label("Bob's Private Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        self.bob_private_key_input = toga.TextInput(style=Pack(flex=1))
        bob_public_key_label = toga.Label("Bob's Public Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        self.bob_public_key_input = toga.TextInput(style=Pack(flex=1))
        ephemeral_key_label = toga.Label("Ephemeral Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        self.ephemeral_key_input = toga.TextInput(style=Pack(flex=1))
        iv_label = toga.Label("IV Key (Hexadecimal): ", style=Pack(padding=(0,5)))
        self.iv_input = toga.TextInput(style=Pack(flex=1))

        name_box0 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box1 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box2 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box3 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box4 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box5 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box6 = toga.Box(style=Pack(direction=ROW, padding=5))
        name_box0.add(ciphertext_label)
        name_box0.add(self.ciphertext_input)
        name_box1.add(alice_private_key_label)
        name_box1.add(self.alice_private_key_input)
        name_box2.add(alice_public_key_label)
        name_box2.add(self.alice_public_key_input)
        name_box3.add(bob_private_key_label)
        name_box3.add(self.bob_private_key_input)
        name_box4.add(bob_public_key_label)
        name_box4.add(self.bob_public_key_input)
        name_box5.add(ephemeral_key_label)
        name_box5.add(self.ephemeral_key_input)
        name_box6.add(iv_label)
        name_box6.add(self.iv_input)

        self.decrypt_view.add(back_button_decrypt)
        self.decrypt_view.add(loadButton)
        self.decrypt_view.add(name_box0)
        self.decrypt_view.add(name_box1)
        self.decrypt_view.add(name_box2)
        self.decrypt_view.add(name_box3)
        self.decrypt_view.add(name_box4)
        self.decrypt_view.add(name_box5)
        self.decrypt_view.add(name_box6)
        self.decrypt_view.add(decryptButton)
        self.decrypt_view.add(self.decrypt_label)
        self.decrypt_view.add(self.decrypted_label)

        self.ciphertext = None
        self.alice_private_key = None
        self.alice_public_key = None
        self.bob_private_key = None
        self.bob_public_key = None
        self.iv = None
        self.ephemeral_key = None
        
        # Create the main view with navigation buttons
        self.view_box = toga.Box()
        self.view_box.style = Pack(direction=ROW, padding=2)
        
        generate_view_button = toga.Button('Generate', on_press=self.show_generate_view, style=Pack(padding=2))
        decrypt_view_button = toga.Button('Decrypt', on_press=self.show_decrypt_view, style=Pack(padding=2))

        self.view_box.add(generate_view_button)
        self.view_box.add(decrypt_view_button)
        
        self.main_box.add(self.view_box)

        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = self.main_box
        self.main_window.show()

    def show_main_view(self, sender):
        if self.current_view is not None:
            self.main_box.remove(self.current_view)
        
        self.current_view = None
        self.main_box.add(self.view_box)
        self.main_window.show()

    def show_generate_view(self, sender):
        if self.current_view is not None:
            self.main_box.remove(self.current_view)
        
        self.current_view = self.generate_view
        self.main_box.add(self.current_view)
        self.main_window.show()

    def show_encrypt_view(self, sender):
        if self.current_view is not None:
            self.main_box.remove(self.current_view)
        
        self.current_view = self.encrypt_view
        self.main_box.add(self.current_view)
        self.main_window.show()

        # Set the ephemeral_key attribute
        self.ephemeral_key = self.ephemeral_key_input.value

    def show_decrypt_view(self, sender):
        if self.current_view is not None:
            self.main_box.remove(self.current_view)
        
        self.current_view = self.decrypt_view
        self.main_box.add(self.current_view)
        self.main_window.show()

    def generate_keys(self, widget):
        alice_private_key_hex, alice_public_key_hex, curve = generate_key_pair()
        bob_private_key_hex, bob_public_key_hex, curve = generate_key_pair()

        self.alice_private_key_input.value = alice_private_key_hex
        self.alice_public_key_input.value = alice_public_key_hex
        self.bob_private_key_input.value = bob_private_key_hex
        self.bob_public_key_input.value = bob_public_key_hex
        
        # Update the view to show the generate view
        self.main_box.remove(self.current_view)
        self.current_view = self.generate_view
        self.main_box.add(self.current_view)
        self.main_window.show()        # Save the relevant key pairs and IV/ephemeral_key for encryption
        
        self.set_key_pairs(
            self.alice_private_key_input.value,
            self.alice_public_key_input.value,
            self.bob_private_key_input.value,
            self.bob_public_key_input.value,
            self.ephemeral_key_input.value,
            self.iv_input.value
        )
        self.generate_label.text = f"Message: The keys have been generated"

    def set_key_pairs(self, alice_private_key, alice_public_key,
                      bob_private_key, bob_public_key, ephemeral_key, iv):
        self.alice_private_key = alice_private_key
        self.alice_public_key = alice_public_key
        self.bob_private_key = bob_private_key
        self.bob_public_key = bob_public_key
        self.ephemeral_key = ephemeral_key
        self.iv = iv

    def encrypt_message(self, instance):
        if '' in (self.alice_private_key, self.alice_public_key,
                    self.bob_private_key, self.bob_public_key):
            self.decrypted_label.text = "Please generate key pairs first and provide ephemeral key/IV or leave it empty."
        else:
            # Get the base point (generator) of the curve
            g = curve.g

            # Convert hexadecimal keys to integers for encryption and decryption
            alice_private_key = int(self.alice_private_key, 16)
            alice_public_key_x = int(self.alice_public_key, 16)
            bob_private_key = int(self.bob_private_key, 16)
            bob_public_key_x = int(self.bob_public_key, 16)

            # Calculate the public keys for Alice and Bob
            alice_public_key = alice_private_key * g
            bob_public_key = bob_private_key * g
            message = self.message_input.value.encode()
            ciphertext, self.ephemeral_public_key ,self.ephemeral_key, self.iv = ecc_encrypt(
                message, bob_public_key,
                provided_ephemeral_public_key=self.ephemeral_key,
                provided_iv=self.iv_input.value
            )
            self.decrypted_label.text = f"Encrypted Message: {ciphertext.hex()}"
            self.encrypt_label.text = f"Message: The message has been encrypted"
            
    def save_ciphertext_and_keys(self, instance):
        # Save the ciphertext and private keys to separate files
        filename1 = join(os.environ["HOME"], "ciphertext.txt")
        filename2 = join(os.environ["HOME"], "private_keys.txt")
        ciphertext = self.decrypted_label.text.split(": ")[1]  # Get the ciphertext part
        # with open("ciphertext.txt", "w") as file:
        with open(filename1, "w") as file:
            file.write(ciphertext)

        # with open("private_keys.txt", "w") as file:
        with open(filename2, "w") as file:
            file.write(f"Alice Private Key: {self.alice_private_key}\n")
            file.write(f"Alice Public Key: {self.alice_public_key}\n")
            file.write(f"Bob Private Key: {self.bob_private_key}\n")
            file.write(f"Bob Public Key: {self.bob_public_key}\n")
            file.write(f"Ephemeral Public Key: {self.ephemeral_key}\n")
            file.write(f"IV: {self.iv}\n")
        self.encrypt_label.text = f"Message: The message and keys has been saved"

    def set_keys(self, alice_private_key, alice_public_key, bob_private_key, bob_public_key, iv):
        self.alice_private_key = alice_private_key
        self.alice_public_key = alice_public_key
        self.bob_private_key = bob_private_key
        self.bob_public_key = bob_public_key
        self.ephemeral_key = ''
        self.iv = iv

    def decrypt_message(self, instance):
        if self.ciphertext is None:
            self.decrypt_label.text = "Please load the ciphertext first."
            return

        # Convert hexadecimal keys to integers for decryption
        alice_private_key = int(self.alice_private_key, 16)
        alice_public_key_x = int(self.alice_public_key, 16)
        bob_private_key = int(self.bob_private_key, 16)
        bob_public_key_x = int(self.bob_public_key, 16)

        # Calculate the public keys for Alice and Bob
        alice_public_key = alice_private_key * curve.g
        bob_public_key = bob_private_key * curve.g

        k = int(self.ephemeral_key, 16)
        self.ephemeral_public_key = k * curve.g

        # Convert ciphertext to bytes
        ciphertext_bytes = bytes.fromhex(self.ciphertext)

        # Perform decryption
        decrypted_message = ecc_decrypt(ciphertext_bytes, self.ephemeral_public_key, self.iv, bob_private_key)
        self.decrypt_label.text = "The message has been decrypted"
        self.decrypted_label.text = f"Decrypted Message: {decrypted_message.decode()}"

    def load_ciphertext_and_keys(self, instance):
        filename1 = join(os.environ["HOME"], "ciphertext.txt")
        filename2 = join(os.environ["HOME"], "private_keys.txt")
        # Load ciphertext from the file
        try:
            # with open('ciphertext.txt', "r") as file:
            with open(filename1, "r") as file:
                self.ciphertext = file.read().strip()
                self.decrypted_label.text = f"Ciphertext loaded: {self.ciphertext}"
                self.ciphertext_input.value = f"{self.ciphertext}"
        except FileNotFoundError:
            self.ciphertext = None
            self.decrypt_label.text = "Ciphertext file not found."

        # Load private keys from the file
        try:
            # with open("private_keys.txt", "r") as file:
            with open(filename2, "r") as file:
                for line in file:
                    if line.startswith("Alice Private Key"):
                        self.alice_private_key = line.split(": ")[1].strip()
                    elif line.startswith("Alice Public Key"):
                        self.alice_public_key = line.split(": ")[1].strip()
                    elif line.startswith("Bob Private Key"):
                        self.bob_private_key = line.split(": ")[1].strip()
                    elif line.startswith("Bob Public Key"):
                        self.bob_public_key = line.split(": ")[1].strip()
                    elif line.startswith("Ephemeral Public Key"):
                        self.ephemeral_key = line.split(': ')[1].strip()
                    elif line.startswith("IV"):
                        self.iv = line.split(": ")[1].strip()
        except FileNotFoundError:
            self.alice_private_key = None
            self.alice_public_key = None
            self.bob_private_key = None
            self.bob_public_key = None
            self.ephemeral_key = None
            self.iv = None

        self.update_inputs()
        self.main_box.remove(self.current_view)
        self.current_view = self.decrypt_view
        self.main_box.add(self.current_view)
        self.main_window.show()

    def update_inputs(self):

        self.alice_private_key_input.value = self.alice_private_key
        self.alice_public_key_input.value = self.alice_public_key
        self.bob_private_key_input.value = self.bob_private_key
        self.bob_public_key_input.value = self.bob_public_key
        self.ephemeral_key_input.value = self.ephemeral_key
        self.iv_input.value = self.iv


def main():
    return aeccap()
