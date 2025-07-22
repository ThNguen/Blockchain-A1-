from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import base64

#Citations:
"""
https://www.youtube.com/watch?v=n0uJsqFGO4k
https://www.youtube.com/watch?v=b2pj0yDhDp4
https://gist.github.com/aellerton/2988ff93c7d84f3dbf5b9b5a09f38ceb
AI Chatbox


"""
# 1.1 Generates a public-private key pair.
private_key = rsa.generate_private_key(
    public_exponent=65537,  # Commonly used public exponent
    key_size=2048,           # 2048 bits is a common key size for RSA
)
""" 
Public_exponent usually refers to the exponent used in the RSA algorithm,
which is typically a small prime number like 65537. Exponent job is to controls how the 
message is encrypted and decrypted. while 
Public exponent: is used in the encryption process, 
Private exponent: is used in the decryption process.

---------------------------------------------------------

Key_size refers to the size of the key in bits. A larger key size generally corresponds
to better security.
"""

# Generate public_key
public_key = private_key.public_key() 

""" 
Generate the public key from the private key as we know that public
key is derived from the private key.
"""

# 1.2 Print the public and private keys in PEM format.
""" 
PEM (Privacy-Enhanced Mail) refers to a base64 encoded format that is commonly used to represent 
cryptographic keys and certificates.
"""

# Public key in PEM format
print("Public Key (PEM):", public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8'))

# Private key in PEM format
print("Private Key (PEM):", private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8'))

"""" 
encoding=serialization.Encoding.PEM: Specifies that the key should be encoded in PEM format.
format=serialization.PublicFormat.SubjectPublicKeyInfo: Specifies the format of the public key.
format=serialization.PrivateFormat.TraditionalOpenSSL: Specifies the format of the private key.
encryption_algorithm=serialization.NoEncryption(): Specifies that the private key should not be encrypted.

---------------------------------------------------------

Purpose of outputting the keys in PEM format:
- PEM format is a widely used format for representing cryptographic keys and certificates.  
- Mainly to present and illustrate the public and private keys in a readable format.
"""


# 2. Take message as input from the user.
message = input("Please enter enter a message: ").encode('utf8') 
print("Message to be signed: ", message)

"""" 
Convert the message to bytes using utf-8 encoding.
This is necessary because RSA encryption works with byte data.
Reason: 
- Simply because RSA operates on byte data, and encoding ensures that the string is
converted to a format suitable for encryption. 
- Computer doesn't understand strings directly, it works with bytes.

"""

# 3. Sign the message using the private key.
real_signature = private_key.sign(message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())

fake_signature = private_key.sign(b"fake message",
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256())

""" 
Sign the message using the private key and SHA-256 as its hashing algorithm.
The purpose of having a digital signature is to ensure the integrity and authenticity of the message.
---------------------------------------------------------

The fake_signature is for me to demonstrate the output a different signature and try to verify it against the original message. 

"""

# 4. Verify the signature using the public key (Using the real signature).
def get_signature(public_key, message, signature, type = "real"):
    """ 
    NOTE: The format of this function, was inspired by chatGPT, as I wanted simulate both real and fake signature without having two block of similar codes, but wasn't sure how to combined them. 
    ---------------------------------------------------------
    
    Signature verify:
    - Verify the signature using the public key, the original message, and the same padding and hashing algorithm.
    
    PSS (Probabilistic Signature Scheme): 
    - Padding scheme for RSA signatures that provides better security.
    - Make signature unique even if the same message is signed multiple times.
    - Often used with RSA.
    
    MGF1 (Mask Generation Function 1):
    - A function used to generate a mask for padding in cryptographic operations.
    - It is part of the PSS algorithm and is used to create a mask for the padding.
    - mgf=padding.MGF1(hashes.SHA256()) means that MGF1 is used with SHA-256 as the hash function.
    
    Testing with fake_signature():
    - The comment part is the fake_signature. It purpose to show the different ouput between a real signature and a fake signature. 
    
    Args:
        public_key: Uses the generated public for verification
        message: The message from user
        signature: The signature that needs to validated
        type: This will identify which type of key will be used for 
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ), # Used for signing and verifying the message
            hashes.SHA256()
        )
        print(f"[{type.capitalize} Signature] Verification: Valid ")
    except Exception:
        print(f"[{type.capitalize} Signature] Verification: Invalid ")
        
# 5. Simulate code
get_signature(public_key, message, real_signature, type="real")
get_signature(public_key, message, fake_signature, type="fake")
    
    