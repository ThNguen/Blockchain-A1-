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
def generate_keys():
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
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used public exponent
        key_size=2048,           # 2048 bits is a common key size for RSA
    )
    public_key = private_key.public_key() 
    
    return private_key, public_key




# 1.2 Print the public and private keys in PEM format.
""" 
PEM (Privacy-Enhanced Mail) refers to a base64 encoded format that is commonly used to represent 
cryptographic keys and certificates.
"""

# Public key in PEM format
def pem_format_key(private_key, public_key):
    
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

    pem_public_key = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return pem_private_key,pem_public_key



# 1.3 Raw form 
def get_raw_key_values(private_key):
    """ 
    This function here returns the Public Key and Private Key in its Raw Form.
    This is to compare with the PEM format to see the differences between the two. 
    """
    private_numbers = private_key.private_numbers()
    public_numbers = private_numbers.public_numbers

    return {
        "Modulus (n)": public_numbers.n,
        "Public Exponent (e)": public_numbers.e,
        "Private Exponent (d)": private_numbers.d,
        "Prime 1 (p)": private_numbers.p,
        "Prime 2 (q)": private_numbers.q
    }
# 2. Take message as input from the user.
def user_input():
    """
    Convert the message to bytes using utf-8 encoding.
    This is necessary because RSA encryption works with byte data.
    Reason: 
    - Simply because RSA operates on byte data, and encoding ensures that the string is
    converted to a format suitable for encryption. 
    - Computer doesn't understand strings directly, it works with bytes.

    """
    message = input("Please enter enter a message: ").encode('utf8') 
    return message



# 3. Sign the message using the private key.
def sign_message(message: bytes, private_key):
    """Sign a message using the private key."""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


""" 
Sign the message using the private key and SHA-256 as its hashing algorithm.
The purpose of having a digital signature is to ensure the integrity and authenticity of the message.
---------------------------------------------------------

The fake_signature is for me to demonstrate the output a different signature and try to verify it against the original message. 

"""

# 4. Verify the signature using the public key (Using the real signature).
def verifiy_signature(public_key, message: bytes, signature: bytes, type = "real"):
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
        return(f"[{type.capitalize} Signature] Verification: Valid ")
    except Exception:
        return(f"[{type.capitalize} Signature] Verification: Invalid ")
        
        
def simulate(fake_signature = "N"):
    # Generate Public Key and Private
    priv_key, pub_key = generate_keys()
    pem_priv, pem_pub = pem_format_key(priv_key, pub_key)

    # Keys raw form 
    raw_keys = get_raw_key_values(priv_key)
    # Take user input
    message = user_input()
    
    #Sign message - 1
    real_sign = sign_message(message, priv_key)
    
    #Sign message - 2
    real_sign_2 = sign_message(message, priv_key)
    
    #Encode the sign message for illustrate purposes -1 
    encode_real_sign = base64.b64encode(real_sign).decode('utf-8')
    
    #Encode the sign message for illustrate purposes - 2
    encode_real_sign_2 = base64.b64encode(real_sign_2).decode('utf-8')
    
    
    output = {
        "Raw Public Key Components": {
            "Modulus (n)": raw_keys["Modulus (n)"],
            "Public Exponent (e)": raw_keys["Public Exponent (e)"]
        },
        "Raw Private Key Components": {
            "Private Exponent (d)": raw_keys["Private Exponent (d)"],
            "Prime 1 (p)": raw_keys["Prime 1 (p)"],
            "Prime 2 (q)": raw_keys["Prime 2 (q)"]
        },
        "Public Key PEM": pem_pub,
        "Private Key PEM": pem_priv,
        "Digital Signature (1)": encode_real_sign,
        "Digital Signature (2)": encode_real_sign_2,
        "Original Message": message.decode('utf-8'),
        "Real Signature Verification": verifiy_signature(pub_key, message, real_sign, type="real")
    }

    
     
    if fake_signature.lower() == "y":
        fake_msg = b"Fake Hello"
        output["Fake Signature Verification "] = verifiy_signature(pub_key, fake_msg, real_sign, type="fake")
    
    return output


# Run program
ask_input = input("Do you want to run fake signature simulation? (y/n) ")
result = simulate(fake_signature=ask_input)
for key, value in result.items():
    print(f"{key}: {value}")