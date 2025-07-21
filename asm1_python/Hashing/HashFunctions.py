import hashlib
import string
from scipy.spatial import distance
import random

#Citations:
"""
https://www.geeksforgeeks.org/python/python-hash-method/
https://www.youtube.com/watch?v=jrVj1D9AOB0
https://docs.scipy.org/doc/scipy/reference/generated/scipy.spatial.distance.hamming.html
https://www.geeksforgeeks.org/dsa/hamming-distance-two-strings/
https://claresloggett.github.io/python_workshops/improved_hammingdist.html
https://www.hideipvpn.com/vpn/what-is-a-preimage-attack/#:~:text=A%20preimage%20attack%20is%20a,against%20malicious%20attacks%20like%20these.
AI Chatbox
"""
#Programming Task: Demonstrating Hash Function Properties

#Hash function to hash input data using SHA-256
    
# 1. Takes an arbitrary string as input from the user.
def hash_data(data: str):
    """Hash the input data using SHA-256.
    Hashes the input data using SHA-256 and returns the hexadecimal digest
    """   
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
 
 
# Take user input and output as hash
def user_input_password() -> str:
    """Prompt user for input and return the hashed value."""
    
    user_input = input("Enter your data to hash: ")
    hashed_value = hash_data(user_input)
    print(f"Hashed value: {hashed_value}") 


def count_hamming(hash1, hash2):
    count = 0;
    for i in range(len(hash1)):
        if hash1[i] != hash2[i]:
            count += 1
    return count

# Demonstrates the avalanche effect - modified input leads to a completely different hash
def avalanche_effect_demo():
    """Demonstrate the avalanche effect with a slight change in input."""
    original_input = input("Enter original input: ")
    modified_input = original_input.upper()  # Slight modification to the original input

    original_hash = hash_data(original_input)
    modified_hash = hash_data(modified_input)

    # Print out the user input
    print("Original user input:", original_input)
    # Print out the modified input
    print("Modified user input:", modified_input)
    
    # Print out the hashes for original and modified input
    print("Original hash:", original_hash)
    print("Modified hash:", modified_hash)
    
    #Count hamming
    print("Hamming distance between original and modified hash:", count_hamming(original_input, modified_input))
    

#Calculate hamming distance between two hashes
def hamming_distance(orginal: str, modified: str) -> int:
    """
    Calculate the Hamming distance between two hashes.
    Hamming Distance is concept that measures the differences between two strings.
    The differents are actually compared it in binary form so : 0s and 1s.
    So even if 1 single letter is different can also affect the hamming distance of it. 
    
    """
    if len(orginal) != len(modified):
        raise ValueError("Hashes must be of the same length")
    
    return sum(el1 != el2 for el1, el2 in zip(orginal, modified))


""" 
In cryptography, the avalanche effect describes 
how a small change in the input (like a single bit flip in the plaintext or key) 
of a cryptographic function (like a block cipher or hash function) leads to a large, 
seemingly unrelated change in the output. This effect is highly desirable because it 
makes the cryptographic algorithm more robust against attacks, particularly statistical analysis and differential cryptanalysis.
"""

# Demonstrate difficulty of finding a pre-image
def find_preimage(original_string, max_attempts = 10000): 
    total_attempts = 0
    hashed_value = hash_data(original_string)
    
    """
    Preimage refers to the input of a cryptogtaphic hash function that will return a specific output or hash value. 
    
    Attempt to find a pre-image for the given hash. 
    Bruteforce search for a string that hashes to the target hash.
    
    So for this function, it purpose is to find the orignal input that produces a specific hash output.
    The use for this is to actually determine the difficulty in the preimage. Usually it is a very long process. 
    Finding preimage is a method that miners uses for Bitcoin Mining. 
    """
    
    for _ in range(max_attempts):
        guess = ''.join(random.choices(string.ascii_letters + string.digits, k = len(original_string)))
        # Generate a random string of the same length as the original string
        if hash_data(guess) == hashed_value:
            return guess, total_attempts
        total_attempts += 1
    return None, total_attempts
    
    
original_string, attempt_count  = find_preimage("blockchain")

# Execute the pre-image finding function
print("\nTarget string:", original_string)
print("Target hash:", original_string)

user_input_password()

# print("Pre-image found:", original_string if original_string else "Not found")
# print("Total attempts:", attempt_count)
