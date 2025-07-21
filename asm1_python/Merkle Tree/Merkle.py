import hashlib


# Merkle Tree Implementation
#Citation:
""" 
https://pypi.org/project/multiproof/
https://www.geeksforgeeks.org/dsa/introduction-to-merkle-tree/
https://stackoverflow.com/questions/70316918/how-to-implement-merkle-hash-tree-in-python
https://redandgreen.co.uk/understanding-merkle-trees-in-python-a-step-by-step-guide/python-code/
https://github.com/Tierion/pymerklet tools (library, tried this but couldn't download it)
AI Chatbox
"""


def hash_data(data: str):
    """Hash the input data using SHA-256.
    Hashes the input data using SHA-256 and returns the hexadecimal digest.
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def merkle_tree(transaction_ids):
    """Create a Merkle tree and return the root and all levels of the tree.
    It is noted that, in this question we only required to return the Merkle root only. 
    """
    if transaction_ids not in transaction_ids:
        return None

    # Hash all transaction IDs to form the leaf nodes
    nodes = [hash_data(item) for item in transaction_ids]
    tree_levels = [nodes]

    # Build the tree upwards
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else left  
            combined = hash_data(left + right)
            next_level.append(combined)
        nodes = next_level
        tree_levels.append(nodes)

    merkle_root = nodes[0]
    return merkle_root, tree_levels

def generate_merkle_proof(data, target_data):
    """
    Generate a Merkle proof for a given transaction ID.
    Merkle Proof is a method that is used to find if a certain data exists without having to know the entire tree strucutre. 
    """
    merkle_tree_proof = []
    if target_data not in data:
        return None
    
    _, tree_levels = merkle_tree(data)
    
    index = data.index(target_data)
    current_index = index
    
    for levels in tree_levels[:-1]: # Skip the root level
        is_right = current_index % 2
        pair_index = current_index - 1 if is_right else current_index + 1 # Formula to determine the new index of the pair node
        """
        This 3 lines of code determine if the current index is even or odd. 
        If the index is even, it means the current node is a left child (value will be 0), and if it is odd (value will be 1), it is a right child. 
        """
        
        if pair_index >= len(levels):
            pair_hash = levels[current_index]
        else:
            pair_hash = levels[pair_index]  
        direction = 'left' if is_right else 'right'
        
        current_index = current_index // 2
        """ 
        The direction is determined by whether the current index is even or odd.
        This is to update the index of the current data in the tree.
        Every time we tranverse up the tree, the index are halved. 
        Hence why we need to update the index of the current level.
        """
        # Append the pair hash and direction to the proof
        merkle_tree_proof.append((pair_hash, direction))
        
    return merkle_tree_proof


def verify_merkle_proof(data,merkle_proof, merkle_root):
    """
    Verify a Merkle proof for a given transaction ID.
    Verify Merkle Proof is 1 step further of a Merkle Proof. Its purpose is to validate and verifiy.
    """
    
    if data not in hashed_data:
        return None
    
    hashed_data = hash_data(data) 
    
    for sibling_hash, direction in merkle_proof:
        if direction == 'left':
            current_hash = hash_data(sibling_hash + current_hash)
        else:
            current_hash = hash_data(current_hash + sibling_hash)
            
    return current_hash == merkle_root
   
    

# Mock data for testing
list_data = ["transaction_id_1", "transaction_id_2", "transaction_id_3", "transaction_id_4"]


#Merkle root
root, _ = merkle_tree(list_data)
# print("Merkle Root:", root)

#Merkle Proof
proof = generate_merkle_proof(list_data, "transaction_id_2")
# print("Merkle Proof for tx4:", proof)

#Verify Merkle Proof
is_valid = verify_merkle_proof("transaction_id_3", proof, root)
print("Is the proof valid?", is_valid)