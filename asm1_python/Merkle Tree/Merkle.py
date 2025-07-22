import hashlib


# Merkle Tree Implementation
#Citations:
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
    
    Args: 
        data (str): Turn input String into hash value
    
    Returns: 
        str: The output will SHA-256 hash value of the inputted string

    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

def merkle_tree(transaction_ids) -> tuple[str, list[list[str]]]:
    """
    NOTE:  This function here was inspired through a source called "redandgreen.co.uk". Prior to this,
    I didn't know the property and components into create the actual tree itselfs. I also had to used chatGPT to help debug the code.
    Reason is, at first this code didn't work when I tried to generate_merkle_proof, using the output of it. 
    
    AI chatbox was also used to debug.
    
    ---------------------------------------------------------
    
    Create a Merkle tree and return the root and all levels of the tree.
    It is noted that, in this question we only required to return the Merkle root only. 
    
    Args:
        transaction_ids (list): Take in list of transaction_ids
        
    Return:
        tuples: Return the list of transaction_ids in its hash form and the corresponding level to each of the nodes. 
    """
    if not transaction_ids:
        return None, []

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

def generate_merkle_proof(data, target_data) -> list[tuple[str, str]]:
    """
    NOTE: For this function, I had to use AI Chatbox for assistant. There are very little information on the internet that 
    has generate_merkle_proof from scratch. A lot of the merkle_proof used the external libraries, which defeats the purpose of explaining
    the process of builing a merkle tree. 
    
    ---------------------------------------------------------
    
    
    Generate a Merkle proof for a given transaction ID.
    Merkle Proof is a method that is used to find if a certain data exists without having to know the entire tree strucutre. 
    
    Args:
        data (list): This is just data list that will be used, which in this case is the transaction_ids
        target_data (str): The targeted transaction_ids that we want to prove if it exists in the Merkle Tree or not.

    Returns:
        list: List of the sibling hashes and paths. 
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
    
    Args: 
        data (str): The transaction_id that will need to be verify
        merkle_proof (list): The Merkle Proof path
        merkle_root (str): The root hash value
    Returns:
        boolean: This will return true if proof is valid, else return False if invalid
    """
    current_hash = hash_data(data) 
    
    for sibling_hash, direction in merkle_proof:
        if direction == 'left':
            current_hash = hash_data(sibling_hash + current_hash)
        else:
            current_hash = hash_data(current_hash + sibling_hash)
            
    return current_hash == merkle_root
   
    

# Mock data for testing
list_data = ["1", "2", "3", "4"]
targeted_data = "3"

def simulate(transaction_ids, target_id):
    """
    This functions combines other function, so that it can all be run. 
    
    Args:
        transaction_ids (list): List of transactions id
        target_id (str): The transction id that we want to generate merkle proof for.
        
    """
    #Merkle root
    root, _ = merkle_tree(transaction_ids)
    print("Merkle Root")
    print(root)
    
    # Merkle proof
    proof = generate_merkle_proof(transaction_ids, target_id)

    #Merkle Proof 
    print("\n Merkle Proof for '{}' ".format(target_id))
    for i, (sibling, direction) in enumerate(proof):
        print(f"Level {i}: {direction.upper()} sibling hash = {sibling}")
    
    # Prompt user if they want verify their merkle proof
    ask_user = input("Verify the merkle proof? (Y/N)").strip().upper()
    
    if ask_user == "Y":
        verify_id = input("Enter the ID that you want to verifiy: (1, 2, 3 or 4) ").strip()
        is_valid = verify_merkle_proof(verify_id, proof, root)
        if is_valid:
            print("Merkle Proof is valid. ")
        else:
            print("Is Invalid")
    else:
        print("Verify Merkle Proof skipped! ")
        
simulate(list_data, targeted_data)
        



    


