import os
import hashlib
import hmac
import binascii
from hashlib import pbkdf2_hmac
import ecdsa

# Step 1: Generate a random 128-bit (16-byte) string (entropy)
def generate_random_entropy():
    return os.urandom(16)

# Step 2: Calculate the SHA-256 hash and extract the first 4 bits (checksum)
def get_checksum(entropy):
    hash_digest = hashlib.sha256(entropy).hexdigest()
    first_byte = int(hash_digest[:2], 16)  # Convert the first two hex characters to an integer (first byte)
    return format(first_byte, '08b')[:4]  # Get the first 4 bits

# Step 3: Append the checksum to the entropy and convert to binary
def entropy_with_checksum(entropy):
    checksum = get_checksum(entropy)
    entropy_bits = ''.join(format(byte, '08b') for byte in entropy)
    return entropy_bits + checksum

# Step 4: Split the binary string into 11-bit sections
def split_into_parts(binary_string):
    return [binary_string[i:i+11] for i in range(0, len(binary_string), 11)]

# Step 5: Convert binary parts to words using the BIP-39 wordlist
def convert_parts_to_words(parts):
    words = []
    with open('word_list.txt', 'r') as file:
        dictionary = file.read().splitlines()
    
    for part in parts:
        number = int(part, 2)  # Convert binary part to integer
        words.append(dictionary[number])
    
    return words

# Step 6: Convert the mnemonic phrase to a seed using PBKDF2-HMAC-SHA512
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = "mnemonic" + passphrase
    
    # Use PBKDF2-HMAC-SHA512 to derive the seed
    seed = pbkdf2_hmac(
        'sha512',                        
        mnemonic.encode('utf-8'),        
        salt.encode('utf-8'),            
        2048,                            
        64                               
    )
    
    # Return the seed as a byte array
    return seed

# Step 7: Derive the Master Private Key and Chain Code from the seed
def derive_master_key_and_chain_code(seed: bytes) -> (str, str):
    hmac_key = b"Bitcoin seed"  # Key for HMAC-SHA512
    hmac_result = hmac.new(hmac_key, seed, hashlib.sha512).digest()  # HMAC-SHA512
    
    # Split the HMAC result into 32-byte parts
    master_private_key = hmac_result[:32]  # First 32 bytes
    master_chain_code = hmac_result[32:]   # Last 32 bytes
    
    # Return both as hex strings
    return binascii.hexlify(master_private_key).decode(), binascii.hexlify(master_chain_code).decode()

# Step 8: Derive the Master Public Key from the Master Private Key
def derive_master_public_key(master_private_key: str) -> str:
    private_key_bytes = binascii.unhexlify(master_private_key)  # Convert the hex private key to bytes
    
    # Use the secp256k1 curve to generate the public key
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key  # Get the corresponding public key
    
    # The public key is a point on the elliptic curve, we encode it as compressed form
    public_key_bytes = vk.to_string("compressed")  # Compressed public key (33 bytes)
    
    return binascii.hexlify(public_key_bytes).decode()

# Step 9: Compare the original private key with the recalculated private key
def compare_private_keys(original_private_key: str, recalculated_private_key: str):
    if original_private_key == recalculated_private_key:
        print("The private keys are identical.")
    else:
        print("The private keys are different.")

# Main function to generate a private key and its mnemonic phrase, then derive the seed
if __name__ == "__main__":
    # Generate random 128-bit entropy
    entropy = generate_random_entropy()
    
    # Append checksum to the entropy
    entropy_bits_with_checksum = entropy_with_checksum(entropy)
    
    # Split the entropy + checksum into 11-bit parts
    parts = split_into_parts(entropy_bits_with_checksum)
    
    # Convert parts to mnemonic words
    mnemonic_words = convert_parts_to_words(parts)
    
    # Join words to form the mnemonic phrase
    mnemonic_phrase = ' '.join(mnemonic_words)
    
    # Derive the seed from the mnemonic phrase
    passphrase = ""  # Optional passphrase
    original_seed = mnemonic_to_seed(mnemonic_phrase, passphrase)
    
    # Derive the master private key and chain code from the original seed
    master_private_key, master_chain_code = derive_master_key_and_chain_code(original_seed)
    
    # Output the original seed, mnemonic, and private key
    print(f"Entropy: {binascii.hexlify(entropy).decode()}")
    print(f"Mnemonic phrase: {mnemonic_phrase}")
    print(f"Original Seed (hex): {binascii.hexlify(original_seed).decode()}")
    print(f"Master Private Key: {master_private_key}")
    print(f"Master Chain Code: {master_chain_code}")
    
    # Derive the master public key from the master private key
    master_public_key = derive_master_public_key(master_private_key)
    print(f"Master Public Key: {master_public_key}")
    
    # Now let's simulate re-importing the mnemonic
    imported_mnemonic = input("Enter the mnemonic phrase to re-import: ")
    
    # Recalculate the seed from the imported mnemonic
    recalculated_seed = mnemonic_to_seed(imported_mnemonic, passphrase)
    
    # Derive the master private key again from the recalculated seed
    recalculated_private_key, _ = derive_master_key_and_chain_code(recalculated_seed)
    
    # Output the recalculated seed and private key
    print(f"Recalculated Seed (hex): {binascii.hexlify(recalculated_seed).decode()}")
    print(f"Recalculated Master Private Key: {recalculated_private_key}")
    
    # Compare the original private key with the recalculated one
    compare_private_keys(master_private_key, recalculated_private_key)

    # Function to derive a child key from the master private key
def derive_child_key(parent_private_key, parent_chain_code, index):
    # Hardened key if index >= 2^31 (set the most significant bit)
    if index >= 0x80000000:
        data = b'\x00' + binascii.unhexlify(parent_private_key) + index.to_bytes(4, 'big')
    else:
        parent_public_key = derive_master_public_key(parent_private_key)
        data = binascii.unhexlify(parent_public_key) + index.to_bytes(4, 'big')
    
    hmac_result = hmac.new(binascii.unhexlify(parent_chain_code), data, hashlib.sha512).digest()
    child_private_key = hmac_result[:32]
    child_chain_code = hmac_result[32:]
    
    return binascii.hexlify(child_private_key).decode(), binascii.hexlify(child_chain_code).decode()

# Example usage:
index = 1  # Example index for child key
child_private_key, child_chain_code = derive_child_key(master_private_key, master_chain_code, index)
print(f"Child Private Key at index {index}: {child_private_key}")
print(f"Child Chain Code at index {index}: {child_chain_code}")




#transforme phras ene liste en utilisant pslit 
#avec les espaces 
#juste une liste de mots 
#word list avec index.off ou equivalent 
#obtention nnombre 
#et transformer en binaire 
#et concatener les mots en binaires et c bon 
#penser retrirer les 4 dernier charateres en binaires 
#ne pas retirer le check sum apres avoir converti en hexadecimal
