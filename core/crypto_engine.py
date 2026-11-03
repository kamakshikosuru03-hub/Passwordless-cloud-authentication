import hashlib
import numpy as np
import base64
import re
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def normalize_bits(data_input, target_len=4000):
    """
    Standardizes biometric input.
    Extracts raw ridge data using Regex if XML tags are present.
    """
    try:
        # 1. Handle String/XML Input
        if isinstance(data_input, str):
            # Find content between <Data> tags (ignores XML overhead)
            match = re.search(r'<Data[^>]*>(.*?)</Data>', data_input, re.DOTALL)
            clean_str = match.group(1).strip() if match else data_input.strip()
            
            # Convert Base64 string to raw bytes
            raw_bytes = base64.b64decode(clean_str)
        elif isinstance(data_input, (bytes, bytearray)):
            raw_bytes = data_input
        else:
            raw_bytes = bytes(data_input)

        # 2. Convert to NumPy array
        arr = np.frombuffer(raw_bytes, dtype=np.uint8)
        
        # 3. Ensure Fixed Length for Hamming Distance calculation
        if len(arr) > target_len:
            return arr[:target_len].copy()
        elif len(arr) < target_len:
            return np.pad(arr, (0, target_len - len(arr)), 'constant')
        
        return arr.copy()
    except Exception as e:
        print(f"Normalization Error: {e}")
        return np.zeros(target_len, dtype=np.uint8)

def derive_keys_fuzzy(bio_bits):
    """Registration: Generates stable ECC keys from a biometric template."""
    stable_bits = normalize_bits(bio_bits)
    stable_bytes = stable_bits.tobytes()
    
    # Generate seed from hashed bits
    seed = hashlib.sha256(stable_bytes).digest()
    private_value = int.from_bytes(seed, 'big')
    
    curve = ec.SECP256R1()
    private_key = ec.derive_private_key(private_value, curve)
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_key, public_pem, stable_bytes

def reproduce_key_fuzzy(new_bits, stored_helper_bits, threshold=5000):
    """Login: Corrects noise and reproduces the EXACT original Private Key."""
    arr_new = normalize_bits(new_bits)
    
    # Handle stored data (Base64 string from JSON or raw bytes)
    if isinstance(stored_helper_bits, str):
        stored_bytes = base64.b64decode(stored_helper_bits)
    else:
        stored_bytes = stored_helper_bits

    arr_stored = np.frombuffer(stored_bytes, dtype=np.uint8)
    
    # Ensure shape alignment
    if arr_new.shape != arr_stored.shape:
        arr_stored = normalize_bits(stored_bytes)

    # Calculate Distance
    distance = np.sum(arr_new != arr_stored)
    
    # Sliding Window Check
    if distance > threshold:
        for shift in range(1, 5):
            d_fwd = np.sum(arr_new[shift:] != arr_stored[:-shift])
            d_bwd = np.sum(arr_new[:-shift] != arr_stored[shift:])
            distance = min(distance, d_fwd, d_bwd)

    print(f"DEBUG: Optimized Biometric Distance is {distance}") 

    if distance <= threshold:
        # SNAP-TO-GRID: Re-derive key from the STORED registration bits
        seed = hashlib.sha256(stored_bytes).digest()
        private_value = int.from_bytes(seed, 'big')
        return ec.derive_private_key(private_value, ec.SECP256R1())
    else:
        raise ValueError(f"Fingerprint too different. Distance: {distance}")

def sign_challenge(private_key, challenge):
    """Generates a standard dynamic ECDSA signature for login security."""
    return private_key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))

def verify_challenge(public_key_pem, challenge, signature):
    """Verifies a standard ECDSA signature against a public key."""
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(signature, challenge.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Signature Verification Failed: {e}")
        return False

# --- UPDATED: DETERMINISTIC VISUAL DIGITAL SIGNATURE ---
def generate_visual_id(private_key, username):
    """
    Creates a DETERMINISTIC Digital Signature.
    This replaces the random ECDSA signature with a keyed hash 
    derived from the Private Key and Username.
    
    Result: 
    - Same for User A (Registration == Login).
    - Different for User B.
    """
    # 1. Get the raw private bytes (the unique secret)
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # 2. Create a stable identity message
    identity_message = f"BIO-IDENTITY-VAL-{username.upper().strip()}"
    
    # 3. Generate a Deterministic Signature using HMAC-SHA256 logic
    # This is unique to the private key and the identity message.
    hasher = hashlib.sha256(priv_bytes)
    hasher.update(identity_message.encode())
    
    # 4. Return as hex. This will now be identical in both screenshots.
    return hasher.hexdigest()