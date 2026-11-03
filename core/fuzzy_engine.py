import hashlib
import numpy as np

def generate_stable_secret(bio_bits):
    # Generates a stable hash from the bits
    stable_hash = hashlib.sha256(bio_bits.tobytes()).digest()
    return stable_hash, bio_bits

def reproduce_stable_secret(new_bits, helper_p, threshold=2000):
    # Calculate difference between scans
    # Threshold varies by scanner; Mantra MFS110 usually needs ~2000-3000
    distance = np.sum(new_bits != helper_p)
    
    if distance <= threshold:
        # If similar enough, we use the original registered bits to get the key
        return hashlib.sha256(helper_p.tobytes()).digest()
    else:
        raise ValueError("Fingerprint too different")