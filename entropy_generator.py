"""
Entropy Generator Module
Converts binary entropy to Bitcoin private keys
"""


def validate_binary_string(binary_str: str) -> bool:
    """
    Validate that the input string contains only binary digits (0 and 1)
    
    Args:
        binary_str: String to validate
        
    Returns:
        bool: True if valid binary string, False otherwise
    """
    return all(bit in '01' for bit in binary_str)


def binary_to_private_key(binary_str: str) -> str:
    """
    Convert binary string to 256-bit private key in hexadecimal format
    
    Args:
        binary_str: Binary string (256 bits recommended for Bitcoin)
        
    Returns:
        str: Hexadecimal private key
        
    Raises:
        ValueError: If binary string is invalid or too long
    """
    # Remove whitespace
    binary_str = binary_str.replace(' ', '').replace('\n', '').replace('\t', '')
    
    # Validate binary string
    if not validate_binary_string(binary_str):
        raise ValueError("Invalid binary string. Only '0' and '1' characters are allowed.")
    
    # Check length
    if len(binary_str) > 256:
        raise ValueError(f"Binary string too long ({len(binary_str)} bits). Maximum is 256 bits.")
    
    if len(binary_str) == 0:
        raise ValueError("Binary string cannot be empty.")
    
    # Pad to 256 bits if shorter
    if len(binary_str) < 256:
        binary_str = binary_str.zfill(256)
    
    # Convert to integer then to hex
    private_key_int = int(binary_str, 2)
    
    # Ensure private key is valid (not zero and less than secp256k1 order)
    secp256_k1_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    if private_key_int == 0:
        raise ValueError("Private key cannot be zero.")
    
    if private_key_int >= secp256_k1_order:
        raise ValueError("Private key exceeds secp256k1 curve order.")
    
    # Convert to 64-character hex string (32 bytes)
    private_key_hex = format(private_key_int, '064x')
    
    return private_key_hex


def generate_random_entropy(bits: int = 256) -> str:
    """
    Generate random binary entropy
    
    Args:
        bits: Number of bits to generate (default 256)
        
    Returns:
        str: Random binary string
    """
    import secrets
    
    if bits <= 0 or bits > 256:
        raise ValueError("Bits must be between 1 and 256")
    
    # Generate random bytes
    num_bytes = (bits + 7) // 8
    random_bytes = secrets.token_bytes(num_bytes)
    
    # Convert to binary string
    binary_str = ''.join(format(byte, '08b') for byte in random_bytes)
    
    # Trim to exact bit length
    return binary_str[:bits]

