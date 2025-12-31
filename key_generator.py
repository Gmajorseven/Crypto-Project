"""
Key Generator Module
Generate Bitcoin public keys from private keys using secp256k1
"""

import hashlib
import ecdsa


def private_key_to_public_key(private_key_hex: str, compressed: bool = True) -> str:
    """
    Derive public key from private key using secp256k1 elliptic curve
    
    Args:
        private_key_hex: Private key in hexadecimal format (64 characters)
        compressed: Whether to return compressed public key (default True)
        
    Returns:
        str: Public key in hexadecimal format
    """
    # Convert hex private key to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Create signing key from private key
    signing_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    
    # Get verifying key (public key)
    verifying_key = signing_key.get_verifying_key()
    
    # Get public key bytes
    public_key_bytes = verifying_key.to_string()
    
    # public_key_bytes contains x and y coordinates (32 bytes each)
    x = int.from_bytes(public_key_bytes[:32], byteorder='big')
    y = int.from_bytes(public_key_bytes[32:], byteorder='big')
    
    if compressed:
        # Compressed format: 02/03 prefix + x coordinate
        # 02 if y is even, 03 if y is odd
        prefix = '02' if y % 2 == 0 else '03'
        public_key_hex = prefix + format(x, '064x')
    else:
        # Uncompressed format: 04 prefix + x + y coordinates
        public_key_hex = '04' + format(x, '064x') + format(y, '064x')
    
    return public_key_hex


def private_key_to_wif(private_key_hex: str, compressed: bool = True, testnet: bool = False) -> str:
    """
    Convert private key to Wallet Import Format (WIF)
    
    Args:
        private_key_hex: Private key in hexadecimal format
        compressed: Whether the corresponding public key is compressed
        testnet: Whether to use testnet prefix (default False for mainnet)
        
    Returns:
        str: Private key in WIF format
    """
    import base58
    
    # Mainnet prefix: 0x80, Testnet prefix: 0xEF
    prefix = b'\xef' if testnet else b'\x80'
    
    # Start with prefix + private key
    private_key_bytes = bytes.fromhex(private_key_hex)
    extended_key = prefix + private_key_bytes
    
    # Add compression flag if compressed
    if compressed:
        extended_key += b'\x01'
    
    # Perform double SHA-256 hash
    hash1 = hashlib.sha256(extended_key).digest()
    hash2 = hashlib.sha256(hash1).digest()
    
    # Take first 4 bytes as checksum
    checksum = hash2[:4]
    
    # Append checksum and encode in Base58
    wif = base58.b58encode(extended_key + checksum).decode('utf-8')
    
    return wif

