"""
Address Generator Module
Generate Bitcoin addresses from public keys
"""

import hashlib
import base58


def hash160(data: bytes) -> bytes:
    """
    Perform RIPEMD-160(SHA-256(data))
    
    Args:
        data: Input bytes
        
    Returns:
        bytes: Hash160 result
    """
    sha256_hash = hashlib.sha256(data).digest()
    ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
    return ripemd160_hash


def public_key_to_p2pkh_address(public_key_hex: str, testnet: bool = False) -> str:
    """
    Generate Legacy P2PKH (Pay-to-Public-Key-Hash) address
    
    Args:
        public_key_hex: Public key in hexadecimal format
        testnet: Whether to use testnet prefix (default False for mainnet)
        
    Returns:
        str: P2PKH Bitcoin address starting with '1' (mainnet) or 'm'/'n' (testnet)
    """
    # Convert public key to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Perform Hash160
    hash160_result = hash160(public_key_bytes)
    
    # Add version byte (0x00 for mainnet, 0x6F for testnet)
    version = b'\x6f' if testnet else b'\x00'
    versioned_hash = version + hash160_result
    
    # Calculate checksum (first 4 bytes of double SHA-256)
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    
    # Encode in Base58
    address = base58.b58encode(versioned_hash + checksum).decode('utf-8')
    
    return address


def public_key_to_p2wpkh_p2sh_address(public_key_hex: str, testnet: bool = False) -> str:
    """
    Generate SegWit P2WPKH-P2SH (Pay-to-Witness-Public-Key-Hash wrapped in P2SH) address
    
    Args:
        public_key_hex: Compressed public key in hexadecimal format
        testnet: Whether to use testnet prefix (default False for mainnet)
        
    Returns:
        str: P2WPKH-P2SH address starting with '3' (mainnet) or '2' (testnet)
    """
    # Convert public key to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Perform Hash160 on public key
    pubkey_hash = hash160(public_key_bytes)
    
    # Create witness program (OP_0 + 20-byte pubkey hash)
    # OP_0 = 0x00, followed by push of 20 bytes (0x14)
    witness_program = b'\x00\x14' + pubkey_hash
    
    # Hash160 of witness program
    script_hash = hash160(witness_program)
    
    # Add version byte (0x05 for mainnet P2SH, 0xC4 for testnet)
    version = b'\xc4' if testnet else b'\x05'
    versioned_hash = version + script_hash
    
    # Calculate checksum
    checksum = hashlib.sha256(hashlib.sha256(versioned_hash).digest()).digest()[:4]
    
    # Encode in Base58
    address = base58.b58encode(versioned_hash + checksum).decode('utf-8')
    
    return address


def bech32_polymod(values):
    """Bech32 checksum polymod operation"""
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP for Bech32 checksum calculation"""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp, data):
    """Create Bech32 checksum"""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data):
    """Encode data in Bech32 format"""
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([charset[d] for d in combined])


def convert_bits(data, from_bits, to_bits, pad=True):
    """Convert between bit groups"""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return ret


def public_key_to_bech32_address(public_key_hex: str, testnet: bool = False) -> str:
    """
    Generate Native SegWit Bech32 (P2WPKH) address
    
    Args:
        public_key_hex: Compressed public key in hexadecimal format
        testnet: Whether to use testnet prefix (default False for mainnet)
        
    Returns:
        str: Bech32 address starting with 'bc1' (mainnet) or 'tb1' (testnet)
    """
    # Convert public key to bytes
    public_key_bytes = bytes.fromhex(public_key_hex)
    
    # Perform Hash160
    pubkey_hash = hash160(public_key_bytes)
    
    # Convert to 5-bit groups for Bech32
    # Witness version 0
    witness_version = 0
    witness_program = convert_bits(pubkey_hash, 8, 5)
    
    if witness_program is None:
        raise ValueError("Failed to convert bits for Bech32 encoding")
    
    # HRP (Human Readable Part)
    hrp = 'tb' if testnet else 'bc'
    
    # Encode in Bech32
    address = bech32_encode(hrp, [witness_version] + witness_program)
    
    return address

