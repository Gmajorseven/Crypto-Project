## Plan: Bitcoin Key Generator from Binary Entropy

Create a Python application that converts binary entropy into Bitcoin private keys, derives public keys using elliptic curve cryptography (secp256k1), and generates Bitcoin addresses in multiple formats (Legacy P2PKH, SegWit P2WPKH, and Native SegWit Bech32).

### Steps

1. Create `requirements.txt` with necessary dependencies: `ecdsa`, `base58`, `hashlib` (built-in), and optionally `bech32` for address encoding
2. Build `entropy_generator.py` module with functions to validate and c
1. Create `requirements.txt` with necessary dependencies: `ecdsa`, `base58`, `hashlib` (built-in), and optionally `bech32` for address encoding
2. Buildonvert binary strings to 256-bit private keys in hexadecimal format
3. Implement `key_generator.py` module with secp256k1 elliptic curve functions to derive compressed/uncompressed public keys from private keys
4. Create `address_generator.py` module with Bitcoin address generation functions supporting P2PKH (Legacy), P2WPKH (SegWit), and Bech32 (Native SegWit) formats
5. Build `main.py` as the command-line interface to accept binary input and display the complete key chain (private key, public key, addresses)
6. Add `README.md` with usage examples, security warnings about handling private keys, and explanation of each address type

### Further Considerations

1. **Entropy source**: Should the app accept user-provided binary strings, generate random entropy, or support both input methods?
2. **Address formats**: Include all three Bitcoin address types (P2PKH, P2WPKH-P2SH, Bech32) or focus on specific formats?
3. **Security**: Add warnings about secure key storage and disclaimer that this is for educational purposes only?
4. **Key format output**: Display keys in WIF (Wallet Import Format) in addition to hex, or hex only?

