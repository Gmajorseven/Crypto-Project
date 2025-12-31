#!/usr/bin/env python3
"""
Bitcoin Key Generator from Binary Entropy
Main CLI Application
"""

import sys
import argparse
from entropy_generator import binary_to_private_key, generate_random_entropy
from key_generator import private_key_to_public_key, private_key_to_wif
from address_generator import (
    public_key_to_p2pkh_address,
    public_key_to_p2wpkh_p2sh_address,
    public_key_to_bech32_address
)


def print_separator():
    """Print a visual separator"""
    print("=" * 80)


def print_key_chain(private_key_hex: str, testnet: bool = False):
    """
    Generate and display complete Bitcoin keychain

    Args:
        private_key_hex: Private key in hexadecimal format
        testnet: Whether to generate testnet addresses
    """
    network = "Testnet" if testnet else "Mainnet"

    print_separator()
    print(f"BITCOIN KEY CHAIN ({network})")
    print_separator()

    # Private Key
    print("\n📌 PRIVATE KEY:")
    print(f"   Hex: {private_key_hex}")

    # WIF formats
    wif_compressed = private_key_to_wif(private_key_hex, compressed=True, testnet=testnet)
    wif_uncompressed = private_key_to_wif(private_key_hex, compressed=False, testnet=testnet)
    print(f"   WIF (Compressed):   {wif_compressed}")
    print(f"   WIF (Uncompressed): {wif_uncompressed}")

    # Public Keys
    print("\n🔑 PUBLIC KEYS:")
    public_key_compressed = private_key_to_public_key(private_key_hex, compressed=True)
    public_key_uncompressed = private_key_to_public_key(private_key_hex, compressed=False)
    print(f"   Compressed:   {public_key_compressed}")
    print(f"   Uncompressed: {public_key_uncompressed}")

    # Addresses - using compressed public key (standard)
    print("\n🏠 ADDRESSES (from Compressed Public Key):")

    # P2PKH (Legacy)
    p2pkh_address = public_key_to_p2pkh_address(public_key_compressed, testnet=testnet)
    print(f"   P2PKH (Legacy):          {p2pkh_address}")

    # P2WPKH-P2SH (SegWit wrapped)
    p2wpkh_p2sh_address = public_key_to_p2wpkh_p2sh_address(public_key_compressed, testnet=testnet)
    print(f"   P2WPKH-P2SH (SegWit):    {p2wpkh_p2sh_address}")

    # Bech32 (Native SegWit)
    bech32_address = public_key_to_bech32_address(public_key_compressed, testnet=testnet)
    print(f"   Bech32 (Native SegWit):  {bech32_address}")

    print_separator()
    print("\n⚠️  WARNING: Keep your private key secure! Anyone with access to it can")
    print("   control your Bitcoin. This tool is for educational purposes only.")
    print_separator()


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Generate Bitcoin keys and addresses from binary entropy',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Generate from binary string
  python main.py --binary "1010101010101010..."
  
  # Generate from random entropy
  python main.py --random
  
  # Generate for testnet
  python main.py --random --testnet
  
  # Read binary from file
  python main.py --file entropy.txt
        '''
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-b', '--binary',
        type=str,
        help='Binary string (256 bits recommended)'
    )
    input_group.add_argument(
        '-r', '--random',
        action='store_true',
        help='Generate random 256-bit entropy'
    )
    input_group.add_argument(
        '-f', '--file',
        type=str,
        help='Read binary string from file'
    )

    parser.add_argument(
        '-t', '--testnet',
        action='store_true',
        help='Generate testnet addresses (default: mainnet)'
    )

    parser.add_argument(
        '--bits',
        type=int,
        default=256,
        help='Number of bits for random generation (default: 256)'
    )

    args = parser.parse_args()

    try:
        # Get binary entropy
        if args.random:
            print(f"Generating {args.bits} bits of random entropy...")
            binary_str = generate_random_entropy(args.bits)
            print(f"Binary: {binary_str[:64]}..." if len(binary_str) > 64 else f"Binary: {binary_str}")
        elif args.file:
            print(f"Reading binary from file: {args.file}")
            with open(args.file, 'r') as f:
                binary_str = f.read().strip()
        else:
            binary_str = args.binary

        # Convert to private key
        private_key_hex = binary_to_private_key(binary_str)

        # Generate and display keychain
        print_key_chain(private_key_hex, testnet=args.testnet)

    except ValueError as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

