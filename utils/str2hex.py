#!/usr/bin/env python3
"""
Convert a string to hex bytes representation.
There are better ways to do this but this takes 2 seconds.
"""

import sys
import argparse


def string_to_hex(text, separator=''):
    """
    Convert a string to hex bytes.

    Args:
        text: String to convert
        separator: Separator between hex bytes

    Returns:
        Hex string representation
    """
    return separator.join(f'{ord(c):02x}' for c in text)


def main():
    parser = argparse.ArgumentParser(description='Convert string to hex bytes')
    parser.add_argument('string', help='String to convert to hex')
    parser.add_argument('-s', '--separator', default='',
                        help='Separator between hex bytes (default: none)')
    parser.add_argument('-u', '--uppercase', action='store_true',
                        help='Use uppercase hex letters')
    parser.add_argument('-p', '--prefix', action='store_true',
                        help='Add 0x prefix to each byte')

    args = parser.parse_args()

    hex_str = string_to_hex(args.string, args.separator)

    if args.uppercase:
        hex_str = hex_str.upper()

    if args.prefix:
        if args.separator:
            hex_bytes = hex_str.split(args.separator)
            hex_str = args.separator.join(f'0x{b}' for b in hex_bytes)
        else:
            print("Warning: -p/--prefix works best with a separator", file=sys.stderr)
            hex_str = '0x' + hex_str

    print(hex_str)


if __name__ == '__main__':
    main()