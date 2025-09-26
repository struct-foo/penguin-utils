#!/usr/bin/env python3
"""
Find the file offset of a given string in a file.
Needed for yolo patching string files since there is
currently only a binary patch option.

eg.

```yaml
static_files:
  /etc/init.d/rcS:
    type: binary_patch
    # using find_offset.py "cos &"
    file_offset: 2136
    # ./str2hex.py "httpd -f -v -h /web/"
    hex_bytes: "6874747064202d66202d76202d68202f7765622f"
```
"""

import sys
import argparse


def find_string_offset(file_path, search_string):
    """
    Find the offset of a string in a file.

    Args:
        file_path: Path to the file to search
        search_string: String to find

    Returns:
        File offset of the first occurrence, or -1 if not found
    """
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        # Convert search string to bytes if needed
        if isinstance(search_string, str):
            search_bytes = search_string.encode('utf-8')
        else:
            search_bytes = search_string

        offset = content.find(search_bytes)
        return offset

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found", file=sys.stderr)
        return -1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return -1


def main():
    parser = argparse.ArgumentParser(description='Find the file offset of a string in a file')
    parser.add_argument('file', help='File to search in')
    parser.add_argument('string', help='String to search for')
    parser.add_argument('-x', '--hex', action='store_true',
                        help='Interpret search string as hex bytes (e.g., "41424344" for "ABCD")')

    args = parser.parse_args()

    if args.hex:
        # Convert hex string to bytes
        try:
            search_string = bytes.fromhex(args.string)
        except ValueError:
            print(f"Error: Invalid hex string '{args.string}'", file=sys.stderr)
            sys.exit(1)
    else:
        search_string = args.string

    offset = find_string_offset(args.file, search_string)

    if offset == -1:
        print(f"String not found in file")
        sys.exit(1)
    else:
        print(f"Found at offset: {offset} (0x{offset:x})")


if __name__ == '__main__':
    main()