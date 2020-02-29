#! /usr/bin/env python3
"""Read an ascii binary string from stdin and convert to ascii text."""
import sys


data = sys.stdin.read().replace(" ", "")
n = int("0b" + data, 2)
print(n.to_bytes((n.bit_length() + 7) // 8, "big").decode())
