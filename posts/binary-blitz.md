# Binary Blitz Writeup

## Introduction
In this writeup, we will explore how to solve the Binary Blitz challenge from a recent CTF competition. This challenge tested our reverse engineering skills and required a deep understanding of binary analysis tools and techniques.

## Challenge Overview
- **Category**: Reverse Engineering
- **Points**: 500
- **Description**: A mysterious binary that requires multiple stages of reverse engineering to uncover its secrets.

## Initial Analysis
First, let's examine the binary structure:
```bash
$ file binary_blitz
binary_blitz: ELF 64-bit LSB executable, x86-64
```

The binary is a standard Linux ELF executable with no obvious signs of packing or obfuscation.

## Static Analysis
Using Ghidra, we identified several interesting functions:

```c
int main() {
    setup_environment();
    check_key();
    validate_input();
    decrypt_flag();
    return 0;
}
```

The `check_key` function contained a complex validation routine:

```c
int check_key(char* input) {
    int sum = 0;
    for(int i = 0; i < strlen(input); i++) {
        sum += (input[i] ^ 0x42) + i;
    }
    return sum == 0x1337;
}
```

## Dynamic Analysis
Running the binary in GDB revealed:
1. Anti-debugging checks in `setup_environment()`
2. Time-based validation in `check_key()`
3. Memory encryption in `decrypt_flag()`

Key breakpoints we used:
```
gdb-peda$ b *check_key+0x45
gdb-peda$ b *decrypt_flag+0x23
```

## Solving the Challenge

```python
from pwn import *

# Set up binary
p = process('./binary_blitz')

# Send crafted key
key = find_key()
p.sendline(key)

# Receive and decrypt flag
enc_flag = p.recvline().strip()
flag = decrypt_flag(enc_flag)
print(f"Flag: {flag.decode()}")
```

## Conclusion
This challenge taught us:
1. The importance of combining static and dynamic analysis
2. Techniques for bypassing anti-debugging
3. Methods for reverse engineering custom encryption
4. The value of writing clean, reusable exploit code

The key insight was recognizing the pattern in the key validation algorithm, which allowed us to work backwards from the target sum to generate a valid key. 