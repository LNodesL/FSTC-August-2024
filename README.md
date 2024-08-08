# FSTC-August-2024
Fallen Scantime Crypter: August 2024

## Notes

Download encrypted file from URL 

Decrypt the file & save to disk

Loads ntdll from disk

Maps sections between new ntdll & hooked ntdll / unhooks

Runs PE from download in a new process


## Future Development

- save to tmp file instead of to cwd

- allow builder to modify the final FSTC.exe program's resources or other data to make it easier to build for a new payload/URL without re-compiling
