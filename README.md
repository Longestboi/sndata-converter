# sndata-extractor

## **WARNING!!!**
This is my first ever python script there will be bugs and errors; Some of which I may or may not know how to fix.
Moreover, this is essentially my first time putting out code on Github.

### Description:
A python script that can extract both function names and offsets. And puts those functions and offsets into a script for either Ghidra or Ida to use. This prints the script directly to stdout, use output redirection to save the script to a file.

### Usage:
```
sndata-extractor.py [-h] FILE OFFSET -i/-g 
This program only works on extracted .sndata headers and outputs to stdout.
Author: Andrew Long, 2020.
-h                   Display this text
FILE                 The extracted .sndata header from a PS2 game

OFFSET, eg. 0x3d64   The offset below the list of function names that locates
                     the name of the first entry in the list in the OG ELF

-i                   output IDA script

-g                   output Ghidra script (use this with ImportSymbolsScript.py)
```
### Extracting .sndata header from ELF binary:
This script **REQUIRES** the .sndata header to be extracted from the ELF binary. To extract the .sndata header from a PS2 ELF binary, you have to source a copy of the official PS2 SDK. Then find "ee-objcopy" and run the command:
```
./ee-objcopy -O binary -j .sndata REPLACE_ME.elf REPLACE_ME.sndata
```
this will output the .sndata header of a PS2 ELF binary.

### Quirks:
The python script **REQUIRES** -i or -g to be stated; Otherwise, the script will error.
I have not tested the Ida script output, because I don't have Ida; If the Ida script doesn't work, please report it.

### References:
[@diwidog](https://twitter.com/diwidog/status/1188626209560596480) - For originally reversing the .sndata header format.
