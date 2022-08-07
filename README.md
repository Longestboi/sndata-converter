# sndata-onverter

###### Preface:
###### I've entirely re-written this program so it can accurately extract debug symbols and support both SNR1 & SNR2 sndata section header formats. As well as creating documentation of the section header format.

### Description:
A python script that can extract both function names and offsets. And puts those functions and offsets into a script for either Ghidra or Ida to use.

I still haven't tested this with IDA, so report and problems if there are any.

### Usage:
```
usage: sndata-converter PS2-ELF Output [options]

Extract Debug Symbols from PS2 ELF files the contain a .sndata section
header

positional arguments:
  PS2 ELF       Input file
  Output        Output file

optional arguments:
  -h, --help    show this help message and exit
  -i, --ida     Output Ida Python script
  -g, --ghidra  Output script for use with Ghidra's 'ImportSymbolsScript.py'

```

### References:
[@diwidog](https://twitter.com/diwidog/status/1188626209560596480) - For originally reversing the .sndata header format.
