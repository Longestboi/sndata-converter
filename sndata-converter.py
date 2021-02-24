#/usr/bin/env python3

import sys
import os
import string
import struct
import binascii
import argparse
from elftools.elf.elffile import ELFFile

# argparse ops here
argparser = argparse.ArgumentParser(description='Extract Debug Symbols from PS2 ELF files the contain a .sndata section header')
group = argparser.add_mutually_exclusive_group()
group.add_argument("-i", "--ida", help="Output Ida Python script", action="store_true")
group.add_argument("-g", "--ghidra", help="Output script for use with Ghidra's 'ImportSymbolsScript.py'", action="store_true")

argparser.add_argument("PS2 ELF", help="Input file")
argparser.add_argument("Output", help="Output file")

args = argparser.parse_args()

# Some constants
sndataHeaderName = ".sndata"
addressSize = 4
skipSize = 12

# Parse ELF Header stuff
inFile = open(sys.argv[1], 'rb')
elffile = ELFFile(inFile)

for section in elffile.iter_sections():
    if section.name.startswith('.sndata'):
         # Convert big endian sndata section header memory address
        sndataAddr = struct.pack("<4s", section['sh_addr'].to_bytes(4, byteorder="big"))
         # Convert big endian sndata section header file offset
        sndataOffset = struct.pack("<4s", section['sh_offset'].to_bytes(4, byteorder="big"))
        sndataAddrInt = int.from_bytes(sndataAddr, byteorder="big")     # Convert sndataAddr to int
        sndataOffsetInt = int.from_bytes(sndataOffset, byteorder="big")     # Convert sndataOffset to int
        memDiff = sndataAddrInt - sndataOffsetInt       # Difference between the memory address and 
        #print(section.name + " " + str(sndataAddr))


# Testing
class parseSndataHeader:
    # offset is where its located in the elf file
    # address is where its located in memory
    def offset2addr(self, i_offset):
        # convert file offset to memory address
        return i_offset + memDiff
    
    def addr2offset(self, i_address):
        # convert memory address to file offset
        return i_address - memDiff

    def returnHeader(self, inFile):
        # return to the start of .sndata header
        inFile.seek(sndataOffsetInt, 0)
        return inFile.read(4).decode("utf-8")
    
    def getNumOfFuncs(self, inFile):
        # Get the number of functions from the sndata section header
        inFile.seek(sndataOffsetInt+16, 0)
        out = inFile.read(addressSize)
        out = int.from_bytes(out, byteorder="little")
        return out

    def returnToSNRHeaderLocation(self, inFile):
            # Self Explanitory
        inFile.seek(startOfSndata, 0)
        return 
    
    def read4Bytes(self, in_bytes):
        buffer = in_bytes
        out = struct.unpack('<I', buffer)[0].to_bytes(addressSize, byteorder="big") # convert big endian byte object to little endian byte object.
        out = int.from_bytes(out, byteorder="big") # convert little endian byte object to int
        out = out.to_bytes(4, byteorder="big")
        return out

    def ret_NUL_T_String(self, inFile, in_list):
        # print out the first null terminated string
        # The only function that was brought over from the previous version, was slightly modified
        byte = ""
        strout = "" 
        func_list_cont = in_list
        while byte != b'\x00': #loop until it finds a NULL byte
            byte = inFile.read(1) #read byte from file
            if byte != b'\x00':
                strout = strout + byte.decode("utf-8") #convert byte to string and concat to strout
            func_list_cont = func_list_cont + 1
            inFile.seek(func_list_cont)
        return strout

    class Offsets:

        def getFuncListingStartAsInteger(self, inFile):
            inFile.seek(skipSize,1) # go to the address start pointer
            val = inFile.read(addressSize) # read big endian address
            out = struct.unpack('<I', val)[0].to_bytes(4, byteorder="big") # convert big endian byte object to little endian byte object.
            out = int.from_bytes(out, byteorder="big") # convert little endian byte object to int
            return out - memDiff # subtract Memory Difference to get file offset

    class Address:
        
        def getFuncListingStartAsInteger(self, inFile):
            inFile.seek(skipSize,1) # go to the address start pointer
            val = inFile.read(addressSize) # read big endian address
            out = struct.unpack('<I', val)[0].to_bytes(4, byteorder="big")  # convert big endian byte object to little endian byte object.
            out = int.from_bytes(out, byteorder="big") # convert little endian byte object to int
            return out

parser = parseSndataHeader()
Address = parseSndataHeader().Address()
Offsets = parseSndataHeader().Offsets()
startOfSndata = parseSndataHeader().addr2offset(sndataAddrInt)

def main():
    fileOut = open(args.Output, "wt")


    parser.returnToSNRHeaderLocation(inFile) # go to the start of SNR2 header

    ptrLoc = Offsets.getFuncListingStartAsInteger(inFile)+skipSize #3143485 + 12

    numOfFunctions = parser.getNumOfFuncs(inFile)
    if(args.ghidra == True or args.ida == True):    # Check if -g or -i have been givven.  
        for i in range (1,numOfFunctions):

            inFile.seek(ptrLoc, 0)  # Go to Pointer location
            funcNameLocPre = inFile.read(addressSize) # read in 4 bytes
            funcNameLocAddr = int.from_bytes(parser.read4Bytes(funcNameLocPre), byteorder="big")    # convert bytes to little endian UINT32
            funcNameLocOffset = parser.addr2offset(funcNameLocAddr) # Convert memory address pointer to ELF file offset

                # Debugging prints
            #print("\nfuncNameLocPre: " + str(binascii.hexlify(funcNameLocPre)))
            #print("funcNameLocAddr: " + str(funcNameLocAddr))
            #print("funcNameLocOffset: " + str(funcNameLocOffset) + "\n")

            inFile.seek(funcNameLocOffset, 0) # Go to func name location
            funcName = parser.ret_NUL_T_String(inFile, funcNameLocOffset)   # Read func name
            #print(funcName)

            inFile.seek(ptrLoc, 0)  # Go to Pointer location

            #print("ptrLoc1: " + str(ptrLoc))
            ptrLoc += addressSize  # Go to next address 

            #print("ptrLoc2: " + str(ptrLoc))
            inFile.seek(ptrLoc, 0)  # Go to Pointer location

            FunctionLocationPre = inFile.read(addressSize)  # Read big endian memory address
            FunctionLocationAddr = parser.read4Bytes(FunctionLocationPre)   # Convert Big endian to Little endian

            funcOffset = "0x" + binascii.hexlify(FunctionLocationAddr).decode("utf-8")  # Add Func location string to "0x" 

            if(args.ghidra):    # Output ghidra script 
                fileOut.write(funcName + " " + funcOffset + "\n")
            if(args.ida):   # Output IDA script
                fileOut.write("idaapi.set_name(" + funcOffset + ", \"" + funcName + "\", idaapi.SN_NOWARN)" + "\n")

            ptrLoc += (addressSize + addressSize)   # Skip past the final Memory address to the start the next func name pointer
            #print("ptrLoc3: " + str(ptrLoc))
    else:
        # Error if -i or -g not given 
        print("Error, Script output type not stated. Exitting...")
        sys.exit(1)

    # print out that the program has run properly
    fileOut.close()
    print("Done! Extracted " + str(numOfFunctions) + " Symbols")
    
if __name__ == '__main__':
    main()