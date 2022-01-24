#!/usr/bin/env python3
import sys, os, io
from elftools.elf.elffile import ELFFile, ELFError, Section

class snPs2ELF(object):
    """ Handles loading of ELF and interfacing with sndata header section """

    # Constants
    PS2MAGIC  = "ELF"
    SNSYSHEAD = ".sndata"
    SNSYSSNR1 = "SNR1"
    SNSYSSNR2 = "SNR2"
    
    MAGICOFF        = 0 # 0x0
    UNKNOWN1OFF     = 4
    UNKNOWN2OFF     = 8
    ADDRESSLISTOFF  = 12
    NUMBEROFFUNCOFF = 16

    # File Data
    ps2file = io.TextIOWrapper
    """ Raw elf data file """
    ps2elf = ELFFile
    """ ELF file object """
    sndata = Section
    """ Sndata Header Section """
    sndata_data = io.BytesIO
    """ Data of sndata header section """
    sndata_functions = list
    """ List of all functions and their offsets in the sndata header section """

    # File Constants
    SNDATA_magic = str
    """ Magic of the header section data """
    SNDATA_unknown1 = int
    """ Unknown data 1 """
    SNDATA_unknown2 = int
    """ Unknown data 2 """
    SNDATA_addressList = int
    """ List of Address data """
    SNDATA_numFuncs = int
    """ The number of function in the sndata header section """

    ### Sndata function class
    class __sndata_function(object):
        """ Used like a struct to store sndata function info """

        function_name: str
        """ Function name """
        function_offset: bytes
        """ Function offset """

        def __init__(self, func_name: str, func_offset: bytes):
            self.function_name = func_name
            self.function_offset = func_offset
            return

    def __init__(self, infile: str):
        # Error checking 
        self.__error_handler(infile)
        self.__init_constants()
        return
        
    def __error_handler(self, infile: str):
        ## File unable to be opened
        try:
            self.ps2file = open(infile, "rb")
        except (FileNotFoundError, IOError) as error:
            print("Unable to open file \"" + infile + "\"")
            exit()
        
        ## File not an elf file
        try:
            self.ps2elf = ELFFile(self.ps2file)
        except ELFError:
            print("Input is not an ELF file")
            exit()
        
        ## File does not have sndata header section
        try:
            if(self.ps2elf.get_section_by_name(self.SNSYSHEAD) == None):
                raise
        except:
            print("ELF file does not have an sndata header section")
            exit()
        
        return

    def __init_constants(self):
        # Sndata section and section data
        self.sndata = self.ps2elf.get_section_by_name(self.SNSYSHEAD)
        self.sndata_data = io.BytesIO(self.sndata.data())

        # Populate Constants
        ## Magic
        self.sndata_data.seek(self.MAGICOFF, 0)
        self.SNDATA_magic = str(self.sndata_data.read(4), "ascii")

        ## Unknowns
        self.sndata_data.seek(self.UNKNOWN1OFF, 0)
        self.UNKNOWN1OFF = int.from_bytes(self.sndata_data.read(4), byteorder="little")
        self.UNKNOWN2OFF = int.from_bytes(self.sndata_data.read(4), byteorder="little")

        ## Addresses
        self.sndata_data.seek(self.ADDRESSLISTOFF, 0)
        self.SNDATA_addressList = hex(int.from_bytes(self.sndata_data.read(4), byteorder="little")
)
        ## Number of functions
        self.sndata_data.seek(self.NUMBEROFFUNCOFF, 0)
        self.SNDATA_numFuncs = int.from_bytes(self.sndata_data.read(4), byteorder="little")

        # Reset seek
        self.sndata_data.seek(0, 0)
        return
    


def main():
    elfFile = snPs2ELF(sys.argv[1])
    print(elfFile.SNDATA_numFuncs)

if __name__ == "__main__":
    main()

'''
import sys
import os
import string
import struct
import binascii
import argparse
from elftools.elf.elffile import ELFFile

# argparse ops here
argparser = argparse.ArgumentParser(prog="sndata-converter", usage='%(prog)s PS2-ELF Output [options]',  description='Extract Debug Symbols from PS2 ELF files the contain a .sndata section header')
group = argparser.add_mutually_exclusive_group()

argparser.add_argument("PS2 ELF", help="Input file")
argparser.add_argument("Output", help="Output file")

group.add_argument("-i", "--ida", help="Output Ida Python script", action="store_true")
group.add_argument("-g", "--ghidra", help="Output script for use with Ghidra's 'ImportSymbolsScript.py'", action="store_true")

args = argparser.parse_args()

# Some constants
sndataHeaderName = ".sndata"
addressSize = 4
skipSize = 12

# Parse ELF Header stuff
inFile = open(sys.argv[1], 'rb')
elffile = ELFFile(inFile)

hasSndata = False

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
        hasSndata = True

if hasSndata == False:
    print("This ELF may not have a .sndata header section.\nCheck if the binary has \"SNR1\" or \"SNR2\"")
    exit()

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
'''