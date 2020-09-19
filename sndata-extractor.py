#/usr/bin/env python

import sys
import string
import binascii

# If -h or no arguments are passed to the script 
if len(sys.argv) < 2 or sys.argv[1] == "-h":
    print("usage: \n" + sys.argv[0] + " [-h]" + " FILE OFFSET -i/-g (you are required to choose either)")
    print("This program only works on extracted .sndata headers and outputs to stdout.\n" + "Author: Andrew Long, 2020.")
    print("-h                   Display this text")
    print("FILE                 The extracted .sndata header from a PS2 game\n")
    print("OFFSET, eg. 0x3d64   The offset below the list of function names that locates")
    print("                     the name of the first entry in the list in the OG ELF\n")
    print("-i                   output IDA .py script\n")
    print("-g                   output Ghidra script (use this with ImportSymbolsScript.py)")
    exit()

# input file
inFile = open(sys.argv[1], "rb")

# offset below the list 
offset = sys.argv[2]

if "0x" in offset:
    offset = sys.argv[2]
else:
    print("invalid name offset")
    exit(1)

ida = ''
# if user wants IDA script instead of ghidra
if sys.argv[3] == "-i":
    ida = 'IDA'
else:
    ida = ''

# Reads in file magic
magic = inFile.read(4)

# Determins if file magic is an sndata header
if (magic != "b'SNR2'"):
    pass
else:
    print("no .sndata header found.")
    exit(1)

def ret_NUL_T_String(sndata_in, first_in_list):
    # print out the first null terminated string
    byte = ""
    strout = "" 
    func_list_cont = first_in_list
    while byte != b'\x00': #loop until it finds a NULL byte
        byte = sndata_in.read(1) #read byte from file
        strout = strout + byte.decode("utf-8") #convert byte to string and concat to strout
        func_list_cont = func_list_cont + 1
        sndata_in.seek(func_list_cont)
    return strout, func_list_cont

def read_reverse_four_bytes(byte_name_offset):
    # read four bytes in reverse and output as string
    inFile.seek(byte_name_offset, 0)  #go to offset in file
    a = inFile.read(4)[::-1]    #read four bytes backwards at offset
    b = binascii.hexlify(a)     #converts four byte to string
    return b.decode("utf-8")    #returns & converts string to utf-8 

def print_NULL_term_string(loop=1):

    # Offset of first func name in list
    func_list_st = int("0x3d", 16)
    inFile.seek(func_list_st, 0)

    for i in range(loop):
        strout, func_list_cont = ret_NUL_T_String(inFile, func_list_st)
        func_list_st = func_list_cont
    return strout

func_name_st = int(offset, 16)

for i in range(1,9999): 
    #It loops 9999 times because I'm not gonna find a way to do it automatically,
    #it'll crash before it can write anything to stdout
    loc_name = read_reverse_four_bytes(func_name_st) # unused but important
    func_name_st = func_name_st + 4 
    loc_func = read_reverse_four_bytes(func_name_st)
    func_name_st = func_name_st + 4 
    loc_exce = read_reverse_four_bytes(func_name_st) # unused but important
    func_name_st = func_name_st + 4 
    
    func_name = str(print_NULL_term_string(i)[:-1])
    if func_name != '' and ida == "IDA":
        if loc_func != str("00000000"):
            print("idaapi.set_name(0x" + loc_func[2:] + ', "' + func_name + '", idaapi.SN_NOWARN)')
    if func_name != '' and ida == "":
        if loc_func != str("00000000"):
            print(func_name + " 0x" + loc_func)
