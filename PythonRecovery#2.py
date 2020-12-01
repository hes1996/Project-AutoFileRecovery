'''

This is a Python script that will take a disk image as an input, 
locate file signatures, properly recover user generated files without 
corruption, and generate a SHA-256 hash for each file recovered.

Contributors: Hannah Strother and Sadok Aounallah

'''

import hashlib
import re
import binascii
import fileinput

count = 0

# taking in the disk image
# 'rb' means we are reading the binary contents of the file
try:
    with open (fileinput.input(), "rb") as Proj_file:
        data = Proj_file.read()
except FileNotFoundError:
    print("File was not found")
    exit()
    
# Creating project file into hexdump
hexdump = binascii.hexlify(data)

# Regular expressions of file header and file footer
regexMPG = "000001bx(.*?)000001b7"
RecoverFiles(regexMPG)
regexPDF = "25504446(.*?)2525454f46"
RecoverFiles(regexPDF)
regexGIF = "47494638(.*?)003b"
RecoverFiles(regexGIF)
regexZIP = "504b0304(.*?)504b0506"
RecoverFiles(regexZIP)
regexJPG = "ffd8(.*?)ffd9"
RecoverFiles(regexJPG)
regexPNG = "89504e47(.*?)49454e44ae426082"
RecoverFiles(regexPNG)
regexDOCX = "504B030414000600(.*?)504b0506[0-9|A-F]{36}"
RecoverFiles(regexDOCX)
regexBMP = "424D[0-9|A-F]{6}"
#bmpsize = regexBMP[2-9]
regexAVI = "52494646[0-9|A-F]{8}215649204C495354"


# I'm not sure how to find the other 3 files using file header and file size
# Don't know how to make regular expressions with header and file size
# regexBMP
# regexAVI

def RecoverFiles(regularEx): 
    # Find values between file header and file footer
    content = re.findall(regularEx, hexdump.decode())
    # If found proceed, else abort
    #
    if content == regexPNG:
        print("")
    elif content==regexGIF:
        print("")
    elif (content == regexJPG):
        print("")
    elif content == regexZIP:
        print("")
    elif content == regexMPG:
        print("")
    elif content == regexDOCX:
        print("")
    elif content == regexPDF:
        print("")
    elif content == regexBMP:
        print("")
    elif content == regexAVI:
        print("")
    else:
        print("no such file available")

    
# recover user generated files without corruption and generate 
# a SHA-256 hash for each file recovered
'''
def hash(file)
    with open(file, "rb") as i:
        # read entire file as bytes
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexadigest()
        print("SHA-256: " + readable_hash'\n')
        print("\n")
'''
def bmpSize(regexBMP):
    sizeLilEndianOrder = ""
    content = re.findall(regexBMP, hexdump.decode())
    

