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
regexPDFOne = "25504446(.*?)2525454f46"
regexPDFTwo = "25504446(.*?)0A2525454F460A" 
regexPDFThree = "25504446(.*?)0D0A2525454F460D0A"
regexPDFFour = "25504446(.*?)0D2525454F460D"
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




def RecoverFiles(regularEx): 
    # Find values between file header and file footer
    content = re.findall(regularEx, hexdump.decode())
    # If found proceed, else abort
    #
    counter = len(content)
    while (counter > 0):
        if content == regexPNG:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content==regexGIF:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif (content == regexJPG):
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content == regexZIP:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content == regexMPG:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content == regexDOCX:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content == regexPDFOne or content == regexPDFTwo or content == regexPDFThree or content == regexPDFFour:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content == regexBMP:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        elif content == regexAVI:
            print("File Name")
            print("Start Offset: ")
            print("End Offset: ")
        else:
            print("no such file available")
        counter = counter - 1 

    
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

