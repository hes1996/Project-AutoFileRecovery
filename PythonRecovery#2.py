'''

This is a Python script that will take a disk image as an input, 
locate file signatures, properly recover user generated files without 
corruption, and generate a SHA-256 hash for each file recovered.

Contributors: Hannah Strother and Sadok Aounallah

'''

import hashlib
import re
import binascii
import sys
import os , struct

regexPNG = ""
regexGIF = ""
regexJPG = ""
regexZIP = ""
regexMPG = ""
regexDOCX = ""
regexPDFOne = ""
regexPDFTwo = ""
regexPDFThree = ""
regexPDFFour = ""
regexBMP = ""
regexAVI = ""
startfilecounter = 0

def RecoverFiles(regularEx,filecounterIn): 
# Find values between file header and file footer
    content = re.findall(regularEx, hexdump.decode())
    counter = 0
    print(type(filecounterIn))
    i = filecounterIn
    if bool(content):
        print("This is limit: " + str(len(content)))
        print("This counter is: " + str(counter))
        while (counter < len(content) ):
            if content[counter].find(regexPNG) != -1:
                print("File" + str(i) + ".PNG Start Offset: " + str(struct.unpack(content[counter])) + " End Offset: ")
                i += 1
            elif content[counter].find(regexGIF) != -1: 
                print("File" + str(i) + ".gif Start Offset: " + " End Offset: ")
                i = i + 1
            elif content[counter].find(regexJPG) != -1: 
                print("File" + str(i) + ".gpg Start Offset: " + " End Offset: ")
                i = i + 1
            elif content[counter].find(regexZIP) != -1:
                print("File" + str(i) + ".zip Start Offset: " + " End Offset: ")
                i = i + 1
            elif content[counter].find(regexMPG) != -1:
                print("File" + str(i) + ".MPG Start Offset: " + " End Offset: ")
                i = i + 1
            elif content[counter].find(regexDOCX) != -1:
                print("File" + str(i) + ".docx Start Offset: " + " End Offset: ")
                i = i + 1
            elif regexPDFOne in content or regexPDFTwo in content or regexPDFThree in content or regexPDFFour in content:
                print("File" + str(i) + ".pdf Start Offset: " + " End Offset: ")
                i = i + 1
            elif content[counter].find(regexBMP) != -1:
                print("File" + str(i) + ".bmp Start Offset: " + " End Offset: ")
                i = i + 1
            elif content[counter].find(regexAVI) != -1:
                print("File" + str(i) + ".avi Start Offset: " + " End Offset: ")
                i = i + 1
            counter = counter + 1
    return i





    # taking in the disk image
    # 'rb' means we are reading the binary contents of the file
 

try:
    with open (input("Enter disk image name: "), "rb") as Proj_file:
        data = Proj_file.read()
        startfilecounter = 1
        hexdump = binascii.hexlify(data)
        regexMPG = "000001bx(.*?)000001b7"
        print("MPG")
        startfilecounter = RecoverFiles(regexMPG,startfilecounter)
        regexPDFOne = "25504446(.*?)2525454f46"
        regexPDFTwo = "25504446(.*?)0A2525454F460A" 
        regexPDFThree = "25504446(.*?)0D0A2525454F460D0A"
        regexPDFFour = "25504446(.*?)0D2525454F460D"
        print("PDF")
        startfilecounter = RecoverFiles(regexPDFOne,startfilecounter)
        regexGIF = "47494638(.*?)003b"
        print("GIF")
        startfilecounter = RecoverFiles(regexGIF,startfilecounter)
        regexZIP = "504b0304(.*?)504b0506"
        print("ZIP")
        startfilecounter = RecoverFiles(regexZIP,startfilecounter)
        regexJPG = "ffd8(.*?)ffd9"
        print("JPG")
        startfilecounter = RecoverFiles(regexJPG,startfilecounter)
        regexPNG = "89504e47(.*?)49454e44ae426082"
        startfilecounter = RecoverFiles(regexPNG,startfilecounter)
        regexDOCX = "504B030414000600(.*?)504b0506[0-9|A-F]{36}"
        startfilecounter = RecoverFiles(regexDOCX,startfilecounter)
        regexBMP = "424D[0-9|A-F]{6}"
        #bmpsize = regexBMP[2-9]
        regexAVI = "52494646[0-9|A-F]{8}215649204C495354"
except FileNotFoundError:
    print("File was not found")
    exit()
        
        



#if __name__ == "__main__":
#    main()


    
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


