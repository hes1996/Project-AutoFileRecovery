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
from re import match

regexPNG = "89504e470d0a1a0a*(.*?)49454e44ae426082"
regexGIF = "474946383761*(.*?)003b"
regexJPG = "ffd8*(.*?)ffd9"
regexZIP = "504b0304*(.*?)504b0506"
regexMPG = "000001ba*(.*?)000001b7"
regexDOCX = "504b030414000600*(.*?)504b0506[\w]{36}"
regexPDFOne = "25504446*(.*?)0a2525454f46"
regexPDFTwo = "25504446*(.*?)0a2525454f460a" 
regexPDFThree = "25504446*(.*?)0d0a2525454f460d0a"
regexPDFFour = "25504446*(.*?)0d2525454f460d"
regexBMP = "424f[\w]{6}"
regexAVI = "52494646[\w]{8}415649204c495354"
startfilecounter = 0

def main():
    def RecoverFiles(regularEx,filecounterIn): 
    # Find values between file header and file footer
        mylist = re.compile(regularEx)
        #content = list(filter(mylist.match, hexdump.decode()))
        #content = re.findall(regularEx, hexdump.decode())
        #content = re.finditer(mylist, hexdump.decode())
        counter = 0
        i = filecounterIn
        
        for match in mylist.finditer(hexdump.decode()):
            #print("This is limit: " + str(len(content)))
            #print("This counter is: " + str(counter))
            #if content[counter].find(regexPNG) != -1:
            #print("File" + str(i) + ".PNG Start Offset: " + content[counter].start()+ " End Offset: " + content[counter].end())
            #i += 1
            #    counter += 1
            if  regexPNG == regularEx:
                print("File" + str(i) + ".png Start Offset: "+ str(match.start()) + " End Offset: "+ str(match.end())) 
                i += 1
                counter += 1    
            elif regexGIF == regularEx: 
                print("File" + str(i) + ".gif Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            elif regexJPG == regularEx: 
                print("File" + str(i) + ".jpg Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
            elif regexZIP == regularEx:
                print("File" + str(i) + ".zip Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            elif regexMPG == regularEx:
                print("File" + str(i) + ".mpg Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            elif regexDOCX == regularEx:
                print("File" + str(i) + ".docx Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            elif regexPDFOne == regularEx:
                print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            elif regexPDFTwo == regularEx:
                print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
            elif regexPDFThree == regularEx:
                print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end())) 
                i = i + 1
                counter += 1
                break
            elif regexPDFFour == regularEx:
                print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break    
            elif regexBMP == regularEx:
                print("File" + str(i) + ".bmp Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            elif regexAVI == regularEx:
                print("File" + str(i) + ".avi Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                i = i + 1
                counter += 1
                break
            else:
                counter += 1
        return i





    # taking in the disk image
    # 'rb' means we are reading the binary contents of the file
 

    try:
        with open (input("Enter disk image name: "), "rb") as Proj_file:
            data = Proj_file.read()
            startfilecounter = 1
            hexdump = binascii.hexlify(data)
            startfilecounter = RecoverFiles(regexMPG,startfilecounter)
            startfilecounter = RecoverFiles(regexPDFOne,startfilecounter)
            startfilecounter = RecoverFiles(regexPDFTwo,startfilecounter)
            startfilecounter = RecoverFiles(regexPDFThree,startfilecounter)
            startfilecounter = RecoverFiles(regexPDFFour,startfilecounter)
            startfilecounter = RecoverFiles(regexGIF,startfilecounter)
            startfilecounter = RecoverFiles(regexZIP,startfilecounter)
            startfilecounter = RecoverFiles(regexJPG,startfilecounter)
            startfilecounter = RecoverFiles(regexPNG,startfilecounter)
            startfilecounter = RecoverFiles(regexDOCX,startfilecounter)
            startfilecounter = RecoverFiles(regexBMP,startfilecounter)
            startfilecounter = RecoverFiles(regexAVI,startfilecounter)
    except FileNotFoundError:
        print("File was not found")
        exit()
        
        
if __name__ == "__main__":
	main()


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


