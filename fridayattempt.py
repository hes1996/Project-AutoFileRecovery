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
regexJPG = "ffd8ffe*(.*?)ffd9"
regexMPG = "000001ba*(.*?)000001b7"
regexDOCX = "504b030414000600*(.*?)504b0506[\w]{36}"
regexPDFOne = "25504446*(.*?)0a" # 0a2525454f46
# regexPDFTwo = "25504446*(.*?)0a2525454f460a" 
regexPDFThree = "25504446*(.*?)0d" # 0d0a2525454f460d0a
# regexPDFFour = "25504446*(.*?)0d2525454f460d"
regexBMP = "424f[\w]{6}"
regexAVI = "52494646[\w]{8}415649204c495354"
startfilecounter = 0

def main():
    def RecoverFiles(regularEx,filecounterIn): 
    # Find values between file header and file footer
        mylist = re.compile(regularEx) # This scans through the disk image and makes a list of all found matching files
        #content = list(filter(mylist.match, hexdump.decode()))
        #content = re.findall(regularEx, hexdump.decode())
        #content = re.finditer(mylist, hexdump.decode())
        counter = 0
        i = filecounterIn
        
        for match in mylist.finditer(hexdump.decode()): # This scans that list only for matching headers and footers
            #print("This is limit: " + str(len(content)))
            #print("This counter is: " + str(counter))
            #if content[counter].find(regexPNG) != -1:
            #print("File" + str(i) + ".PNG Start Offset: " + content[counter].start()+ " End Offset: " + content[counter].end())
            #i += 1
            #    counter += 1
            if  regexPNG == regularEx:
		counter += 1
		# Need a for statement to actually save all of the content to the filename so hash will be correct
		For j in mylist:
			PNGfullFile = "89504e470d0a1a0a" + j + "49454e44ae426082"
			# PNGfullFile is still in hexdump, so we convert back to binary
			convPNGfile = binascii.a2b_hex(PNGfullFile)
                	print("File" + str(i) + ".png Start Offset: "+ str(match.start()) + " End Offset: "+ str(match.end())) # This would be inside for statement
                	i += 1 # This would be inside for statement
			hash(convPNGfile)
                # counter += 1 - This would be before for statement
            elif regexGIF == regularEx:
		counter += 1
		For j in mylist:
			GIFfullFile = "474946383761" + j + "003b"
			convGIFfile = binascii.a2b_hex(GIFfullFile)
                	print("File" + str(i) + ".gif Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convGIFfile)
                # counter += 1
                break # is break supposed to be under all elifs?
            elif regexJPG == regularEx: 
		counter += 1
		For j in mylist:
			JPGfullFile = "ffd8ffe" + j + "ffd9"
			convJPGfile = binascii.a2b_hex(JPGfullFile)
                	print("File" + str(i) + ".jpg Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convJPGfile)
                # counter += 1
            elif regexMPG == regularEx:
		counter += 1
		For j in mylist:
			MPGfullFile = "000001ba" + j + "000001b7"
			convMPGfile = binascii.a2b_hex(MPGfullFile)
                	print("File" + str(i) + ".mpg Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convJPGfile)
                # counter += 1
                break
            elif regexDOCX == regularEx:
		counter += 1
		For j in mylist:
			DOCXfullFile = "504b030414000600" + j # + "504b0506[\w]{36}" - is this right?
			convDOCXfile = binascii.a2b_hex(DOCXfullFile)
                	print("File" + str(i) + ".docx Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convDOCXfile)
                # counter += 1
                break
            elif regexPDFOne == regularEx:
		counter += 1
		For j in mylist:
			PDF1fullFile = "25504446" + j + ""
			convPDF1file = binascii.a2b_hex(PDF1fullFile)
                	print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convPDF1file)
                # counter += 1
                break
            elif regexPDFThree == regularEx:
		counter += 1
		For j in mylist:
			PDF2fullFile = "25504446" + j + ""
			convPDF2file = binascii.a2b_hex(PDF2fullFile)
                	print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convPDF2file)
                # counter += 1
            # elif regexPDFThree == regularEx:
            #   print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end())) 
            #   i = i + 1
            #   counter += 1
            #   break
            # elif regexPDFFour == regularEx:
            #   print("File" + str(i) + ".pdf Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
            #   i = i + 1
            #   counter += 1
            #   break    
            elif regexBMP == regularEx:
		counter += 1
		For j in mylist:
			BMPfullFile = "" + j + ""
			convBMPfile = binascii.a2b_hex(BMPfullFile)
                	print("File" + str(i) + ".bmp Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convBMPfile)
                # counter += 1
                break
            elif regexAVI == regularEx:
		counter += 1
		For j in mylist:
			AVIfullFile = "" + j + ""
			convAVIfile = binascii.a2b_hex(AVIfullFile)
                	print("File" + str(i) + ".avi Start Offset: " + str(match.start()) + " End Offset: " + str(match.end()))
                	i = i + 1
			hash(convAVIfile)
                # counter += 1
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
       #    startfilecounter = RecoverFiles(regexPDFTwo,startfilecounter)
            startfilecounter = RecoverFiles(regexPDFThree,startfilecounter)
       #    startfilecounter = RecoverFiles(regexPDFFour,startfilecounter)
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
def hash(file)
    with open(file, "rb") as i:
        # read entire file as bytes
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexadigest()
        print("SHA-256: " + readable_hash'\n')
        print("\n")
