'''
This Project accepts a disk image as an input, locates file signatures, recovers files, and generates a SHA-256 hash for each file recovered.
Authors: Sadok Aounallah and Hannah Strother.
'''
# Importing re for regular expressions and hashlib for SHA-256 hash.
import re
import hashlib

# Start and end of file expressions.
# These will be used to locate the file signatures and recover the files.
JPG_SOF = b'\xFF\xD8\xFF\xE0'
JPG_EOF = b'\xFF\xD9'
PNG_SOF = b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A'
PNG_EOF = b'\x49\x45\x4E\x44\xAE\x42\x60\x82'
DOCX_SOF =b'\x50\x4B\x03\x04'
#DOCX_EOF = b'\x50\x4B\x05\x06'
#DOCX_EOF = b'\x50\x4B\x03\x04\x14\x00\x06\x00'
DOCX_EOF = b'\x06\x05\x4B\x50'
#dox = b'\0[0-9a-fA-F]{36}'
#DOCX_EOF += dox
BMP_SOF = b'\x42\x4F'
BMP_EOF = b'\0[0-9A-F]{6}'
PDF1_SOF = b'\x25\x50\x44\x46'
PDF1_EOF = b'\x0A\x25\x25\x45\x4F\x46'
PDF2_SOF = b'\x25\x50\x44\x46'
PDF2_EOF = b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A'
GIF_SOF = b'\x47\x49\x46\x38\x39\x61'
GIF_EOF = b'\x00\x3B'
AVI_SOF = b'\x52\x49\x46\x46\x41\x56\x49\x20'
AVI_EOF = b'\x41\x56\x49\x20\x4C\x49\x53\x54'
MGP_SOF = b'\x00\x00\x01\xBA'
MGP_EOF = b'\x00\x00\x01\xB7'
filecounter = 1


'''
This is the hashing method.
It takes in each recovered file's content, opens it, reads through it, and generates and prints a SHA-256 hash.
'''
def hash(file):
    with open(file, "rb") as i:
        # read entire file as bytes
        bytes = i.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
        print("SHA-256: " + readable_hash + '\n')
        print("\n")

'''
This allows a user to input a disk image.
A disk image is read in as bytes and saved to data.
The disk image is then closed.
'''
file_obj = open(input("Enter file name: "), 'rb')
data = file_obj.read()
file_obj.close()

'''
Search of jpg file types.
Data is scanned for start and end of file matches. When matches are found, they are saved to lists.
Next, recursively scan both lists to recover all jpg files. Then those files get printed along with their start and end offsets.
'''
# Search for jpg file headers and footers and create lists of matches.
SOF_list=[match.start() for match in re.finditer(re.escape(JPG_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(JPG_EOF),data)]
i = 0
# Scan through SOF and EOF.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            print(type(SOF))
            carve_filename="file"+ str(filecounter) + ".jpg Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="Carve1_"+str(SOF)+"_"+str(EOF)+".jpg" 
            # writes each jpg file to an object.
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            # calls hash function.
            hash(filename)
            filecounter += 1
            break
            
'''
Search of PNG files.
This works in the exact same way the JPG search worked.
'''
# Search for PNG files and saves matches into a list.
SOF_list=[match.start() for match in re.finditer(re.escape(PNG_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(PNG_EOF),data)]
i = 0
# Scans through the lists.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".png Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+".png" 
            # Writes to an object.
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            # calls hash function with PNG file contents.
            hash(filename)
            filecounter += 1
            break
        
'''
Search of MGP files.
This works in the exact same way the JPG and PNG search worked.
'''
# Search for MPG files and save the matches to a list.
SOF_list=[match.start() for match in re.finditer(re.escape(MGP_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(MGP_EOF),data)]
i = 0
# Sacns through the lists.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".mgp Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+".mgp" 
            # writes to an object.
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            # Calls hash function
            hash(filename)
            filecounter += 1
            break

'''
Search of DOCX files.
This works differently than the above files.
**Explain how it works**
'''
# Search for DOCX files and saves them to lists.
SOF_list=[match.start() for match in re.finditer(re.escape(DOCX_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(DOCX_EOF),data)]
i = 0
# Searches lists.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".docx Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+".docx" 
            # writes to an object.
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            # Calls hash function.
            hash(filename)
            filecounter += 1
            break

'''
Search of PNG files.
This works similarly to the DOCX file search.
**Explain what this does that DOCX does not do**
'''
# Searches AVI SOF and EOF expressions and creates lists of matches.
SOF_list=[match.start() for match in re.finditer(re.escape(AVI_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(AVI_EOF),data)]
i = 0
# Searches lists for individual AVI files.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".avi Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"avi" 
            # writes file to object
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            # Calls hash function
            hash(filename)
            filecounter += 1
            break

'''
Search of GIF files.
This works differently than the other file types.
**Explain how this works**
'''
# Searches for GIF expression matches and makes lists of the matches.
SOF_list=[match.start() for match in re.finditer(re.escape(GIF_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(GIF_EOF),data)]
i = 0
# Scans lists
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".gif Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"gif" 
            # writes to object
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            # Calls hash function
            hash(filename)
            filecounter += 1
            break
            
'''
Search of one of PDF files.
This will work the same way as PDF2.
**Explain how this works**
'''
'''
# Searches data for matching PDF SOF and EOF, then creates lists for matches.
SOF_list=[match.start() for match in re.finditer(re.escape(PDF1_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(PDF1_EOF),data)]
i = 0
# Scans lists to get file content.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".pdf Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"pdf" 
            # writes to object.
            #carve_obj=open(filename,'wb')
            #carve_obj.write(subdata)
            #carve_obj.close()
            #i=i+1  
            print(carve_filename)
            # Calls hash function.
            #hash(carve_filename)
            filecounter += 1

'''
#Search of the second PDF file.
#This works exactly like the PDF1.
'''
# Searches for PDF SOF and EOF and makes lists of matches.
SOF_list=[match.start() for match in re.finditer(re.escape(PDF2_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(PDF2_EOF),data)]
i = 0
# Scans lists.
for SOF in SOF_list:
      for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF_list]
            carve_filename="file"+ str(filecounter) + ".pdf Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF_list)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"pdf" 
            # Writes to object.
            #carve_obj=open(filename,'wb')
            #carve_obj.write(subdata)
            #carve_obj.close()
            #i=i+1  
            print(carve_filename)
            # Calls hash function.
            #hash(carve_filename)
            EOF_list.remove(EOF)
            filecounter += 1

'''
#Search of PNG files.
#This works similarly to DOCX file search.
#**Explain how this will work**
'''
# Searches for SOF and EOF for BMP files and creates lists for matches.
SOF_list=[match.start() for match in re.finditer(re.escape(BMP_SOF),data)]
#EOF_list=[match.start() for match in re.finditer(re.escape(BMP_EOF),data)]
i = 0
# Scans lists of matches.
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF: SOF + 6]
            carve_filename="file"+ str(filecounter) + ".bmp Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(int(SOF+6))
            #**Does this write to carve_obj as well or nah?**
            i=i+1  
            print(carve_filename)
            # Calls hash function
            #hash(filename)
            filecounter += 1
            continue
'''
