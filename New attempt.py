import re
import hashlib

#This section we get to establish the
#file signature and file footers
#

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


#This is the hashing encryption method
def hash(file):
    with open(file, "rb") as i:
        # read entire file as bytes
        bytes = i.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()
        print("SHA-256: " + readable_hash + '\n')
        print("\n")

##
##HERE IS WHERE THE MAGIC HAPPENS
file_obj = open(input("Enter file name: "), 'rb')
data = file_obj.read()
file_obj.close()

##We begin with JPG
##the headers are in one list and the footers are in another
SOF_list=[match.start() for match in re.finditer(re.escape(JPG_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(JPG_EOF),data)]
i = 0
##We kind of 
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            print(type(SOF))
            carve_filename="file"+ str(filecounter) + ".jpg Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="Carve1_"+str(SOF)+"_"+str(EOF)+".jpg" 
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            hash(filename)
            filecounter += 1
            break

SOF_list=[match.start() for match in re.finditer(re.escape(PNG_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(PNG_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".png Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+".png" 
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            hash(filename)
            filecounter += 1
            break
        
            
SOF_list=[match.start() for match in re.finditer(re.escape(MGP_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(MGP_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".mgp Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+".mgp" 
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            hash(filename)
            filecounter += 1
            break

SOF_list=[match.start() for match in re.finditer(re.escape(DOCX_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(DOCX_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".docx Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+".docx" 
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            hash(filename)
            filecounter += 1
            break

SOF_list=[match.start() for match in re.finditer(re.escape(AVI_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(AVI_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".avi Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"avi" 
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            hash(filename)
            filecounter += 1
            break

SOF_list=[match.start() for match in re.finditer(re.escape(GIF_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(GIF_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".gif Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"gif" 
            carve_obj=open(filename,'wb')
            carve_obj.write(subdata)
            carve_obj.close()
            i=i+1  
            print(carve_filename)
            hash(filename)
            filecounter += 1
            break
'''
SOF_list=[match.start() for match in re.finditer(re.escape(PDF1_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(PDF1_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF]
            carve_filename="file"+ str(filecounter) + ".pdf Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"pdf" 
            #carve_obj=open(filename,'wb')
            #carve_obj.write(subdata)
            #carve_obj.close()
            #i=i+1  
            print(carve_filename)
            #hash(carve_filename)
            filecounter += 1

SOF_list=[match.start() for match in re.finditer(re.escape(PDF2_SOF),data)]
EOF_list=[match.start() for match in re.finditer(re.escape(PDF2_EOF),data)]
i = 0
for SOF in SOF_list:
      for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF:EOF_list]
            carve_filename="file"+ str(filecounter) + ".pdf Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(EOF_list)
            filename="file"+ str(filecounter) + "_"+str(SOF)+"_"+str(EOF)+"pdf" 
            #carve_obj=open(filename,'wb')
            #carve_obj.write(subdata)
            #carve_obj.close()
            #i=i+1  
            print(carve_filename)
            #hash(carve_filename)
            EOF_list.remove(EOF)
            filecounter += 1

SOF_list=[match.start() for match in re.finditer(re.escape(BMP_SOF),data)]
#EOF_list=[match.start() for match in re.finditer(re.escape(BMP_EOF),data)]
i = 0
for SOF in SOF_list:
    for EOF in EOF_list:
        if int(SOF) < int(EOF):
            subdata=data[SOF: SOF + 6]
            carve_filename="file"+ str(filecounter) + ".bmp Start Offset: 0x" + str(SOF)+ " End Offset: 0x" + str(int(SOF+6))
            i=i+1  
            print(carve_filename)
            #hash(filename)
            filecounter += 1
            continue

def hashering(file):
    sha256_hash = hashlib.sha256()
    with open(file,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        print(sha256_hash)

def hash(file):
    with open(file, "rb") as i:
        # read entire file as bytes
        bytes = i.read()
        readable_hash = hashlib.sha256(bytes).hexadigest()
        print("SHA-256: " + readable_hash + '\n')
        print("\n")
'''
