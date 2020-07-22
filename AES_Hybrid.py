from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad,unpad
from Crypto.PublicKey import RSA  
from Crypto.Signature import PKCS1_PSS as PKCS  
from Crypto.Hash import SHA  
import hashlib,sys
from webdav3.client import Client
import time
import warnings
from weddavexception import WebDavException
import os
import struct
from tkinter import Tk
from tkinter.filedialog import askopenfilename
import tkinter as tk

salt=b'\xa4iZ\x98\x86\\\xd0Q\x1e\xfe\x85\nPe2s\x01\xc3\xde\x9c8\xe02\xef\x97\xb4\x133\x9a\xdf\xefk'

def aes_decrypt(file_to_decrypt,buffer_size=65536):

    value=input("Is the key stored in a file? (Y/N)\n")
    
    if value=="y" or value=="Y":
        key_location=input("Enter location of key or press Enter for default location\n")
        if len(key_location)==0:
            key_location = "./my_key.bin"
        file_in = open(key_location, "rb") # Read bytes
        key = file_in.read() # This key should be the same
        file_in.close()
    else:
        password=input("Enter the key\n")
        key = PBKDF2(password,salt, dkLen=32)
        
    st=time.time()
    input_file = open(file_to_decrypt + '.encrypted', 'rb')
    output_file = open(file_to_decrypt + '.decrypted', 'wb')
    
    fsz = struct.unpack('<Q',input_file.read(struct.calcsize('<Q')))[0]

    # Read in the iv
    iv = input_file.read(16)
    sz=2048
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Keep reading the file into the buffer, decrypting then writing to the new file
    
    while True:
        buffer = input_file.read(sz)
        n=len(buffer)
        if n==0:
            break
        decrypted_bytes = cipher.decrypt(buffer)
        n = len(decrypted_bytes)
        if fsz> n:
            
            output_file.write(decrypted_bytes)
    
        else:
            output_file.write(decrypted_bytes[:fsz])
        fsz -=n
    et=time.time()
    # Close the input and output files
    input_file.close()
    output_file.close()
    t=et-st
    with open('log.txt', 'a') as log:
        log.write('Decrypted '+file_to_decrypt+' in '+str(t)[:5]+"secs\n")
    
    print("File decrypted\n Time = ",et-st)

def aes_encrypt(key,file_to_encrypt,buffer_size=65536):
    
    st=time.time()
    print("Encrypting file with given key.......")
     # Open the input and output files
    input_file = open(file_to_encrypt, 'rb')
    output_file = open(file_to_encrypt + '.encrypted', 'wb')

    fsz=os.path.getsize(file_to_encrypt)
    output_file.write(struct.pack('<Q',fsz))

    # Create the cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC)

    # Initially write the iv to the output file
    output_file.write(cipher.iv)
    
    
    # Keep reading the file into the buffer, encrypting then writing to the new file
    buffer = input_file.read(buffer_size)
    n=len(buffer)
    while len(buffer) > 0:
        if  n%16 !=0:
            buffer += b' ' * (16 - n % 16)
        ciphered_bytes = cipher.encrypt(buffer)
        output_file.write(ciphered_bytes)
        buffer = input_file.read(buffer_size)
    et=time.time()
    
    input_file.close()
    output_file.close()
    t=et-st
    with open('log.txt', 'a') as log:
        log.write('Encrypted '+file_to_encrypt+' in '+str(t)[:5]+"secs\n")
    print("File encrypted successfully\n",et-st)

def generate_hash(input_file,buffer_size=65536):
    file_hash = hashlib.sha256() # Create the hash object
    with open(input_file, 'rb') as f: 
        fb = f.read(buffer_size) # Read from the file. Take in the amount declared above
        while len(fb) > 0: # While there is still data being read from the file
            file_hash.update(fb) # Update the hash
            fb = f.read(buffer_size) # Read the next block from the file
    with open(input_file+'.hash', 'w') as file:  
        file.write(file_hash.hexdigest()) 
    print("Hash succesfully generated and stored in file")

def gen_keys():
    st=time.time()
    key = RSA.generate(2048)  
    privKey = key.exportKey('PEM')  
    pubKey =  key.publickey().exportKey('PEM')
    et=time.time()
    #save PEM key into the files 
    with open('./private_key.pem', 'wb') as file:  
        file.write(privKey)  
    
    with open('./public_key.pem', 'wb') as file:  
        file.write(pubKey)
    t=et-st
    with open('log.txt', 'a') as log:
        log.write('Keys generated in '+str(t)[:5]+"secs\n")
    print("Public and private keys generated and stored\nTime Taken = ",et-st)

def sign(input_file):
    with open(input_file+'.hash','r') as file:
        gen_hash=file.read(128)

    f = open('./private_key.pem', 'rb')

    privatekey = RSA.importKey(f.read())  
    h = SHA.new()  
    h.update(gen_hash.encode('utf-8'))  
    signer = PKCS.new(privatekey)  
    signature = signer.sign(h)
    with open(input_file+'.sign','wb') as fout:
        fout.write(signature)
    print("Hash successfully signed")
    
    return(signature)


def verify_sign(input_file,buffer=65536):
    f1 = open('./public_key.pem', 'rb')
    pubKey = RSA.importKey(f1.read()) 
    file=input_file + '.decrypted'
    
    file_hash = hashlib.sha256() 
    
    with open(file, 'rb') as f: 
        fb = f.read(buffer) 
        while len(fb) > 0: 
            file_hash.update(fb) 
            fb = f.read(buffer) 
    """ with open(file+'.new_hash', 'w') as file:  
        file.write(file_hash.hexdigest()) """
    h=SHA.new()     
    h.update((file_hash.hexdigest()).encode('utf-8'))
    verifier= PKCS.new(pubKey)
    with open(input_file+'.sign','rb') as fin:
        signature=fin.read(buffer)
    if verifier.verify(h,signature):
        print("The  signature is authentic and the file has not been modified.")
    else:
        print("The signature is not authentic!!!!!\nThe file has been modified.")    
    
def sign_encrypt():
    Tk().withdraw()
    #input_file = input("Enter the name of the file to be Signed and Encrypted\n") #Replaced with GUI
    input_file = askopenfilename()
    if os.path.isfile(input_file):
        password=input("Enter key for encrytion\n")
        
        key = PBKDF2(password, salt, dkLen=32)
        value=input("Would you like to store key in a file Y/N\n")
        if value=="y" or value=="Y":
            key_location = input("Enter the location to store key. Press enter to store in present directory.\n")
            if len(key_location)==0:
                key_location = "./my_key.bin"
            file_out = open(key_location, "wb")
            file_out.write(key)
            file_out.close()
        #gen_keys()
        generate_hash(input_file)
        sign(input_file)
        aes_encrypt(key,input_file)
    else:
        print("The file does not exist!\n")

        

def decrypt_verify():
    
    input_file = input("Enter the name of the file to be decrypted\n")
    if os.path.exists(input_file):
        aes_decrypt(input_file)
        verify_sign(input_file)
    else:
        print("The file does not exist!!!\n")


def GUI():

    root=tk.Tk()

    def fetch():

        ip=ip_entry.get()
        name=name_entry.get()
        password=password_entry.get()
        return ip,name,password

    ip=tk.StringVar()
    name=tk.StringVar()
    password=tk.StringVar()

    ip_l = tk.Label(root, text = 'IP Address')
    name_l = tk.Label(root, text = 'Username')
    password_l = tk.Label(root, text = 'Password')

    ip_entry = tk.Entry(root,textvariable = ip)
    name_entry = tk.Entry(root,textvariable = name)
    password_entry = tk.Entry(root,textvariable = password)

    sub_btn=tk.Button(root,text = 'Submit',command = fetch()) 

    ip_l.grid(row=0,column=0)
    ip_entry.grid(row=0,column=1)
    name_l.grid(row=1,column=0)
    name_entry.grid(row=1,column=1)
    password_l.grid(row=2,column=0)
    password_entry.grid(row=2,column=1)
    sub_btn.grid(row=3,column=1)

    root.mainloop()

    return ip,name,password

def upload_dav():

    

    
    
    try:
        
        options = {
        'webdav_hostname': "https://192.168.1.4/remote.php/dav/files/clouduser/",
        'webdav_login':    "clouduser",
        'webdav_password': "root",
        'verbose':True
        }
        conn=False
        client = Client(options)
        client.verify = False
        try:
            if(client.list()):
                print('\n' * 4)
                print("Connection Successfull")
                conn=True
                print('\n' * 3)
        except:
            print('\n' * 4)
            print("Connection error. Check credentials")
            
            
            
        if conn:
            print("##############################################################")
            opt=int(input("Choose action to be performed:\n1:Show all files\n2:Make Directory\n3:Delete\n4:Download file\n5:Upload File\n"))
            if opt==1:
                
                files=client.list()
                print(files)
            elif opt==2:
                d=input("Enter directory name\n")
                if client.mkdir(d):
                    print("Created Successfully")
            elif opt==3:
                d=input("Enter directory or file name\n")
                client.clean(d)
                print("Deleted")
            elif opt==4:
                file=input("Enter file to download with public key and signature\n")
                path_1=file+'.encrypted'
                path_2=file+'.sign'
                path_3='public_key.pem'
                
                s_time=time.time()
                client.download_sync(path_1, path_1)
                client.download_sync(path_2, path_2)
                client.download_sync(path_3, path_3)
                e_time=time.time()
                t=e_time-s_time
                with open('log.txt','w') as log:
                    log.write('Time taken to download all files'+str(t)[:5])
                print("Downloaded, Time taken is",e_time-s_time)
            elif opt==5:
                file=input("Enter file to upload with public key and signature\n")
                path_1=file+'.encrypted' 
                path_2=file+'.sign'
                path_3='public_key.pem'
                
                s_time=time.time()
                client.upload_sync(path_1, path_1)
                client.upload_sync(path_2, path_2)
                client.upload_sync(path_3, path_3)
                e_time=time.time()
                with open('log.txt','w') as log:
                    log.write('Time taken to upload all files'+str(t)[:5])
                print("Uplaoded, Time taken is",e_time-s_time)
            else:
                None
    except WebDavException as exception:
            print("\n\n",exception,"\n\n")


def main():
    #buffer_size = 65536 # 64kb

    if (input("Are the keys generated?")=='N'):
        print("Generate keys first")
        exit()


    else:
        while True:
            case=int(input("\n"*5+"Enter the action to be performed:\n1:Sign And Encrypt File\n2:Decrypt and Verify Signature\n3:Access Cloud Server\n4:Exit\n"))
            if case == 1:
                sign_encrypt()
            elif case == 2:
                decrypt_verify()
            elif case == 3:
                upload_dav()
            elif case == 4:
                break
            else: 
                print("\nInvalid Option")

""" if os.path.isfile('log.txt'):
    os.remove('log.txt') """


warnings.filterwarnings("ignore")
main()

        









