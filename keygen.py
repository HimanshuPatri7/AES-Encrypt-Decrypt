import time
from Crypto.PublicKey import RSA  

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

gen_keys()