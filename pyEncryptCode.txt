import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


#program uses a hashed password for the key and a file to encrypt
def encrypt(key, filename):
    #define the chunk size to read out of the file
    chunksize = 64 * 1024
    
    #add the string encrypted to the original file name
    outputFile = ("[encrypted]")+filename
    
    #get the size of the file
    filesize = str(os.path.getsize(filename)).zfill(16)
    
    #get a nonce for the secret key
    IV = Random.new().read(16)

    #create encryptor that uses AES in mode CBC
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    #get the file to encrypt in read binary mode
    with open(filename, 'rb') as infile:
        
        #create new file in write binary mode
        with open(outputFile, 'wb') as outfile:
            
            #write the filesize as a string and encode it into bytes
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            #create a loop to encrypt the actual file
            while True:
                chunk = infile.read(chunksize)

                #if there is nothing left to read, break out of the loop
                if len(chunk) ==0:
                    break
                #add padding if there is not a 16 byte block
                elif len(chunk) % 16 !=0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                #once fileis encrypted, write it to the outfile
                outfile.write(encryptor.encrypt(chunk))
                




#reverse the the encryption
def decrypt(key, filename):
    
    #define the chunk size to read out of the file
    chunksize = 64 * 1024

    #strip the eleven characters off the front of the file that says "encrypted"
    outputFile = filename[11:]

    #open the encrypted file in read binary format
    with open(filename, 'rb') as infile:

        #get file size, read 16 bytes
        filesize = int(infile.read(16))

        #get IV out of file
        IV = infile.read(16)

        #create decryptor that uses AES in mode CBC
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        #create new file in write binary mode
        with open(outputFile, 'wb') as outfile:

            #create a loop to decrypt the file
            while True:
                chunk = infile.read(chunksize)

                #break out of the loop when you reach the end of the file
                if len(chunk) == 0:
                    break

                #output the decrypted file
                outfile.write(decryptor.decrypt(chunk))
                    
            #remove padding added from the encryption process
            outfile.truncate(filesize)





def getKey(password):
    #create a hash for password provided by user
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()


def Main():
        #print to screen the following message                
        choice = input("would you like to (E)ncrypt or (D)ecrypt?: ")

        #if the user types E, run the encryption function
        if choice == 'E':

                #get the name of the file to encrypt from user       
                filename = input("File to encrypt: ")

                #get a password from the user
                password = input("Password: ")

                #hash the password and and encrypt the file        
                encrypt(getKey(password), filename)

                print("All Done")
                        
        #if the user types D, run the decryption function
        elif choice == 'D':

                #get the name of the file to decrypt from user       
                filename = input("File to decrypt: ")

                #get a password from the user
                password = input("Password: ")

                #hash the password and and decrypt the file        
                decrypt(getKey(password), filename)

                print("All Done")
        else:
                print("No option was selected, closing program..")




if __name__== '__main__':
        Main()
                




                        
                        
    

















