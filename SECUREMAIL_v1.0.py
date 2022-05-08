#!/usr/bin/env python
# coding: utf-8

# #Alice's account
# username: refer to README file
# password: refer to README file

# 
# #Bob's account
# username: refer to README file
# password: refer to README file

import smtplib
import time
import imaplib
import email
import traceback
import pandas
import os
import datetime 
import base64
from email.message import EmailMessage
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet 
from cryptography.exceptions import InvalidSignature


###---CONSTANT---###
ALICE_USER = 'alicespring2022@gmail.com'
ALICE_PSWD = '!AliceX2022'

BOB_USER = 'bobspring2022@gmail.com'
BOB_PSWD = '!BobX2022'

SUBJECT_PREFIX = '[SECUREMAIL]'     #ALL EMAILS NEED THIS PREFIX
SUBJECT_SHARED_KEY = '[SHARED_KEY]' #EMAIL SENDING SHARED KEY HAS SUBJECT  [SECUREMAIL][SHARED_KEY]
SUBJECT_PUBLIC_KEY = '[PUBLIC_KEY]' #EMAIL SENDING PUBLIC KEY HAS SUBJECT  [SECUREMAIL][PUBLIC_KEY]
SUBJECT_REQUEST_PUBLIC_KEY = '[REQUEST_PUBLIC_KEY]' #EMAIL REQUESTING PUBLIC KEY HAS SUBJECT  [SECUREMAIL][REQUEST_PUBLIC_KEY]
SEPARATOR_SIGNATURE = b'------SIGNATURE------\n'

FILENAME_SUFFIX_SHARED = '_shared'
FILENAME_SUFFIX_SEC = '_sec'

TTL = 5 #Exception will be raised when exceeding TTL
MAX_ATTEMPT = 150  #Time out if exceeding MAX_ATTEMPT



###---INTERACTION WITH GMAIL SERVER---###
#login via smtp to send
def login_smtp(user, password):

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(user, password)
        #print('Login Successful!')
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    return server

#log in via imap to view
def login_imap(user, password):

    try:
        server = imaplib.IMAP4_SSL('imap.gmail.com')
        server.login(user, password)
        #print('Login Successful!')
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    return server

#send email. Input user is a tuple of (USERNAME, PASSWORD)
def send(user, receiver, subject, message):
    
    server = login_smtp(user[0],user[1])
    
    msg = EmailMessage()
    msg['Subject'] = SUBJECT_PREFIX + subject
    msg['From'] = user
    msg['To'] = receiver
    if type(message) == str:
        message = base64.urlsafe_b64encode(bytes(message,'utf-8')) 
    else:
        message = base64.urlsafe_b64encode(message) 
    
    msg.set_content(message.decode('utf-8')) 
    
    try:
        server.send_message(msg)
        print('Sent!')
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    server.quit()
    return

#get email list
def get_email_list(server):
    
    try:
        server.select('inbox')
        res, mail_ids = server.search(None, 'SUBJECT', SUBJECT_PREFIX) #CHANGE ACCORDINGLY
        #print(mail_ids)
        id_list = mail_ids[0].split()
    except Exception as e:
        #traceback.print_exc() 
        print(str(e)) 
        
    mailList = []
    for eid in range(int(id_list[-1]),int(id_list[0])-1, -1):
        msg = get_email(server, eid)  
        #print('msg=', msg)
        mailList.append((str(eid),) + get_header(msg))
        
    return mailList

#get an email object from fetch data. 
def get_email(server, eid):
    
    try:
        server.select('inbox')
        res, email_i = server.fetch(str(eid), '(RFC822)' ) 
        #email_i has len of 2. 
        #[0] is a tuple of the email index + content of the email.
        #[0][0] = index
        #[0][1] = content
        msg = email.message_from_string(str(email_i[0][1],'utf-8'))
        #print('msg=', msg)
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
        
    return msg

#get the header of an email. 
#Input is an object of class email
def get_header(msg):
    mailSubject = msg['subject']
    mailFrom = msg['from']
    mailDate = msg['date']
    return mailFrom, mailSubject, mailDate
    
#get the body of an email. 
#Input is an object of class email
def get_body(msg):
    if msg.is_multipart():
        return get_body(msg.get_payload(0))
    else:
        #return str(msg.get_payload(None, True),'utf-8')
        return base64.urlsafe_b64decode(msg.get_payload(None, True))

#read email. 
#Output is a tuple. tuple[0] is from, [1] is subject, [2] is date, [3] is body.
def read(user):
    
    server = login_imap(user[0],user[1])
    mailList = get_email_list(server)
    print('\n---------------------EMAIL LIST--------------------\n',
         '--- Email ID --- From --- Subject --- Date ---\n')
    for item in mailList:
        if (SUBJECT_SHARED_KEY in item[2]) or (SUBJECT_PUBLIC_KEY in item[2]) or (SUBJECT_REQUEST_PUBLIC_KEY in item[2]):
            continue
        print(item, '\n')
    
    eid = input("Select an email id to read: ")
    msg = get_email(server, eid)
    mailHeader = get_header(msg)
    mailBody = get_body(msg)
        
    server.close()
    server.logout()
    
    return (mailHeader + (mailBody,))

#get the shared_key from email
#Input: keyName should be either SUBJECT_SHARED_KEY = '[SHARED_KEY]' or SUBJECT_PUBLIC_KEY = '[PUBLIC_KEY]'
#return key or None if not found
def get_key_from_email(user, sentFrom, keyName):
    
    try:
        server = login_imap(user[0],user[1])
        server.select('inbox')
        res, mail_ids = server.search(None, f"SUBJECT {SUBJECT_PREFIX + keyName} FROM {sentFrom} UNSEEN")
        
        id_list = mail_ids[0].split()
        if len(id_list) == 0:
            key = None
        else:
            #get the latest key sharing email
            msg = get_email(server, int(id_list[-1]))
            key = get_body(msg)           
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    server.close()
    server.logout()
    
    return key

###---ASYMMETRIC ENCRYPTION AND DECRYPTION---###
#generate and store private key
def gen_private_key(user):
    # generate secret key
    sec_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # encode secret key to Byte type
    sec_key_encoded = sec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # save private key to pem file
    with open(user[0][:-10] + FILENAME_SUFFIX_SEC, 'wb') as pem_out:
        pem_out.write(sec_key_encoded)
    
    return

#load private key from local file
def load_private_key(user):
    # load private key to pem file
    with open(user[0][:-10] + FILENAME_SUFFIX_SEC, 'rb') as pem_in:
        pemlines = pem_in.read()
        
    sec_key = load_pem_private_key(pemlines, None, default_backend())
    
    return sec_key

#generate public key from private key
def gen_public_key(user):
    
    sec_key = load_private_key(user)
    
    #generate public key from secret key and encode to Byte type
    pub_key_bytes = sec_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return pub_key_bytes

#transfer public key from bytes to object
def load_public_key(public_key_bytes):
        
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    
    return public_key

#Encrypt RSA
def encrypt_RSA(public_key, message):
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

#Decrypt RSA
def decrypt_RSA(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

#Create Signature
def sign(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

#Verify Signature
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        print('Invalid Signature: Untrusted Public Key.\n')
        return False
    return True   


###---SYMMETRIC ENCRYPTION AND DECRYPTION---###
# generate shared_key(for message encryption) and store it into a file
def generate_shared_key(username):
    key = Fernet.generate_key()
    store_shared_key(username, key)
    return key

# store shared_key into a file
def store_shared_key(username, key):
    with open(username[:-10] + FILENAME_SUFFIX_SHARED + ".key", "wb") as key_file:
        key_file.write(key)
    return key

# load the previously generated key
def load_shared_key(username):
    return open(username[:-10] + FILENAME_SUFFIX_SHARED + ".key", "rb").read()

# Encrypts a message
def encrypt_AES(key, message):
    encoded_message = message.encode()
    f = Fernet(key)
    encrypted_message = f.encrypt(encoded_message)
    return encrypted_message

# Decrypts a message
# emailtime is msg[2]
def decrypt_AES(key, encrypted_message, emailtime, ttl):       
    decrypted_message=b''    
    f = Fernet(key)
    try:
        timestamp = f.extract_timestamp(encrypted_message)
    except Exception as e:
        print("Warning: Invalid Token.")
        
    if verify_timestamp(timestamp, emailtime, TTL) == False:
        print("Warning: Invalid Timestamp! Data Replay Attack Detected!\n")  
        return decrypted_message
    
    try:
        decrypted_message = f.decrypt(encrypted_message) 
    except Exception as e:
        print("Warning: Invalid MAC Tag! Data Modification Attack Detected!\n")
         
    return decrypted_message

#Verify if timestamp is vaild
def verify_timestamp(timestamp, emailtime, ttl):
    timestamp_time = datetime.datetime.fromtimestamp(float(timestamp)) # convert UNIX time to datetime
    emailtime_parsed = email.utils.parsedate(emailtime)
    emailtime_utc = time.mktime(emailtime_parsed)
    #print("emailtime_utc=",emailtime_utc)
    emailtime_time = datetime.datetime.fromtimestamp(emailtime_utc)
    #print("emailtime_time=",emailtime_time)
    interval = (emailtime_time - timestamp_time).total_seconds() / 60
    if interval > ttl:
        return False
    else:
        return True


###---KEY EXCHANGE HANDLING---###
def key_exchange(user, receiver):   
    #check if key exchange is necessary
    if check_key(receiver, FILENAME_SUFFIX_SHARED) == False: # user doesn't have shared key
        #scan if there's unseen pk request from receiver
        body = get_key_from_email(user, receiver, SUBJECT_REQUEST_PUBLIC_KEY)
        if body == None:
            print("Please make sure the other party join connection in 5 mins.")
            shared_key = key_exchange_request(user, receiver)            
        else: 
            shared_key = key_exchange_accept(user, receiver)        
    else:
        shared_key = load_shared_key(receiver)
    
    print("key exchange finished.\n")
    return shared_key

def key_exchange_request(user, receiver):
    #send email to request public key
    send(user, receiver, SUBJECT_REQUEST_PUBLIC_KEY, "")
    print(SUBJECT_REQUEST_PUBLIC_KEY + " sent.\n")
    
    #loop checking if public key is received
    attempt = 0
    while(True):
        time.sleep(2)
        #print("attemp" + str(attempt))        
        body = get_key_from_email(user, receiver, SUBJECT_PUBLIC_KEY)
        if body == None:
            attempt += 1
            if attempt > MAX_ATTEMPT:
                print("Key exhange time out.\n")
                shared_key=b''
                break
            continue
        
        print(SUBJECT_PUBLIC_KEY + " received.\n")
        public_key_bytes = body[:451]
        public_key = load_public_key(public_key_bytes)
        signature =  body[-256:]
            
        #verify signature and send shared key
        if verify_signature(public_key, public_key_bytes, signature) == True:
            shared_key = generate_shared_key(receiver)
            shared_key_c = encrypt_RSA(public_key, shared_key)
            send(user, receiver, SUBJECT_SHARED_KEY, shared_key_c)
            print(SUBJECT_SHARED_KEY + " sent.\n")
            break
        else:
            break 
        
    return shared_key

def key_exchange_accept(user, receiver):
    
    #send my public to receiver
    my_pub_key_bytes = gen_public_key(user)
    my_pub_key = load_public_key(my_pub_key_bytes)
    my_signature = sign(my_pub_key_bytes, load_private_key(user))
    body = my_pub_key_bytes + SEPARATOR_SIGNATURE + my_signature
    send(user, receiver, SUBJECT_PUBLIC_KEY, body)
    print(SUBJECT_PUBLIC_KEY + " sent.\n")
        
    #loop checking if shared key is received
    attempt = 0
    while(True):
        time.sleep(2)
        #print("attemp" + str(attempt))
        body = get_key_from_email(user, receiver, SUBJECT_SHARED_KEY)
        if body == None:
            attempt += 1
            if attempt > MAX_ATTEMPT:
                print("Key exhange time out.\n")
                shared_key=b''
                break
            continue
        print(SUBJECT_SHARED_KEY + " received.\n")    
        
        #Decrypt shared key using private key
        shared_key_c = body
        shared_key = decrypt_RSA(load_private_key(user), shared_key_c)
        
        store_shared_key(receiver, shared_key)
        break   
    
    return shared_key

#check if key has been stored
#suffix can be: "_shared" or "_sec"
def check_key(username, suffix):
    #check if key is in store
    for filename in os.listdir():
        if username[:-10] + suffix in filename:
            return True
    
    return False


def main():
    print("Welcome to [SECUREMAIL]\n")
    username = input("Please enter your gmail address: ")
    password = input("Please enter your password: ")
    user = (username, password)
    
    #Check If user have sk_a stored
    #If no: generate sk_a
    if check_key(username, FILENAME_SUFFIX_SEC) == False: # user doesn't have keys generated yet
        gen_private_key(user)
    
    while(True):
        menu = input("""Please select: \n
                        1. Request Connection\n
                        2. Send Email \n
                        3. Read Email \n
                        4. Quit [SECUREMAIL]\n""")
        
        if menu == '1':
            # Request Connection: Key Exchange.
            # The first time connection can only be established when 2 parties are both in connection mode.
            # After that email can be sent anytime.
            receiver = input("Please enter the email address you want to connect: ")                
            shared_key = key_exchange(user, receiver)                
            if len(shared_key) >  0:
                print("You and " + receiver + " are connected now.\n")
            else:
                print(receiver + " is not online. Please try again later.\n")
                                   
        if menu == '2': 
            #Send Email
            receiver = input("To: ")
            subject = input("Subject: ")
            body = input("Content: ")
                
            #check if key exchange is required and key exchange 
            if check_key(receiver, FILENAME_SUFFIX_SHARED) == False:
                print("You are not connected with " + receiver +". Please Select Request Connection" )
                continue
                                
            #Encryption: 
            shared_key = load_shared_key(receiver)
            cBody = encrypt_AES(shared_key, body)
            send(user, receiver, subject, cBody)
                
        if menu == '3': 
            #Read Email   
            cMail = read(user)
            receiver = cMail[0]
            subject = cMail[1]
            date = cMail[2]
            cBody = cMail[3]
                                
            #check if key exchange is required and key exchange 
            if check_key(receiver, FILENAME_SUFFIX_SHARED) == False:
                print("You are not connected with " + receiver +". Please Select Request Connection" )
                continue                    
                
            #Decryption:
                
            shared_key = load_shared_key(receiver)
            body_bytes = decrypt_AES(shared_key, cBody, date, TTL)
            body = body_bytes.decode()
                
            print('\n----------------EMAIL STARTS---------------\n',
                    'From: ' + receiver + '\n', 
                    'Subject: ' + subject + '\n',
                    'Date: ' + date + '\n',
                    '\n' + body,
                    '\n----------------EMAIL ENDS-----------------\n')
            
        if menu == '4': 
            print("Quiting [SECUREMAIL]...")
            break
    
    print("Terminated.")
    return      


if __name__ == '__main__':
    main()






