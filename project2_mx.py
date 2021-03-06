#!/usr/bin/env python
# coding: utf-8

# In[246]:


import smtplib
import time
import imaplib
import email
import traceback
import pandas
from email.message import EmailMessage
from cryptography.fernet import Fernet 
from cryptography.hamzat.primitives import hashes
from cryptography.hamzat.primitives.kdf.pdkdf2 import PBKDF2HMAC



# In[265]:


ALICE_USER = 'x'
ALICE_PSWD = 'x'

BOB_USER = 'x'
BOB_PSWD = 'x'

SUBJECT_PREFIX = '[SECUREMAIL]'     #ALL EMAILS NEED THIS PREFIX
SUBJECT_SHARED_KEY = '[SHARED_KEY]' #EMAIL SENDING SHARED KEY HAS SUBJECT  [SECUREMAIL][SHARED_KEY]
SUBJECT_PUBLIC_KEY = '[PUBLIC_KEY]' #EMAIL SENDING PUBLIC KEY HAS SUBJECT  [SECUREMAIL][PUBLIC_KEY]
SUBJECT_REQUEST_PUBLIC_KEY = '[REQUEST_PUBLIC_KEY]' #EMAIL REQUESTING PUBLIC KEY HAS SUBJECT  [SECUREMAIL][REQUEST_PUBLIC_KEY]


# In[123]:


#login via smtp
def login_smtp(user, password):

    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(user, password)
        print('Login Successful!')
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    return server


# In[130]:


def login_imap(user, password):

    try:
        server = imaplib.IMAP4_SSL('imap.gmail.com')
        server.login(user, password)
        print('Login Successful!')
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    return server


# In[253]:


#send email. Input user is a tuple of (USERNAME, PASSWORD)
def send(user, receiver, subject, message):
    
    server = login_smtp(user[0],user[1])
    
    msg = EmailMessage()
    msg['Subject'] = SUBJECT_PREFIX + subject
    msg['From'] = user
    msg['To'] = receiver
    msg.set_content(message)
    
    try:
        server.send_message(msg)
        print('Sent!')
    except Exception as e:
        traceback.print_exc() 
        print(str(e))
    
    server.quit()


# In[312]:


#get email list
def get_email_list(server):
    
    try:
        server.select('inbox')
        res, mail_ids = server.search(None, 'SUBJECT', SUBJECT_PREFIX) #CHANGE ACCORDINGLY
        id_list = mail_ids[0].split()
    except Exception as e:
        traceback.print_exc() 
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
        traceback.print_exc() 
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
        return str(msg.get_payload(None, True),'utf-8')

#read email. 
#Output is a tuple. tuple[0] is from, [1] is subject, [2] is date, [3] is body.
def read(user):
    
    server = login_imap(user[0],user[1])
    mailList = get_email_list(server)
    print('\n---------------------EMAIL LIST--------------------\n',
         '--- Email ID --- From --- Subject --- Date ---\n')
    for item in mailList:
        print(item, '\n')
    
    eid = input("Select an email id to read: ")
    msg = get_email(server, eid)
    mailHeader = get_header(msg)
    mailBody = get_body(msg)
        
    server.close()
    server.logout()
    
    return (mailHeader + (mailBody,))


# In[303]:


#get the shared_key from email
#Input: keyName should be either SUBJECT_SHARED_KEY = '[SHARED_KEY]' or SUBJECT_PUBLIC_KEY = '[PUBLIC_KEY]'
#return key or None if not found
def get_key(user, sentFrom, keyName):
    
    try:
        server = login_imap(user[0],user[1])
        server.select('inbox')
        res, mail_ids = server.search(None, f"SUBJECT {SUBJECT_PREFIX + keyName} FROM {sentFrom}")
        id_list = mail_ids[0].split()
        if len(id_list) == 0:
            sharedKey = None
        else:
            #get the latest key sharing email
            msg = get_email(server, int(id_list[-1]))
            sharedKey = get_body(msg)           
    except Exception as e:
        #traceback.print_exc() 
        print(str(e))
    
    server.close()
    server.logout()
    
    return sharedKey

# generate a key(for message encryption) and store it into a file
def generate_key():
	key = Fernet.generate_key()
	with open("secret.key", "wb") as key_file:
		key_file.write(key)


# load the previously generated key
def load_key():

	return open("secret.key", "rb").read()

# Encrypts a message
def encrypt_message(message):
	key = load_key()
	encoded_message = message.encode()
	f = Fernet(key)
	encrypted_message = f.encrypt(encoded_message)

	return encrypted_message

	#print(encrypted_message)

# Decrypts a message
def decrypt_message(encrypted_message):
	key = load_key()
	f = Fernet(key)
	decrypted_message = f.decrypt(encrypted_message)

	return decrypted_message


	#print(decrypted_message.decode())







# In[ ]:


def main():
    print("Welcome to [SECUREMAIL]\n")
    username = input("Please enter your gmail username: ")
    password = input("Please enter your password: ")
    user = (username, password)
    
    while(true):
        menu = input("Please select: \n1. Send Email \n2. Read Email \n3.Quit")
        match menu:
            case 1: 
                #Send Email
                print("Please create a new email.\n")
                receiver = input("To: ")
                subject = input("Subject: ")
                body = input("Content: ")
                
                #check if key exchange is required <--AL
                #key exchange:
                #should store private key in some place related to bob's email address 
                                
                #Encryption: <--TLY
                #encrypt body
                #return cBody

                cBody = encrypt_message(body)

                
                send(user, receiver, cSubject, cBody)
                
            case 2: #Read Email   
                cMail = read(user)
                                
                #check if shared privated key is available <-- AL
                #if not, search email to get the shared private key sent by Alice (maybe with a special name)
                #Aiden: please use the function get_key() code to get the encrypted key from server 
                #and use your function to decrypt it                   
                
                #Decryption: <--TLY
                #decrypt cBody=cMail[3]
                #return body
                
                cBody = cMail[3]
                body = decrypt_message(cBody)
                print('\n----------------EMAIL STARTS---------------\n',
                      'From: ' + cMail[0] + '\n', 
                      'Subject: ' + subject + '\n',
                      'Date: ' + cMail[2]+ '\n',
                      '\n' + body,
                      '\n----------------EMAIL ENDS-----------------\n')
            
            case 3: #Quit
                print("Quiting [SECUREMAIL]...")
                break
    
    print("Terminated.")
    return      


# In[258]:


#test case: send
user = (ALICE_USER, ALICE_PSWD)
subject = "[SHARED_KEY]"
message = "hello world!"
send(user, BOB_USER, subject, message)


# In[314]:


#test case: read email list
user = (BOB_USER, BOB_PSWD)
msg = read(user)
msg


# In[310]:


#test case: get key
user = (BOB_USER, BOB_PSWD)
key = get_key(user, ALICE_USER, SUBJECT_SHARED_KEY)
key

