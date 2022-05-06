#!/usr/bin/env python
# coding: utf-8

# In[246]:


import smtplib
import time
import imaplib
import email
import traceback
import pandas
import os
from email.message import EmailMessage
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# In[265]:


ALICE_USER = 'x'
ALICE_PSWD = 'x'

BOB_USER = 'x'
BOB_PSWD = 'x'

SUBJECT_PREFIX = '[SECUREMAIL]'     #ALL EMAILS NEED THIS PREFIX
SUBJECT_SHARED_KEY = '[SHARED_KEY]' #EMAIL SENDING SHARED KEY HAS SUBJECT  [SECUREMAIL][SHARED_KEY]
SUBJECT_PUBLIC_KEY = '[PUBLIC_KEY]' #EMAIL SENDING PUBLIC KEY HAS SUBJECT  [SECUREMAIL][PUBLIC_KEY]
SUBJECT_REQUEST_PUBLIC_KEY = '[REQUEST_PUBLIC_KEY]' #EMAIL REQUESTING PUBLIC KEY HAS SUBJECT  [SECUREMAIL][REQUEST_PUBLIC_KEY]


KEY_PARAMETERS = dh.generate_parameters(generator=2, key_size=2048)         # parameters to use for key generation later
SECRET_KEY = b''
PUBLIC_KEY = b''

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
    
def generate_keys(name):
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

    # generate public key from secret key and encode to Byte type
    pub_key_encoded = sec_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # convert Byte type keys to String for processing
    sec_key_string = sec_key_encoded.decode()
    pub_key_string = pub_key_encoded.decode()

    # remove the begin/end key text from the RSA keys
    trimsec = sec_key_string.replace('-----BEGIN PRIVATE KEY-----', '')
    trimsec2 = trimsec.replace('-----END PRIVATE KEY-----', '')
    SECRET_KEY = trimsec2

    trimpub = pub_key_string.replace('-----BEGIN PUBLIC KEY-----', '')
    trimpub2 = trimpub.replace('-----END PUBLIC KEY-----', '')
    PUBLIC_KEY = trimpub2

    # save key files using the user's name
    sec_key_file = open('%s_sec.txt' % name, 'x')
    sec_key_file.write(SECRET_KEY)
    sec_key_file.close()
    
    pub_key_file = open('%s_pub.txt' % name, 'x')
    pub_key_file.write(PUBLIC_KEY)
    pub_key_file.close()

# In[ ]:


def main():
    print("Welcome to [SECUREMAIL]\n")
    username = input("Please enter your gmail username: ")
    password = input("Please enter your password: ")
    user = (username, password)
    name_trimmed = username.replace('@gmail.com', '') 

    saved_keys = []
    for j in os.listdir():
        if j.endswith('.txt'):
            user_name = j.replace('.txt', '')
            saved_keys.append(user_name)

    if name_trimmed not in saved_keys:                  # user doesn't have keys generated yet 
        print('Performing first-time key generation...\n.')
        generate_keys(name_trimmed)
        
    
    while(true):
        menu = input("Please select: \n1. Send Email \n2. Read Email \n3. Generate Keys  \n4. Quit")
        match menu:
            case 1: 
                #Send Email
                print("Please create a new email.\n")
                receiver = input("To: ")
                receiver_name = receiver.replace('spring2022@gmail.com', '')              # will be used for key checking
                subject = input("Subject: ")
                body = input("Content: ")
                
                #check if key exchange is required <--AL
                #key exchange:
                #should store private key in some place related to bob's email address 

                # make a list of all the users whose public keys are available already
                saved_keys = []
                for j in os.listdir():
                    if j.endswith('.txt'):
                        user_name = j.replace('.txt', '')
                        saved_keys.append(user_name)

                if receiver_name not in saved_keys:
                    print('Key for user %s not found. Please have them send their public key file\n.' % receiver)
                    break
                
                # get the public key of the current recipient 
                key_file = open('%s_pub.txt' % receiver_name) 
                receiver_pub = key_file.read()
                key_file.close()
                                
                #Encryption: <--TLY
                #encrypt subject and body
                #return cSubject, cBody
                
                send(user, receiver, cSubject, cBody)
                
            case 2: #Read Email   
                cMail = read(user)
                                
                #check if shared privated key is available <-- AL
                #if not, search email to get the shared private key sent by Alice (maybe with a special name)
                #Aiden: please use the function get_key() code to get the encrypted key from server 
                #and use your function to decrypt it                   
                
                sender = cMail(0)
                sender_name = sender.replace('spring2022@gmail.com', '')              # will be used for key checking

                saved_keys = []
                for j in os.listdir():
                    if j.endswith('.txt'):
                        user_name = j.replace('.txt', '')
                        saved_keys.append(user_name)

                if sender_name not in saved_keys:
                    print('Key for user %s not found. Please have them send their public key file\n.' % receiver)
                    break

                key_list_index = saved_keys.index(sender_name)
                sender_pub_key = saved_keys[key_list_index]

                #Decryption: <--TLY
                #decrypt cSubject=cMail[1] and cBody=cMail[3]
                #return subject and body
                
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

