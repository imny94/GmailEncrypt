from __future__ import print_function
import httplib2
import os
from apiclient import errors

from apiclient import discovery
from oauth2client import client
from oauth2client import tools
from oauth2client import file

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pickle
from CredentialsGetter import CredentialsGetter

try:
    import argparse
    flags = argparse.ArgumentParser(parents=[tools.argparser]).parse_args()
except ImportError:
    flags = None

class EncryptionWorker():

	'''
	This Class is used to either run encryption or decryption of the given data from Gmail.
	The main purpose of this class is to encapsulate the relevant methods required for the
	encryption and decryption process, allowing easy encryption or decryption of the desired
	data. 

	To Toggle between Encryption or Decryption, choose between the methods:
		runEncryption(startDate,endDate, optionalPassword)
		runDecryption(startDate,endDate, optionalPassword)

	This class takes in 2 arguments on initialisation, username and password

	Note: 
		This encryption model only works for small scale encryption of data, if the data given
		for encryption is too large, the application will crash. 

	ARGS:
		username: Users gmail email address to login into google
		password: Users gmail email password

	'''

	def __init__(self,username,password,):
		self.user = username
		self.password = password
		self.SCOPES = 'https://mail.google.com'
		self.CLIENT_SECRET_FILE = 'client_id.json'
		self.APPLICATION_NAME = 'GmailEncryptFetcher'

	'''
	Entry Point to run Encryption
	'''

	def runEncryption(self,startDate,endDate,encryptPassword=None):
		"""
		Runs the Relevant steps in the encryption process

		Args:
			startDate: start searching from this date
			endDate: stop searching up to this date
		"""
		self.__start(startDate,endDate)
		self.salt = self.__setSalt()
		for i in self.messages:
			try:
				self.__encryptMessage(self.service,self.user,i['id'],self.salt,encryptPassword)
			except Exception:
				print("Error encrypting this message, skipping...")

	'''
	Entry Point to run Decryption
	'''

	def runDecryption(self,startDate,endDate,encryptPassword=None):
		"""
		Runs the Relevant steps in the decryption process

		Args:
			startDate: start searching from this date.
			endDate: stop searching up to this date

			startDate and endDate must be in form: YYYY/MM/DD

		"""
	  	self.__start(startDate,endDate)
		self.salt = self.__getSalt()
		for i in self.messages:
			try:
				self.__decryptMessage(self.service,self.user,i['id'],self.salt,encryptPassword)
			except Exception:
				print("Error encrypting this message, skipping...")

	'''
	This starts the relevant initialisation starting sequence
	'''

	def __start(self,startDate,endDate):
		'''
			This method starts the relevant set-up process for the program.
		'''

		self.credentials = self.__get_credentials()
		self.http = self.credentials.authorize(httplib2.Http())
		self.service = discovery.build('gmail', 'v1', http=self.http)

		self.messages = self.__ListMessagesMatchingQuery("after:"+startDate+" before:"+endDate)

	'''
	Gets Relevant Credentials used for authentication
	'''

	def __get_credentials(self):
	    """Gets valid user credentials from storage.

	    If nothing has been stored, or if the stored credentials are invalid,
	    the OAuth2 flow is completed to obtain the new credentials.

	    Returns:
	        Credentials, the obtained credential.
	    """
	    home_dir = os.path.expanduser('~')
	    credential_dir = os.path.join(home_dir, '.credentials')
	    if not os.path.exists(credential_dir):
	        os.makedirs(credential_dir)
	    credential_path = os.path.join(credential_dir,
	                                   'gmail-python-encrypt.json')

	    store = file.Storage(credential_path)
	    credentials = store.get()
	    if not credentials or credentials.invalid:
	    	if not os.path.exists(self.CLIENT_SECRET_FILE):
	    		print("starting web scrapper...")
		    	getJSON = CredentialsGetter(self.user,self.password)
		    	getJSON.start() # Runs the webscraper to get relevant JSON File. Some user input is required after this step. Refer to CredentialsGetter Class for more info, or refer to Readme.

	        flow = client.flow_from_clientsecrets(self.CLIENT_SECRET_FILE, self.SCOPES)
	        flow.user_agent = self.APPLICATION_NAME
	        if flags:
	            credentials = tools.run_flow(flow, store, flags)
	        else: # Needed only for compatibility with Python 2.6
	            credentials = tools.run(flow, store)
	        print('Storing credentials to ' + credential_path)
	    return credentials

	"""Get a list of Messages from the user's mailbox.
	"""

	def __ListMessagesMatchingQuery(self, query=''):
	  """List all Messages of the user's mailbox matching the query.

	  Args:
	    query: String used to filter messages returned.
	    Eg.- 'from:user@some_domain.com' for Messages from a particular sender.

	  Returns:
	    List of Messages that match the criteria of the query. Note that the
	    returned list contains Message IDs, you must use get with the
	    appropriate ID to get the details of a Message.
	  """
	  print(query)
	  try:
	    response = self.service.users().messages().list(userId=self.user,
	                                               q=query).execute()
	    messages = []
	    if 'messages' in response:
	      messages.extend(response['messages'])

	    while 'nextPageToken' in response:
	      page_token = response['nextPageToken']
	      response = self.service.users().messages().list(userId=self.user, q=query,
	                                         pageToken=page_token).execute()
	      messages.extend(response['messages'])

	    return messages
	  except errors.HttpError, error:
	    print ('An error occurred: %s' % error)

	'''
	Sets and saves the salt used for encryption to allow for decryption
	'''

	def __setSalt(self):
		"""
		Saves randomly generated salt for storage under root folder in folder named ".gmailsalt".
		File name is 'gmail-python-encrypt-salt.json'

	    Returns:
	        value of salt
	    """

		salt = os.urandom(16)

		home_dir = os.path.expanduser('~')
		salt_dir = os.path.join(home_dir, '.gmailsalt')
		if not os.path.exists(salt_dir):
			os.makedirs(salt_dir)
		salt_path = os.path.join(salt_dir,'gmail-python-encrypt-salt.json')

		saltFile = open(salt_path+".txt","w")
		saltFile.write(salt)
		saltFile.close()
		return salt

	'''
	Gets the salt used for encryption to allow decryption
	'''

	def __getSalt(self):
		"""
		Retrieves previously randomly generated salt in storage under root folder in folder named ".gmailsalt".
		File name is 'gmail-python-encrypt-salt.json'

	    Returns:
	        value of salt
	    """
		home_dir = os.path.expanduser('~')
		salt_dir = os.path.join(home_dir, '.gmailsalt')
		salt_path = os.path.join(salt_dir,'gmail-python-encrypt-salt.json')

		saltFile = open(salt_path+".txt","r")
		salt = saltFile.read()
		saltFile.close()
		return salt

	'''
	Returns a Fernet Object which can be used for encryption and decryption
	'''

	def __getEncryptionObject(self,salt, encryptPassword = None):
  		"""
		If Encryption password is given,
		Creates Object required for Encryption from given encryption password and returns the object for use.

		Otherwise, Creates Object required for Encryption from given present key(It will create a new key if not present) 
		and returns the object for use.

		Args:
			salt: value of salt to be used to encrypt and decrypt data
			encryptPassword: Optional password used to encrypt and decrypt data

		Returns:
			Fernet Object which can be used to encrypt or decrypt data
		"""

	  	if encryptPassword != None:
			kdf = PBKDF2HMAC(
				algorithm=hashes.SHA256(),
				length=32,
				salt=salt,
				iterations=100000,
				backend=default_backend()
				)
			key = base64.urlsafe_b64encode(kdf.derive(encryptPassword))
			return Fernet(key)
		
		else:
			home_dir = os.path.expanduser('~')
			key_dir = os.path.join(home_dir, '.fernetkey')
			if not os.path.exists(key_dir):
				os.makedirs(key_dir)
				key = Fernet.generate_key()
				f = Fernet(key)
				key_path = os.path.join(key_dir,'gmail-python-encrypt-key.json')

				keyFile = open(key_path+".txt","w")
				keyFile.write(key)
				keyFile.close()
				return f
			else:
				key_path = os.path.join(key_dir,'gmail-python-encrypt-key.json')

				keyFile = open(key_path+".txt","r")
				key = keyFile.read()
				keyFile.close()
				return Fernet(key)

	'''
	Gets relevant message, encrypts message, uploads message to Gmail, and deletes unencrypted message
	'''

	def __encryptMessage(self,service, user_id, msg_id, salt, encryptPassword=None): 
		"""
		Obtains messages from Gmail account and ecrypts the contents of the email.
		After Encryption of the email, encrypted mail will be uploaded to gmail account
		with subject as "encrypted mail", designated to 'me' from 'me'
		After uploading encrypted contents, the unencypted mail will be deleted from mailbox

		Args:
			service: gmail service to be used to access gmail account
			user_id: Authenticated owner of Gmail Account
			msg_id: msg_id used to identify the messages to fetch from Gmail account
			encryptPassword: Optional password used to encrypt and decrypt data
			salt: value of salt to be used to encrypt and decrypt data

		"""

		try:
			f =self.__getEncryptionObject(salt,encryptPassword)

			message = service.users().messages().get(userId=user_id, id=msg_id , format = "raw").execute()
			tokenForFile = {}

			for i in message.keys():
				if i != "historyId" and i != "internalDate" and i != "sizeEstimate" and i != 'labelIds' and i != 'threadId':
					token = f.encrypt(bytes(message[i]))
					tokenForFile[i] = token

			newMessage = MIMEMultipart()
			newMessage['to'] = 'me'
			newMessage['from'] = 'me'
			newMessage['subject'] = 'encrypted mail'

			msg = MIMEText(pickle.dumps(tokenForFile), _subtype='plain')
			msg.add_header("Encrypted-Mail", 'attachment' , filename = 'Token.txt')
			newMessage.attach(msg)

			toInclude = {'raw': base64.urlsafe_b64encode(newMessage.as_string())}
			toInclude['labelIds'] = message['labelIds']

			print ('... Trying to upload now ... ')
			service.users().messages().insert(userId=user_id,body=toInclude).execute()
			
			service.users().messages().delete(userId=user_id, id=msg_id).execute()		# Comment out if you want to keep unencrypted email in mailbox
			print ('Message with id: %s deleted successfully.' % msg_id)

		except errors.HttpError, error:
			print ('An error occurred: %s' % error)

	'''
	Gets relevant encrypted message, decrypts message, uploads message to Gmail
	'''

	def __decryptMessage(self,service, user_id, msg_id, salt, encryptPassword=None): 
		"""
		Obtains messages from Gmail account and decrypts the contents of the email.
		After Decryption of the email, decrypted mail will be uploaded to gmail account
		with original subject, sender and receipient

		Args:
			service: gmail service to be used to access gmail account
			user_id: Authenticated owner of Gmail Account
			msg_id: msg_id used to identify the messages to fetch from Gmail account
			encryptPassword: Optional password used to encrypt and decrypt data
			salt: value of salt to be used to encrypt and decrypt data

		"""

		try:
			f = self.__getEncryptionObject(salt,encryptPassword)

			fullMessage = service.users().messages().get(userId=user_id, id=msg_id ).execute()
			unEncodedMessage = fullMessage['payload']['parts'][0]['body']['data']
			
			message = base64.urlsafe_b64decode(unEncodedMessage.encode('ascii'))
			messageDict = pickle.loads(message)
			clearMessageDict = {}
			clearMessageDict['labelIds'] = fullMessage['labelIds']
			
			for i in messageDict.keys():
				if i != "historyId" and i != "internalDate" and i != "sizeEstimate" and i != 'labelIds' and i != 'threadId':
					clearMessageDict[i] = f.decrypt(messageDict[i])

			print ('... Trying to upload decrypted Version now ... ')
			service.users().messages().insert(userId=user_id,
												body=clearMessageDict).execute()

		except errors.HttpError, error:
			print ('An error occurred: %s' % error)
