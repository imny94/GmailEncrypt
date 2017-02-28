from GmailEncrypt import EncryptionWorker

'''
Create a Python application to retrieve items in specific Gmail mailbox (filtered by specified period of time) 
and store them in the same folder in encrypted form (algorithm should be chosen by yourself). 
Parameters are: mailbox name, mailbox password, start of the retrieval period, end of the retrieval period. 
You need to use official API provided by Google, no IMAP/POP3.
'''


def main():
	argv = []
	argv.append(raw_input("mailbox name without @gmail.com: "))
	argv[0] = argv[0] + "@gmail.com"
	argv.append(raw_input("mailbox password : "))
	argv.append(raw_input("start date in form YYYY/MM/DD : "))
	argv.append(raw_input("end date in form YYYY/MM/DD : "))
	argv.append(raw_input("Type a password if you wish to use a password as key for encryption and decryption, else, leave blank and press enter : "))

	user = argv[0]
	password = argv[1]
	startDate = argv[2]
	endDate = argv[3]
	optionalEncryptionPassword = argv[4]
	if optionalEncryptionPassword == "":
		optionalEncryptionPassword = None

	EncryptionModel = EncryptionWorker(user,password)
	EncryptionModel.runEncryption(startDate,endDate,optionalEncryptionPassword)
 
if __name__ == '__main__':
	main()

# import argparse
# parser = argparse.ArgumentParser()
# parser.add_argument("user", help="mailbox name")
# parser.add_argument("password", help="mailbox password")
# parser.add_argument("startDate", help="start of retrival period")
# parser.add_argument("endDate", help="end of retrival period")
# parser.add_argument("optionalEncryptionPassword", "--verbosity", help="Optional password to be used for encryption")
# parser.add_argument("-v", "--verbosity", action="count", default=0)
# args = parser.parse_args()
# print args
