from Crypto.Cipher import AES
import md5,base64,os.path,getpass
descriptions = []
passwords = []
def encrypt(password, message):
	if len(password) > 16:
		password = password[:16]
	while len(password) < 16:
		password += "0"
	iv = md5.new(password).hexdigest()
	iv = iv[:16]
	cryption = AES.new(password,AES.MODE_CBC,iv)
	while len(message) % 16 != 0:
		message += "|"
	message = cryption.encrypt(message)
	return base64.b64encode(message)
def decrypt(password, message):
	message = base64.b64decode(message)
	if len(password) > 16:
		password = password[:16]
	while len(password) < 16:
		password += "0"
	iv = md5.new(password).hexdigest()
	iv = iv[:16]
	cryption = AES.new(password,AES.MODE_CBC,iv)
	message = cryption.decrypt(message)
	while message[-1:] == "|":
		message = message[:-1]
	return message
def readPasswordsFromFile(password,filename):
	if os.path.isfile(filename):
		global descriptions,passwords
		lastread = 0
		for line in open(filename,"r").readlines():
			while line[-1:] == "\n":
				line = line[:-1]
			if lastread == 0:
				lastread = 1
				descriptions.append(decrypt(password,line))
			elif lastread == 1:
				lastread = 0
				passwords.append(decrypt(password,line))
	else:
		f = open(filename,"w")
		f.close()
def writePasswordsToFile(password,filename):
	global descriptions,passwords
	f = open(filename,"w")
	for x in range(len(passwords)):
		f.write(encrypt(password,descriptions[x])+"\n")
		f.write(encrypt(password,passwords[x])+"\n")
	f.close()
def showPassword():
	description = raw_input("Name: ")
	global descriptions,passwords
	for x in range(len(passwords)):
		if descriptions[x] == description and passwords[x][:2] == "!!":
			print(passwords[x][2:])
			return 0
	print("No password with that name exists")
def listDescriptions():
	global descriptions
	for x in range(len(descriptions)):
		if passwords[x][:2] == "!!":
			print(descriptions[x])
def addPassword():
	global descriptions,passwords
	description = raw_input("Name: ")
	password = getpass.getpass("Password: ")
	descriptions.append(description)
	passwords.append("!!"+password)
def delPassword():
	global descriptions,passwords
	description = raw_input("Name: ")
	for x in range(len(passwords)):
		if descriptions[x] == description:
			descriptions.pop(x)
			passwords.pop(x)
tfile = "passwords.dat"
password = getpass.getpass("Enter password: ")
readPasswordsFromFile(password,tfile)
uinput = raw_input(">")
while uinput != "exit" and uinput != "quit":
	if uinput == "help":
		print("--HELP--")
		print("-list - Shows names of passwords saved")
		print("-new  - Create new password")
		print("-del  - Delete password")
		print("-show - Show password")
	if uinput == "list":
		listDescriptions()
	if uinput == "new":
		addPassword()
		writePasswordsToFile(password,tfile)
	if uinput == "del":
		delPassword()
		writePasswordsToFile(password,tfile)
	if uinput == "show":
		showPassword()
	uinput = raw_input(">")
