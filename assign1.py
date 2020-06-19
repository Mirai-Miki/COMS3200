### Assign1.py
### Author: Michael Bossner 

import sys
from datetime import datetime, timedelta
from urllib.parse import urlparse
from socket import *

########################### Function Definitions ##############################

def main():	
	# take command line argument as URL
	url = urlparse(sys.argv[1])
	sock = socket(AF_INET, SOCK_STREAM)	
	print("URL Requested:", url.geturl())

	if (url.scheme == "https"):
		print("HTTPS Not Supported")
		return

	tcpConnect(sock, url)
	response = httpRequest(sock, url)

	while (response.get("status") == 301 or response.get("status") == 302):		

		print("Resource", response.get("moved"), "moved to", \
			response.get("redirect").geturl())

		if (response.get("redirect").scheme == "https"):
			print("HTTPS Not Supported")
			return

		sock = socket(AF_INET, SOCK_STREAM)
		tcpConnect(sock, response.get("redirect"))
		response = httpRequest(sock, response.get("redirect"))
	
	print("Retrieval Successful")
	print("Date Accessed:", \
		response.get("dateAccess").strftime("%d/%m/%Y %H:%M:%S"), "AEST")
	if (response.get("lastModified") == None):
		print("Last Modified not available")
	else:
		print("Last Modified:", \
			response.get("lastModified").strftime("%d/%m/%Y %H:%M:%S"), "AEST")

	storeBody(response)

	return

def tcpConnect(sock, url):
	# open tcp socket to the url
	sock.connect((url.hostname, 80))

	# extract TCP Info

	clientPort = str(sock.getsockname()[1])
	clientIP = str(gethostbyname(gethostname()))
	serverIP = str(sock.getpeername()[0])
	serverPort = str(sock.getpeername()[1])

	
	print("Client:", clientIP, clientPort)
	print("Server:", serverIP, serverPort)
	return

def httpRequest(sock, url):
	# request http document
	if (url.path == ""):
		get = "GET / HTTP/1.1\r\n"\
		"Host: " + url.hostname + "\r\n"\
		"User-Agent: Firefox/3.6.10\r\n"\
		"Accept: text/html,text/plain,text/css,text/javascript,"\
		"application/javascript,application/json,application/octet-stream\r\n"\
		"Accept-Language: en-us,en;q=0.5\r\n"\
		"Accept-Encoding: \r\n"\
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7\r\n"\
		"Keep-Alive: \r\n"\
		"Connection: close\r\n\r\n"
	else:
		get = "GET " + url.path + " HTTP/1.1\r\n"\
		"Host: " + url.hostname + "\r\n"\
		"User-Agent: Firefox/3.6.10\r\n"\
		"Accept: text/html,text/plain,text/css,text/javascript,"\
		"application/javascript,application/json,application/octet-stream\r\n"\
		"Accept-Language: en-us,en;q=0.5\r\n"\
		"Accept-Encoding: \r\n"\
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7\r\n"\
		"Keep-Alive: \r\n"\
		"Connection: close\r\n\r\n"

	sock.send(get.encode())

	# collects the HTTP response
	data = ''
	while (True):
		incoming = sock.recv(1024)
		if not incoming:
			break
		data = data + incoming.decode("utf-8")
	sock.close()
	
	#parses the header then stores the body of the response
	response = httpParse(data)	
	return response

# parses a HTTP response separating required information
def httpParse(data):
	# HTTP Response header
	header = data[0 : data.find("\r\n\r\n")]

	status, moved = findStatus(header)
	redirect = findRedirect(header)

	dateAcc = findDateAccess(header)
	lastMod = findLastModified(header)
	ext = findExt(header)

	# HTTP Response body
	body = data[(data.find("\r\n\r\n") + 4) : ]

	response = {
		"header": header,
		"ext": ext,
		"dateAccess": dateAcc,
		"lastModified": lastMod,
		"body": body,
		"status": status,
		"redirect": redirect,
		"moved": moved
	}
	return response

def findRedirect(header):
	url = header[(header.find("Location: ") + 10) :]
	if (url != -1):
		url = url[: url.find("\r\n")]
		redirect = urlparse(url)
	else:
		redirect = None
	return redirect

def findStatus(header):
	status = int(header[9:12])
	moved = None
	if (status >= 400 and status <= 599):
		print("Retrieval Failed (" + str(status) + ")")
		exit()
	elif (status == 302):
		moved = "temporarily"
	elif (status == 301):
		moved = "permanently"
	return status, moved

# Retrives the date accessed date and stores it in a datetime obj and prints
# the value after converting from GMT to AEST
def findDateAccess(header):
	if (header.find("Date:") != -1):
		date = header[(header.find("Date: ") + 11) :]
		date = date[: date.find("\r\n")]	
		dateAccess = datetime.strptime(date, '%d %b %Y %H:%M:%S %Z')
		dateAccess = gmtToAest(dateAccess)
	else: 
		dateAccess = None
		
	return dateAccess

# Retrives the last modified date and stores it in a datetime obj and prints
# the value after converting from GMT to AEST
def findLastModified(header):
	if (header.find("Last-Modified: ") == -1):
		lastMod = None
		return
	else:
		date = header[(header.find("Last-Modified: ") + 20) :]
		date = date[: date.find("\r\n")]
		lastMod = datetime.strptime(date, '%d %b %Y %H:%M:%S %Z')
		lastMod = gmtToAest(lastMod)
		
	return lastMod
	
# converts a datetime obj from GMT to AEST and returns it
def gmtToAest(date):
	aest = timedelta(hours=10)
	date += aest
	return date

# looks through a HTTP header and finds the type of file contents and returns
# the file extension
def findExt(header):
	fType = header[(header.find("Content-Type: ") + 14) :]
	fType = fType[: fType.find("\r\n")]
	ext = ""
	
	if (fType == "text/html"):
		ext = ".html"
	elif (fType == "text/plain"):
		ext = ".txt"
	elif (fType == "text/css"):
		ext = ".css"
	elif (fType == "text/javascript" or fType == "application/javascript"):
		ext = ".js"
	elif (fType == "application/json"):
		ext = ".json"
	elif (fType == "application/octet-stream"):
		ext = ""

	return ext

# stores the body of the HTTP response into a file
def storeBody(response):
	# contents of the http request should be written to a file
	f = open(("output" + response.get("ext")), 'w', encoding="utf-8")
	f.write(response.get("body"))
	f.close()
	return

################################# Runs Main ###################################

main()