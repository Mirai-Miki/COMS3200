### assign2.py
### Author: Michael Bossner

import sys
import os
from socket import *
import signal
import time

############################### Constants #####################################

RECV_SIZE = 1500
PACKET_SIZE = 1472
PAYLOAD_SIZE = 1466
LOCALHOST = "127.0.0.1"
UNUSED_PORT = 0
MY_PORT = 1

FLAG_MASK = 0b00000111

ACK = 16
NAK = 8
GET = 4
DAT = 2
FIN = 1

########################## Function Definitions ###############################

def main():
	conn = Connection()
	conn.openSocket()
	conn.handleIncoming()
	return

def str_to_byte(string, pad=PAYLOAD_SIZE):
    b_str = string.encode("UTF-8")
    if pad is not None:
        for i in range(len(string), pad):
            b_str += b'\0'
    return b_str

def int_to_str(integer, size=PAYLOAD_SIZE):
    return integer.to_bytes(size, byteorder='big').rstrip(b'\x00').decode("UTF-8")

############################# Class Definitions ###############################

# Handles server functionality
class Connection:
	def __init__(self):
		self._my_info = ((LOCALHOST, UNUSED_PORT))
		self._client = None
		self._sock = None
		self._seqNum = 1
		self._clientSeqNum = 0
		self._file = None

	# Opens a socket and prints the port to STDOUT
	def openSocket(self):
		self._sock = socket(AF_INET, SOCK_DGRAM)
		self._sock.bind(self._my_info)	
		print(self._sock.getsockname()[MY_PORT])
		sys.stdout.flush()

	
	def recvPkt(self, flags, altFlags=None):
		while (True):
			data = self._sock.recvfrom(RECV_SIZE)
			pkt = Packet(data=data)
			if not pkt.isRush():
				print("is not a rush packet")
				continue
			elif (self._client != None and \
					pkt.senderInfo[1] != self._client[1]):
				# another port sent a packet
				print("sender:"+str(pkt.senderInfo[1])+" is not the client: "+\
					str(self._client[1]))
				continue
			else:
				if (pkt._flags == flags or \
						(altFlags != None and pkt._flags == altFlags)):
					# Flags are what we expected
					if (self.isCorrupt(pkt)):
						print("Packet is Corrupt")
						continue
					else:
						break
				else:
					# Did not expect those flags
					print("Flag received was "+str(pkt._flags)+" we wanted "\
						+str(flags)+" or "+str(altFlags))
		
		self._clientSeqNum = pkt._seqNum
		print("Received packet from port "+str(pkt.senderInfo[1]))
		print("(seq_num="+str(pkt._seqNum)+", ack_num="+str(pkt._ackNum)\
			+", flags="+str(pkt._flags)+")")
		print("Data:", pkt.body)
		print("")
		return pkt

	def isCorrupt(self, pkt):
		if (pkt._flags & ACK or pkt._flags & NAK): # packet contains ACK or NAK
			if (pkt._ackNum != (self._seqNum - 1)):
				print("pkt._ackNum-"+str(pkt._ackNum)+" != "+\
					"lastPktSent-" + str((self._seqNum - 1)))
				return True
		elif (pkt._flags & GET):
			if (pkt._seqNum != 1):
				print("Get packets sequence is not 1")
				return True
			elif (pkt._ackNum != 0):
				print("GET is set and ack number is not 0")
				return True
			elif (pkt.body == ""):
				print("GET is set and no file requested")
				return True
		
		if (pkt._seqNum != (self._clientSeqNum + 1)):
			print("packets sequence number is not + 1 in order")
			return True
		elif (pkt._flags & 0b11011 and pkt.body != ""):
			# if GET is not set the body should be empty
			print("if GET is not set the body should be empty")
			return True

		return False

	def sendPkt(self, pkt):
		self._sock.sendto(pkt.rush(), self._client)
		print("Sent packet from port "+str(self._sock.getsockname()[MY_PORT]))
		print("(seq_num="+str(pkt._seqNum)+", ack_num="+str(pkt._ackNum)\
			+", flags="+str(pkt._flags)+")")
		print("")

	def terminateConn(self):
		print("Start termination")
		# send FIN packet
		pkt = Packet(flags=FIN, seqNum=self._seqNum)
		self.sendPkt(pkt)
		self._seqNum += 1

		# wait for FIN/ACK
		self.timeout(pkt, (FIN + ACK))

		# parse packet
		self.sendPkt(Packet(flags=(FIN + ACK), seqNum=self._seqNum, \
				ackNum=self._clientSeqNum))

		# send FIN/ACK
		self._sock.close()

	def fileLoop(self):
		# open and read from file
		file = open(self._file, "r")
		body = file.read()
		bSize = len(body)
		bIndex = 0

		while (True):
			# send packets containing file
			if (bIndex < (bSize - PAYLOAD_SIZE)):
				pktBody = body[bIndex : (PAYLOAD_SIZE + bIndex)]
				bIndex = (PAYLOAD_SIZE + bIndex)
			elif (bIndex == bSize):
				return
			else:
				pktBody = body[bIndex :]
				bIndex = None

			pkt = Packet(flags=DAT, seqNum=self._seqNum, body=pktBody)
			self.sendPkt(pkt)
			self._seqNum += 1

			self.timeout(pkt, (ACK + DAT), altFlag=(NAK + DAT))			

			# exit loop when complete
			if (bIndex == None):
				return

	def timeout(self, pkt, flags, altFlag=None):
		pid = os.fork()

		if (pid == 0): # We are in the timeout process
			while (True):
				time.sleep(3)
				print("TIMEOUT! resending packet")
				self.sendPkt(pkt)

		else: # we are in the parent process
			# wait for acks	or naks		
			response = self.recvPkt(flags, altFlags=altFlag)
			# got uncorrupted ACK/DAT or NAK/DAT
			os.kill(pid, signal.SIGKILL)
			if (response._flags == (NAK + DAT)): # packet is NAK/DAT
				# resend packet and start timeout again
				self.sendPkt(pkt)
				self.timeout(pkt, flags, altFlag)
		
	def handleIncoming(self):
		# recv GET pkt
		pkt = self.recvPkt(GET)
		self._client = pkt.senderInfo
		self._file = pkt.body

		# send file requested
		self.fileLoop()
		# terminate connection
		self.terminateConn()

# Stores packet information.
class Packet:
	def __init__(self, data=None, flags=None, seqNum=None, body='', ackNum=0):
		self._data = data
		self._flags = flags
		self._seqNum = seqNum
		self._ackNum = ackNum	
		self.body = body
		self.senderInfo = None

	# Checks if packet information meets RUSH protocol standards
	# Return: returns True if packet is a RUSH Packet or false if not.
	def isRush(self):
		self.senderInfo = self._data[1]
		if len(self._data[0]) != PACKET_SIZE:
			return False
		flags = int.from_bytes(self._data[0][4:5], byteorder='big')
		if (flags & FLAG_MASK or \
			int.from_bytes(self._data[0][5:6], byteorder='big')):
			# there are bits set that should be null
			print("There were bits set in the flag header that"\
				" should of been null. Received: "+str(flags))
			print((flags & FLAG_MASK))
			print(self._data[0][5:6])
			return False
		self._seqNum = int.from_bytes(self._data[0][0:2], byteorder='big')
		self._ackNum = int.from_bytes(self._data[0][2:4], byteorder='big')
		self._flags = (((flags//2)//2)//2) # shifting the bits over 3
		self.body = self._data[0][6:].rstrip(b'\x00').decode('UTF-8')
		return True

	# takes packet information and returns the RUSH packet in bytes for use in 
	# sending across the network
	def rush(self):
		seqNum = self._seqNum.to_bytes(2, byteorder='big')
		ackNum = self._ackNum.to_bytes(2, byteorder='big')
		flags = (((self._flags*2)*2)*2).to_bytes(1, byteorder='big') + b'\0'

		header = (seqNum + ackNum + flags)

		return header + str_to_byte(self.body)

################################# Runs Main ###################################

main()