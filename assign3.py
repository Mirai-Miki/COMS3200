### assign3.py
### Author: Michael Bossner

from socket import *
import os
import sys
import random
import signal

############################### Constants #####################################

MTU = 1500
IP_SIZE = 32
CIDR_MASK = [128, 192, 224, 240, 248, 252, 254, 255]
LOCALHOST = "127.0.0.1"

# Packet Constants
VER = 4
IHL = 5
TTL = 64
UDP = 17
NULL = 0
MORE_FRAGS = 1
# Bit sizes
VER_BITSHIFT = 4
DSCP_BITSHIFT = 2
FLAGS_BITSHIFT = 13
# Byte sizes
TOTAL_LEN_BYTE = 2
ID_BYTE = 2
TTL_BYTE = 1
PROTOCOL_BYTE = 1
CHECKSUM_BYTE = 2
SOURCE_IP_BYTE = 4
DEST_IP_BYTE = 4
TWO_BYTES = 65535
IPV4_HEADER_SIZE = (5*4)

# Cursor Escape Character
ERASE_LINE = '\b\b'
CARRAGE_RETURN = '\r'



########################## Function Definitions ###############################

def main():
	host = Host()
	host.run()

def str_to_ip(string):
	temp = ""
	ip = []
	for i in range((len(string) + 1)):
		if (i == len(string) or string[i] == "."):
			ip.append(int(temp))
			temp = ""
		else:
			temp = temp + string[i]
	return ip

def ip_to_str(ip):
	return str(ip[0])+"."+str(ip[1])+"."+str(ip[2])+"."+str(ip[3])

def byte_to_ip(bytes):
	ip = []
	for i in range(4):
		ip.append(bytes[i])

def int_to_byte(integer, size):
	return integer.to_bytes(size, byteorder='big')

def byte_to_int(byte):
	return int.from_bytes(byte, byteorder='big')

############################# Class Definitions ###############################

class Host:
	def __init__(self):
		self.ip_addr = None
		self.mac_addr = int(sys.argv[2])
		self.subnet = []
		self.subnet_mask = None
		self.subnet_index = None
		self.gw_ip = None
		self.arp_table = ArpTable()
		self.mtu = MTU
		self.pid = None
		self.sock = None
		self.id = 0
		self.init_host()

	def init_host(self):
		cidr = (int(sys.argv[1][(sys.argv[1].find("/") + 1):]) - 1)
		self.ip_addr = str_to_ip(sys.argv[1][: sys.argv[1].find("/")])

		if (cidr <= 7):
			self.subnet_mask = [CIDR_MASK[cidr], 0, 0, 0]
			self.subnet_index = 0
		elif (cidr <= 15):
			self.subnet_mask = [255, CIDR_MASK[(cidr - 8)], 0, 0]
			self.subnet_index = 1
		elif (cidr <= 23):
			self.subnet_mask = [255, 255, CIDR_MASK[(cidr - 24)], 0]
			self.subnet_index = 2
		elif (cidr <= 31):
			self.subnet_mask = [255, 255, 255, CIDR_MASK[(cidr - 32)]]
			self.subnet_index = 3

		for i in range(4):
			if (i > self.subnet_index):
				self.subnet.append(0)
			else:
				self.subnet.append((self.ip_addr[i] & self.subnet_mask[i]))

	def is_subnet(self, ip):
		for i in range(self.subnet_index):
			if ((ip[i] & self.subnet_mask[i]) != self.subnet[i]):
				return False
		return True

	def cli_loop(self):
		while(True):
			cmd = input("> ")

			if (cmd == "gw get"):
				self.gw_get(cmd)
				continue		
			elif (cmd == "mtu get"):
				print(str(self.mtu))
				sys.stdout.flush()
				continue
			elif (cmd == "exit"):
				if (self.pid != None):
					os.kill(self.pid, signal.SIGKILL)
					self.sock.close()
				return		
			elif (len(cmd) >= 8):
				if (cmd[: 4] == "msg "):					
					self.send(cmd[4:cmd.find(" ", 4)], \
							cmd[(cmd.find('"', 4)+1): -1])
					continue
				elif (cmd[: 7] == "gw set "):
					self.gw_ip = str_to_ip(cmd[7:])
					continue		
				elif (cmd[: 8] == "arp set "):
					self.arp_table.new(cmd[8:cmd.find(" ", 8)], \
							cmd[(cmd.find(" ", 8)+1):])
					continue
				elif (cmd[: 8] == "arp get "):
					mac = self.arp_table.get_mac(cmd[8:])
					if (mac):
						print(mac)
					else:
						print("None")

					sys.stdout.flush()
					continue		
				elif (cmd[: 8] == "mtu set "):	
					self.mtu = int(cmd[8:])
					continue

			# Not supported cmd
			print("Invalid Command")

	def gw_get(self, cmd):
		if (self.gw_ip == None):
			print("None")
		else:
			print(ip_to_str(self.gw_ip))
		sys.stdout.flush()

	def run(self):
		self.open_connection()
		self.recv_loop()
		self.cli_loop()

	def recv_loop(self):
		self.pid = os.fork()
		if (self.pid == 0): # We are in the recv process	
			self.frag_storage = {}
			while (True):
				message = self.sock.recvfrom(6500)
				frag_pkt = Packet(message[0])
				if not (frag_pkt.frag_offset == 0 and frag_pkt.flags == 0):
					pkt = self.restore_packets(frag_pkt)
					if (pkt == None):
						continue
				else:
					pkt = frag_pkt

				sys.stdout.write(ERASE_LINE)
				if (pkt.protcol == NULL):
					print("Message received from "+ip_to_str(pkt.source_ip)+\
							': "'+pkt.payload+'"')
				else:
					if (pkt.protcol < 10):						
						print("Message received from "+ip_to_str(pkt.source_ip)+\
								" with protocol 0x0"+str(pkt.protcol))
					else:
						print("Message received from "+ip_to_str(pkt.source_ip)+\
								" with protocol", hex(pkt.protcol))
				print("> ", end='')
				sys.stdout.flush()

	def restore_packets(self, pkt):
		# Packet Storage is set up as
		# {
		#	"192.168.1.1":   { 2: [pkt0, pkt4, pkt1, pkt2, pkt3]
		#					   6: [pkt0, pkt1] }
		#   "192.168.1.137": { 0: [pkt0, pkt1, pkt2]  }
		#   "192.1.1.1":	 { 2: [pkt1, pkt0] }
		# }
		sender = ip_to_str(pkt.source_ip)
		# We need to add the packet to our fragment storage
		if sender in self.frag_storage:
			# We already have this sender stored in fragment storage
			if pkt.id in self.frag_storage.get(sender):
				# We have the sender and we already have fragments
				self.frag_storage.get(sender).get(pkt.id).append(pkt)

			else: # We have the sender but it's a new fragged packet
				self.frag_storage.get(sender)[pkt.id] = [pkt]

		else: # No sender stored in fragment storage
			self.frag_storage[sender] = {pkt.id: [pkt]}

		# We need to check if the packet is complete
		offset = []
		last_pkt = False
		mtu = 0
		packets = self.frag_storage.get(sender).get(pkt.id)
		for i in range(len(packets)):
			offset.append(packets[i].frag_offset)
			if not (packets[i].flags): # this is the last packet
				last_pkt = True
			if (packets[i].frag_offset == 0): # This is the first packet
				mtu = ((packets[i].total_len - IPV4_HEADER_SIZE) // 8)
		if (last_pkt):
			# We have the last packet but we need to check if all the middle
			# packets have arrived
			for i in range(len(packets)):
				# If mtu is None we have not gotten the first packet
				# if (i * mtu) is not in offset we are missing a middle packet
				if not mtu or (i * mtu) not in offset:
					return None
			else:
				# We have all the packet fragments
				body = ''
				# We need to reassemble the message
				for index in range(len(packets)):					
					for i in range(len(packets)):
						if (packets[i].frag_offset == (index * mtu)):
							body += packets[i].payload
				# We just edit the last packet with the reconstructed message
				new_packet = packets[-1]
				new_packet.payload = body
				new_packet.frag_offset = 0

				# Now we remove the entry from storage to free up space
				if (len(self.frag_storage.get(sender)) == 1):
					# Sender only has 1 ID in storage so we also remove sender
					self.frag_storage.pop(sender)
				else: # There are multiple IDs stored so we just remove this ID
					self.frag_storage.get(sender).pop(pkt.id)
				return new_packet
		else: # the Last packet has not come in yet
			return None

	def send(self, dest, message):
		dest_ip = str_to_ip(dest)
		pkt = Packet()
		packets = pkt.construct(self.ip_addr, dest_ip, message, self.mtu, self.id)
		self.inc_id()
		if (self.is_subnet(dest_ip)):
			mac = self.arp_table.get_mac(ip_to_str(dest_ip))
			if (mac == None):
				print("No ARP entry found")
				sys.stdout.flush()
			else:
				self.send_packets(packets, mac)
		else:
			if (self.gw_ip == None):
				print("No gateway found")
				sys.stdout.flush()
			else:
				mac = self.arp_table.get_mac(ip_to_str(self.gw_ip))
				if (mac == None):
					print("No ARP entry found")
					sys.stdout.flush()
				else:
					self.send_packets(packets, mac)

	def send_packets(self, packets, mac):
		for i in range(len(packets)):
			self.sock.sendto(packets[i], (LOCALHOST, mac))

	def open_connection(self):
		self.sock = socket(AF_INET, SOCK_DGRAM)
		self.sock.bind((LOCALHOST, self.mac_addr))

	def inc_id(self):
		if (self.id > TWO_BYTES):
			self.id = 0
		else:
			self.id += 1

class ArpTable:
	def __init__(self):
		self.table = {}

	def get_mac(self, ip):
		return self.table.get(ip)

	def new(self, ip, mac):
		self.table[ip] = int(mac)

class Packet:
	def __init__(self, message=None):
		self.ver = None
		self.ihl = None
		self.dscp = None
		self.ecn = None
		self.total_len = None
		self.id = None
		self.flags = None
		self.frag_offset = None
		self.ttl = None
		self.protcol = None
		self.checksum = None
		self.source_ip = None
		self.dest_ip = None
		self.payload = None
		self.message = message

		if (message != None):
			self.deconstruct()

	def construct(self, source, dest, payload, set_mtu, ident):
		payload_size = len(payload)
		packets = []
		index = 0
		mtu = (set_mtu - IPV4_HEADER_SIZE) - ((set_mtu - IPV4_HEADER_SIZE) % 8)

		while (index < payload_size):
			self.ver = VER
			self.ihl = IHL
			self.dscp = NULL
			self.ecn = NULL
			if (index < (payload_size - mtu)):
				self.total_len = mtu + IPV4_HEADER_SIZE				
				self.flags = MORE_FRAGS
			else:
				self.total_len = IPV4_HEADER_SIZE + (len(payload) - index)
				self.flags = NULL
			self.id = ident
			self.frag_offset = (index // 8)
			self.ttl = TTL
			self.protcol = NULL
			self.checksum = NULL
			self.source_ip = (int_to_byte(source[0], 1)+int_to_byte(source[1], 1)+\
					int_to_byte(source[2], 1)+int_to_byte(source[3], 1))
			self.dest_ip = (int_to_byte(dest[0], 1)+int_to_byte(dest[1], 1)+\
					int_to_byte(dest[2], 1)+int_to_byte(dest[3], 1))
			self.payload = payload.encode("UTF-8")

			header = self.constHeader()

			if (index > (payload_size - mtu)):
				packets.append(header + self.payload[index:])
			else:
				packets.append(header + self.payload[index : (index + mtu)])
			index = (mtu + index)

		return packets

	def constHeader(self):
		byte0 = int_to_byte(((self.ver << VER_BITSHIFT) + self.ihl), 1)
		byte1 = int_to_byte(((self.dscp << DSCP_BITSHIFT) + self.ecn), 1)
		byte2_3 = int_to_byte(self.total_len, TOTAL_LEN_BYTE)
		byte4_5 = int_to_byte(self.id, ID_BYTE)
		byte6_7 = int_to_byte(((self.flags << FLAGS_BITSHIFT) + \
				self.frag_offset), 2)
		byte8 = int_to_byte(self.ttl, TTL_BYTE)
		byte9 = int_to_byte(self.protcol, PROTOCOL_BYTE)
		byte10_11 = int_to_byte(self.checksum, CHECKSUM_BYTE)
		byte12_15 = self.source_ip
		byte16_19 = self.dest_ip

		return (byte0+byte1+byte2_3+byte4_5+byte6_7+byte8+byte9+byte10_11+\
				byte12_15+byte16_19)

	def deconstruct(self):
		self.ver = ((self.message[0] & 0b11110000) >> VER_BITSHIFT)
		self.ihl = (self.message[0] & 0b00001111)
		self.dscp = ((self.message[1] & 0b11111100) >> DSCP_BITSHIFT)
		self.ecn = (self.message[1] & 0b00000011)
		self.total_len = byte_to_int(self.message[2:4])
		self.id = byte_to_int(self.message[4:6])
		self.flags = ((self.message[6] & 0b11100000) >> 5)
		self.frag_offset = (byte_to_int(self.message[6:8]) & 0b0001111111111111)
		self.ttl = self.message[8]
		self.protcol = self.message[9]
		self.checksum = byte_to_int(self.message[10:12])
		self.source_ip = [self.message[12], self.message[13], \
				self.message[14], self.message[15]]
		self.dest_ip = [self.message[16], self.message[17], \
				self.message[18], self.message[19]]
		self.payload = self.message[20:].decode("UTF-8")

################################# Runs Main ###################################

main()