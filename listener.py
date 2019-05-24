#!/usr/bin/env python3

import re
import socket
import sys
import argparse
import random
import hashlib

n = 9

addresses = {0:"192.168.1.231", 1:"192.168.1.232", 2:"192.168.1.233", 3:"192.168.1.234", 4:"192.168.1.235", 5:"192.168.1.236", 6:"192.168.1.237", 7:"192.168.1.238", 8:"192.168.1.239", 9:"192.168.1.240"}
metrics = []
routes = []
key = ['Wc2', 'S34', '', 'Cky', 'be3', 'ztN', '3HK', 'DD9', 'Rf2']

def create_parser():
	parser = argparse.ArgumentParser()
	parser.add_argument("own_id", nargs='?')
	return parser

def response(dst_id, packet):
	route = routes[dst_id]
	i = 0
	for host in route:
		if host == own_id:
			break
		i = i+1
	address = addresses[host]
	try:
		send = socket.socket()
		send.connect((address, 1984))
		send.send(packet.encode('utf-8'))
		send.close()
	except:
		return -1 

def Dijkstra(N, S, matrix):
    valid = [True]*N        
    weight = [1000000]*N
    weight[S] = 0
    routes = []
    for i in range(N):
        routes.append([])
    print(routes)
    for i in range(N):
        min_weight = 1000001
        ID_min_weight = -1
        for i in range(len(weight)):
            if valid[i] and weight[i] < min_weight:
                min_weight = weight[i]
                ID_min_weight = i
        for i in range(N):
            if weight[ID_min_weight] + matrix[ID_min_weight][i] < weight[i]:
                weight[i] = weight[ID_min_weight] + matrix[ID_min_weight][i]
                routes[i].append(ID_min_weight)
        valid[ID_min_weight] = False
    for i in range(N):
    	routes[i].append(i)
    return routes

def gen():
	iv = ""
	random.seed()
	for i in range(24):
		iv = iv + str(random.randint(41, 122))
	m = hashlib.md5()
	m.update(iv.encode('utf-8'))
	print(m.hexdigest())
	return str(m.hexdigest())

def write_packet(packet):
	f = open("/opt/scripts/packets.log", "a")
	f.write(packet)
	f.close()

def decrypt(cipher, key):
	msg = ""
	if len(key) < len(cipher):
		while len(key) < len(cipher):
			key = key + key
	for i in range(len(cipher)):
		msg = msg + chr(ord(cipher[i])^ord(key[i]))
	return msg

try:
	parser = create_parser()
	namespace = parser.parse_args()
	own_id = int(namespace.own_id)
except:
	print("Usage: python3 listener.py <own_id>")
	exit(0)

for i in range(n):
	routes.append([own_id])
	metrics.append([])
	if i!=own_id:
		routes[i].append(i)
	for j in range(n):
		if i == j:
			metrics[i].append(0)
			continue
		metrics[i].append(1)
routes.append([own_id, n])

listener = socket.socket()
listener.bind(('', 1984))
listener.listen(n)

packets = []
i=0
with open("/opt/scripts/packets.log") as f:
	for line in f:
		packets.append(line)
		i = i+1

msgtype = re.compile(b'MAIL|SERV')
srcid = re.compile(b'Src ([0-9]{1,3})')
dstid = re.compile(b'Dst ([0-9]{1,3})')
msg = re.compile(b'Msg (.{4,42})\n{0,1}')

while True:
	conn, addr = listener.accept()
	packet = conn.recv(63)
	if msgtype.findall(packet) == [] or srcid.findall(packet) == [] or dstid.findall(packet) == [] or msg.findall(packet) == []:
		conn.close()
		continue
	packets.append(packet)
	write_packet(packet.decode('utf-8'))
	src = int(srcid.findall(packets[i])[0])
	dst = int(dstid.findall(packets[i])[0])
	if dst!=own_id:
		conn.close()
		response(dst, packet)
		resp = "SERV Src " + str(own_id) + " Dst " + str(src) + " Msg SRLY"
		response(src, resp)
		write_packet(resp)
		i = i+1  
		continue
	else:
		mtype = msgtype.findall(packets[i])[0]
		mesg = msg.findall(packets[i])[0]
		if mtype == b'SERV':
			if mesg == b'SRCV' or mesg == b'SRLY':
				i = i+1
				conn.close()
				continue
			if mesg[0:4] == b'SMTR':
				conn.close()
				metric = int(msg[5:])
				metrics[src][own_id] = metric
				metrics[own_id][src] = metric
				routes = Dijkstra(n, own_id, metrics)
				resp = "SERV Src " + str(own_id) + " Dst " + str(src) + " Msg SRCV\n"
				response(src,resp)
				write_packet(resp)
				i = i+1
				continue
			if mesg[0:4] == b'SKEY':
				conn.close()
				key = int(msg[5:])
				keys[src] = key
				resp = "SERV Src " + str(own_id) + " Dst " + str(src) + " Msg SRCV\n"
				response(src, resp)
				write_packet(resp)
				i = i+1
				continue
			if mesg[0:4] == b'PING': # use only for debug
				ping = "PING"
				if src != own_id:
					ping = decrypt(ping, key[src])
				resp = "SERV Src " + str(own_id) + " Dst " + str(src) + " Msg " + ping + "\n"
				conn.send(resp.encode('utf-8'))
				write_packet(resp)
				packet = conn.recv(63)
				try:
					thing = msg.findall(packet)[0]
					packets.append(packet)
					write_packet(packet.decode('utf-8'))
				except:
					continue
				thing = thing.decode('utf-8')
				fl = decrypt(gen(), thing)
				resp = "MAIL Src " + str(own_id) + " Dst " + str(src) + " Msg " + fl + "\n"
				#conn.send(resp.encode('utf-8'))
				response(src, resp)
				write_packet(resp)
				conn.close()
				continue
			if mesg[0:4] == b'SSYN':
				for i in range(-10,0):
					try:
						resp = packets[i]
						conn.send(resp.encode('utf-8'))
						#response(src, resp)
					except:
						conn.close()
						continue
				conn.close()
				continue

		if mtype == b'MAIL':
			conn.close()
			print("this is our way")
			mesg = mesg.decode('utf-8')
			if src != own_id:
				mesg = decrypt(mesg, keys[src])
			print(mesg)
			resp = "SERV Src " + str(own_id) + " Dst " + str(src) + " Msg SRCV\n"
			response(src, resp)
			write_packet(resp)
			i = i+1
			continue