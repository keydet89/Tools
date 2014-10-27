import argparse
import os
import struct
import time
import OleFileIO_PL

def getFileTime(data0,data1):
	if (data0 == 0 and data1 ==0):
		return 0
	else:
		data0 -= 0xd53e8000
		data1 -= 0x019db1de
		return int(data1 * 429.4967296 + data0/1e7)


parser = argparse.ArgumentParser(description='Parse AutoDest Jump List DestList streams')
parser.add_argument('-f','--file', help='Select an AutoDest Jump List file')
parser.add_argument('-d','--dir', help='Select a folder of AutoDest Jump List files')
parser.add_argument('-t','--tln', help='Output in TLN format', action='store_true')
parser.add_argument('-u','--user', help='User - use with TLN output')
parser.add_argument('-s','--server', help='Server - use with TLN output')
args = vars(parser.parse_args())

file_list = []

if args['server']:
	system = args['server']
else:
	system = ""
	
if args['user']:
	who = args['user']
else:
	who = ""


if args['file']:
	if args['file'].endswith("automaticDestinations-ms"):
		file_list.append(args['file']) 

if args['dir']:
	for filename in os.listdir(args['dir']):
		if filename.endswith("automaticDestinations-ms"):
			file_list.append(os.path.join(args['dir'],filename)) 


# main
for jl in file_list:
	ole = OleFileIO_PL.OleFileIO(jl)

	if not args['tln']:
		print "----------------------------------------------------------------------"
		print jl
		print "----------------------------------------------------------------------"

	if ole.exists('DestList'):
		dest = ole.openstream('DestList')
		data = dest.read()
		num  = struct.unpack("<Q",data[4:12])
		
		ofs = 32
		l = len(data)
		while ofs < l:
#		print "Offset: " + hex(ofs)
			stream = data[ofs:ofs+114]
	
			name = stream[72:88]
			name = name.replace("\00","")
	
			num, = struct.unpack("<Q",stream[88:96])
	
			time0, time1 = struct.unpack("II",stream[100:108])
			timestamp = 	getFileTime(time0,time1)
			
			sz, = struct.unpack("h",stream[112:114])

			ofs += 114
			sz2 = sz * 2
			path = data[ofs:ofs + sz2]
			path = path.replace("\00","")
			
			if args['tln']:
				print str(timestamp) + "|DestList|"+ system + "|" + who + "|" + path
			
			else:
#		print name + "  " + path + "  Index: %d" % num + " - Time: %d" % timestamp
#		print name + "  " + path + "  Index: " + hex(num) + "  Time: " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
				print "Index: " + str(num) + "  " + path + "  Time: " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
				print ""
				
			ofs += sz2
	
	ole.close()
	
