import os, sys
from struct import *

DEBUG = False

def usage():
	print "\n[+] Usage\n"
	print "\tpython carving.py <volume/drive>\n"
	sys.exit()

def VBRInfo(vbr):
	global bytesPsec, secPclu, reservedSector, RootDirClusterOffset, FSinfoOffset, FatSize, FatNum
	bytesPsec = unpack_from('<H', vbr, 0xb)[0]
	secPclu = unpack_from('B',vbr, 0xd)[0]
	reservedSector = unpack_from('<H',vbr,0xe)[0]
	FatNum = unpack_from('B',vbr, 0x10)[0]
	mediaType = unpack_from('B',vbr, 0x15)[0]
	FatSize = unpack_from('<I',vbr, 0x24)[0]
	RootDirClusterOffset = unpack_from('<I',vbr, 0x2c)[0]
	FSinfoOffset = unpack_from('<H',vbr, 0x30)[0]
	VLabel = unpack_from('<10s',vbr,0x47)[0]
	FStype = unpack_from('<8s',vbr,0x52)[0]
	magic = unpack_from('>H',vbr,0x1fe)[0]	

	if FStype != "FAT32   ":
		print "\n[-] Error! None FAT32 FileSystem\n"
		sys.exit()

	print "\n[+] FAT32 FileSystem Detected!\n"

	if DEBUG:
		print "\n[+] VBR Info\n"
		print "\t[+] Bytes per Sector:", bytesPsec
		print "\t[+] Sectors per Cluster:", secPclu
		print "\t[+] Reserved Sector Count:", reservedSector
		print "\t[+] Number of FAT:", FatNum
		print "\t[+] Media Type:", hex(mediaType)
		print "\t[+] RootDirClusterOffset:", RootDirClusterOffset
		print "\t[+] Size of FAT:", FatSize
		print "\t[+] FSInfo Offset:", FSinfoOffset
		print "\t[+] Volume Label:", VLabel
		print "\t[+] FileSystem Type:", FStype
		print "\t[+] Signature:", hex(magic)

	FSInfo(FSinfoOffset)

def FSInfo(FSoffset):
	if FSoffset != 1:
		offset = (FSoffset-1)*bytesPsec
		handle.seek(offset, 1)
	fsinfo = handle.read(0x200)

	magic1 = unpack_from('<I',fsinfo,0)[0]
	magic2 = unpack_from('<I',fsinfo,484)[0]
	FreeClusterNum = unpack_from('<I',fsinfo,488)[0]
	NextFreeCluster = unpack_from('<I',fsinfo,492)[0]
	magic3 = unpack_from('>H',fsinfo,510)[0]

	#print hex(magic1), hex(magic2), hex(magic3)
	if magic1 == 0x41615252 and magic2 == 0x61417272 and magic3 == 0x55aa:
		if DEBUG:
			print "\n[+] FSInfo\n"
			print "\t[+] Number of free cluster:", FreeClusterNum
			print "\t[+] Next Free Cluster:", NextFreeCluster

		FATArea()

def FATArea():
	offset = reservedSector*bytesPsec
	handle.seek(offset)	

	global result
	result = []

	if DEBUG:	
		print "\n[+] FAT Area\n"
		print "\t[+] Offset: ", handle.tell()	

	global entryNum
	entryNum = FatSize*bytesPsec/4
	
	data_area_start = offset + FatNum*FatSize*bytesPsec # Cluster 2 offset

	print "\n[+] Carving...(Ctrl + C to stop)\n"
	try:
		for i in range(entryNum):
			FatEntry = handle.read(4)
			return_offset = handle.tell()
			if i > 1:
				entry = unpack('<I',FatEntry)[0]
				entry = entry & 0x0fffffff
				if entry == 0x0:
					#print i, "th Cluster\t\t", hex(entry)
					offset = data_area_start + (i-2)*bytesPsec*secPclu
					check_sign(offset, i)
					handle.seek(0)
					handle.read(return_offset)
	except KeyboardInterrupt:
		print "\nCtrl + C pressed!"

	print "\n################# RESULT #################\n"
	print "Processed : ", i ,"/", entryNum, "\n"
	for e in result:
		print e
				
def check_sign(offset, num):
	handle.seek(0)
	handle.read(offset)
	cluster = handle.read(bytesPsec*secPclu)

	test = unpack_from('>I',cluster,0)[0]
	if test == 0:
		return

	jpg_sign = unpack_from('>H',cluster,0)[0]
	zip_sign = unpack_from('>I',cluster,0)[0]
	pdf_sign = unpack_from('>I',cluster,0)[0]
	png_sign = unpack_from('>Q',cluster,0)[0]
	gif_sign = unpack_from('>I',cluster,0)[0]
	lnk_sign = unpack_from('>I',cluster,0)[0]
	rar_sign = unpack_from('>Q',cluster,0)[0] & 0xffffffffffffff

	if jpg_sign == 0xffd8:
		print num,"- jpeg"
		result.append(str(num)+"- jpeg")
	elif zip_sign == 0x504b0304:
		zip_sign2 = unpack_from('>I',cluster,4)[0]
		if zip_sign2 == 0x14000600:
			ext = check_ms(offset)
			result.append(str(num)+"- zip ["+ext+"]")
			print num,"- zip ["+ext+"]"
		elif zip_sign2 == 0x14000800:
			result.append(str(num)+"- zip [JAR]")
			print num,"- zip [JAR]"
		else:
			in_file = zip_parse(offset)
			result.append(str(num)+"- zip {"+in_file+"}")
			print num,"- zip {"+in_file+"}"			
	elif pdf_sign == 0x25504446:
		result.append(str(num)+"- pdf")
		print num,"- pdf"
	elif png_sign == 0x89504e470d0a1a0a:
		result.append(str(num)+"- png")
		print num,"- png"
	elif gif_sign == 0x47494638:
		result.append(str(num)+"- gif")
		print num,"- gif"
	elif lnk_sign == 0x4c000000:
		result.append(str(num)+"- lnk")
		print num,"- lnk"
	elif rar_sign == 0x526172211a0700:
		result.append(str(num)+"- RAR")
		print num,"- RAR"

def zip_parse(offset):
	handle.seek(0)
	handle.read(offset)

	cluster = handle.read(0x1d)

	name_len = unpack_from('<H',cluster,0x1a)[0]
	name = handle.read(name_len+1) + " "
	return name

def check_ms(offset):
	handle.seek(0)
	handle.read(offset)

	cluster = handle.read(0x1000)
	if "ppt/slides/_rels" in cluster:
		return "pptx"
	elif "xl/_rels" in cluster:
		return "xlsx"
	elif "word/_rels" in cluster:
		return "docx"

if __name__ == "__main__":

	#hdd = "\\\\.\\PhysicalDrive"
	print('''

 _______    ___   .___________.____    ___        ______     ___      .______     ____    ____  __  .__   __.   _______ 
|   ____|  /   \  |           |___ \  |__ \      /      |   /   \     |   _  \    \   \  /   / |  | |  \ |  |  /  _____|
|  |__    /  ^  \ `---|  |----` __) |    ) |    |  ,----'  /  ^  \    |  |_)  |    \   \/   /  |  | |   \|  | |  |  __  
|   __|  /  /_\  \    |  |     |__ <    / /     |  |      /  /_\  \   |      /      \      /   |  | |  . `  | |  | |_ | 
|  |    /  _____  \   |  |     ___) |  / /_     |  `----./  _____  \  |  |\  \----.  \    /    |  | |  |\   | |  |__| | 
|__|   /__/     \__\  |__|    |____/  |____|     \______/__/     \__\ | _| `._____|   \__/     |__| |__| \__|  \______| 
                                                                                                                         by Jungwan''')
	if len(sys.argv) < 2:
		usage()
		
	volume_label = sys.argv[1]
	hdd_name = "\\\\.\\" + volume_label 

	global handle
	#hdd_name = hdd + str(idx)
	handle = open(hdd_name, 'rb')

	handle.seek(0*512)

	vbr = handle.read(0x200)
	#print mbr

	VBRInfo(vbr)

	handle.close()