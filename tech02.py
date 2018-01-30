import os, sys
from struct import *

def StringCalcSector2Size(num):
	str_size = ['B', 'KB', 'MB', 'GB']

	t = size = (num * 512)

	for i in range(4):
		t = t / 1024
		if int(t) > 0:
			size = size / 1024
		else:
			break

	return '%.2f %s' % (size, str_size[i])

def LogicalDrivePartition(part, base):
	print 'LogicalDrivePartition'
	start = unpack('<L', part[8:8+4])[0]
	num = unpack('<L', part[12:12+4])[0]

	#print '[L] %10d %s' %(base+start, StringCalcSector2Size(num))

def ExtendedPartition(part, start):
	print 'ExtendedPartition'

	handle.seek((base+start) * 512)
	data = handle.read(0x200)

	if ord(data[510]) == 0x55 and ord(data[511]) == 0xAA:
		print 'PARTITION Read Success'

		part = []

		for i in range(2):
			part.append(data[0x1BE + (i*0x10):0x1BE + (i*0x10) + 0x10])

		if ord(part[0][4]) != 0x0:
			LogicalDrivePartition(part[0], base+_start)
		if ord(part[1][4]) != 0x0:
			start = unpack('<L', part[1][8:8+4])[0]
			ExtendedPartition(part[1], start)

def PrimaryPartition(part):
	global start
	start = unpack('<L', part[8:8+4])[0]
	num = unpack('<L', part[12:12+4])[0]

	#print '[P] %10d %s' %(start, StringCalcSector2Size(num))

	handle.seek(start*512)
	vbr = handle.read(0x200)

	#print vbr
	chk_fat = vbr[82] + vbr[83] + vbr[84] + vbr[85] + vbr[86]
	if chk_fat == "FAT32":
		print hdd_name
		print "\n[+] Start: \t\t%d \n[+] Total Size: \t%s" %(start, StringCalcSector2Size(num))
		#print "[+] FileSystem: \t", chk_fat

		VBRInfo(vbr)

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
		print "\n[+] FSInfo\n"
		print "\t[+] Number of free cluster:", FreeClusterNum
		print "\t[+] Next Free Cluster:", NextFreeCluster

		FATArea()

def FATArea():
	offset = start*bytesPsec + reservedSector*bytesPsec
	handle.seek(offset)	

	print "\n[+] FAT Area\n"
	print "\t[+] Offset: ", handle.tell()	

	entryNum = (FatSize*bytesPsec) / 4

	print "\t[+] Entry Number:", entryNum
	
	data_area_start = offset + FatNum*FatSize*bytesPsec # Cluster 2 offset

	print "\n"
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
				
def check_sign(offset, num):
	handle.seek(0)
	handle.read(offset)
	cluster = handle.read(bytesPsec*secPclu)
	sign1 = unpack_from('>H',cluster,0)[0]
	sign2 = unpack_from('>I',cluster,0)[0]

	if sign1 == 0xffd8:
		print num,"-jpeg file"
	if sign2 == 0x504b0304:
		tmp = unpack_from('>I',cluster,4)[0]
		if tmp == 0x14000600:
			print num,"- zip(docx,pptx,xlsx)"
		else:
			print num,"-zip file"

if __name__ == "__main__":

	hdd = "\\\\.\\PhysicalDrive"
	idx = 0

	while True:
		hdd_name = hdd + str(idx)
		try:
			handle = open(hdd_name, 'rb')

			handle.seek(0*512)

			mbr = handle.read(0x200)

			if ord(mbr[510]) == 0x55 and ord(mbr[511]) == 0xAA:
				#print '\n' + str(idx) + 'th PhysicalDrive'

				part = []

				for i in range(4):
					part.append(mbr[0x1BE + (i*0x10):0x1BE + (i*0x10) + 0x10])


				for i in range(4):
					p = part[i]
					if ord(p[4]) == 0xF or ord(p[4]) == 0x5:
						base = unpack('<L', p[8:8+4])[0]
						ExtendedPartition(p,0)
					elif ord(p[4]) != 0:
						PrimaryPartition(p)
				idx += 1
			else:
				print 'MBR Read Fail'

			handle.close()
		except:
			break