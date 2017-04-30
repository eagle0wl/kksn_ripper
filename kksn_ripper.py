#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
kksn_ripper ver0.1

Copyright (c) 2017 eagle0wl All rights Reserved.

python 2.7.x
This script is released under the MIT License.

Contact:
masm0wl [at] hotmail [dot] com
http://www.twitter.com/eagle0wl
http://www.mysys.org/eagle0wl/
"""
import sys, md5

rip_status_table = []
rip_status_table.append({'md5_hash': u'5aed41fe291d0d1b21bbf48e2bcb77f9', 'offset': 0x00069094, 'size': 0x00039BE4}) # KKSN DX.exe
rip_status_table.append({'md5_hash': u'1d6f9515a10eb20ed719e9c7fcad9635', 'offset': 0x00069094, 'size': 0x00039FA4}) # KKSN AC.exe
rip_status_table.append({'md5_hash': u'b5cb27b56c23fdde3cd0b0d793024ae5', 'offset': 0x000690AC, 'size': 0x0003A2F6}) # KKSN GOLD.exe

commoniNESHeader = '4E45531A102042000000000000000000'.decode('hex')


def get_rip_status(md5_hash):
	
	for r in rip_status_table:
		if r['md5_hash'] == md5_hash:
			return r
	
	return None
	


# original code is so buggy.
# has not optimize, some deadcode, contrived pointer and mix 'call by value' and 'call by reference'.
def lzss_variant_decompress(src, dist):
	
	ringbuffer = bytearray([0x00]*0x1000) # 0x0FEE
	wpos1 = 0x0FEE
	flags = 0
	
	s = d = 0
	
	while True:
		flags >>= 1
		
		if flags & 0x0100 == 0:
			if len(src) <= s:
				break
			flags = ord(src[s]) | 0xFF00
			s += 1
		
		if flags & 1:
			if len(src) <= s:
				break
			dist[d] = src[s]
			d += 1
			ringbuffer[wpos1] = src[s]
			s += 1
			wpos1 = (wpos1 + 1) & 0x0FFF
			
		else:
			if len(src) <= s:
				break
			offset = ord(src[s])
			s += 1
			
			if len(src) <= s:
				break
			length = ord(src[s])
			s += 1
			
			offset |= (length & 0xF0) << 4
			length  = (length & 0x0F) + 2
			
			if length == 0:
				continue
			
			for k in range(length + 1):
				c = ringbuffer[(offset + k) & 0x0FFF]
				dist[d] = c
				d += 1
				ringbuffer[wpos1] = c
				wpos1 = (wpos1 + 1) & 0x0FFF
	
	return d
	


def usage():
	
	print u'usage:'
	print u'> python ' + __file__ + u' [.exe] [.nes]'
	print u'[.exe] is "KKSN DX.exe", "KKSN AC.exe" or "KKSN GOLD.exe".'
	print u'[.nes] is output file name.'
	print u''
	print u'example:'
	print u'> python ' + __file__ + u' "KKSN DX.exe" dx.nes'
	print u''
	
	return
	


def main():
	
	argvs = sys.argv
	argc = len(argvs)
	
	if argc != 3:
		usage()
		return
	
	exefilename = argvs[1]
	nesfilename = argvs[2]
	
	f = open(exefilename, 'rb')
	exedata = f.read()
	f.close()
	
	md5_hash = md5.new(exedata).hexdigest()
	
	rip_status = get_rip_status(md5_hash)
	if rip_status is None:
		usage()
		return
	
	offset = rip_status['offset']
	size = rip_status['size']
	compressdata = exedata[offset:offset+size]
	
	nesdata = bytearray([0x00]*(1024*1024))
	nessize = lzss_variant_decompress(compressdata, nesdata)
	
	f = open(nesfilename, 'wb')
	f.write(commoniNESHeader)
	f.write(nesdata[:nessize])
	f.close()
	
	print u'completed! "%s" => "%s"' % (exefilename, nesfilename)
	
	return
	


if __name__ == "__main__":
	main()
