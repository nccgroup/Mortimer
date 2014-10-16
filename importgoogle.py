#!/usr/bin/python

# A collection of scripts for processing network forensics type data and intel, mainly into a postgres database.
#
# Released as open source by NCC Group Plc - http://www.nccgroup.com/
#
# Developed for John Green, cirt at nccgroup dot com
#
# https://github.com/nccgroup/mortimer
#
# Released under AGPL see LICENSE for more information

import urllib
import urllib2
import psycopg2
import sys
from struct import unpack

APIKEY='GETYOUROWNKEY!'
APPVERSION='1.09'
PVERSION='2.2'
lists=['goog-malware-shavar', 'goog-regtest-shavar', 'goog-whitedomain-shavar', 'googpub-phish-shavar']

url = 'https://safebrowsing.clients.google.com/safebrowsing/downloads?client=api&apikey=%s&appver=%s&pver=%s' % (APIKEY,APPVERSION,PVERSION)

conn=psycopg2.connect("dbname=bro user=analyst3")
cur=conn.cursor()



def process_chunkS(chunk,hashlen,num,list):

	n=0

	# Empty chunk (sent by google to remove gaps)
	if (len(chunk) == 0):
		cur.execute("INSERT INTO s_chunks (num,list) values (%s,%s)",(num,list))
		return


	while(n<len(chunk)):
		#hostkey=unpack('I',chunk[n:n+4])[0]
		hostkey=chunk[n:n+4]
		count=unpack('B',chunk[n+4])[0]
		#print "Count",count
		n+=5
		if (count == 0):
			addchunknum=unpack('>I',chunk[n:n+4])[0]
			#print hostkey,addchunknum
			cur.execute("INSERT INTO s_chunks (hostkey,num,add_num,list) values (%s,%s,%s,%s)", (psycopg2.Binary(hostkey),num,addchunknum,list))
			n+=4
		else:
			#prefix=[]
			for i in range(count):
				#print i,count,n,len(chunk)
				addchunknum=unpack('>I',chunk[n:n+4])[0]
				prefix=chunk[n+4:n+4+hashlen]
				#.encode('hex'))
				#print hostkey,addchunknum,prefix
				cur.execute("INSERT INTO s_chunks (hostkey,num,add_num,prefix,list) values (%s,%s,%s,%s,%s)", (psycopg2.Binary(hostkey),num,addchunknum,psycopg2.Binary(prefix),list))
				n+=4+hashlen

def process_chunkA(chunk,hashlen,num,list):

	n=0
	if (len(chunk)== 0):
		cur.execute("INSERT INTO a_chunks (num,list) values (%s,%s)",(num,list))
		return

	while(n<len(chunk)):
		hostkey=chunk[n:n+4]
                count=unpack('B',chunk[n+4])[0]
		n+=5
		if (count==0):
			cur.execute("INSERT INTO a_chunks (hostkey,num,list) values (%s,%s,%s)", (psycopg2.Binary(hostkey),num,list))
		else:
			for i in range(count):
                                prefix=chunk[n:n+hashlen]
				#.encode('hex'))
                                #print hostkey,prefix
				cur.execute("INSERT INTO a_chunks (hostkey,num,prefix,list) values (%s,%s,%s,%s)", (psycopg2.Binary(hostkey),num,psycopg2.Binary(prefix),list))
                                n+=hashlen

def rangeConvert(nums):
    """
    nums: sorted list of integers.
    returns comma separated list wit range
    """
    if len(nums) == 0:
      return ''
    output = []
    i = 0
    while i < len(nums):
      output.append(str(nums[i]))
      use_range = False
      while i < len(nums) - 1 and nums[i + 1] - nums[i] == 1:
        i += 1
        use_range = True
      if use_range:
        output.append('-')
        output.append(str(nums[i]))
      if i < len(nums) - 1:
        output.append(',')
      i += 1
    return ''.join(output)

def rangeSplit(rangeStr):
    """
    range: sorted range list eg 1,3-6,9-10,12,17
    returns sorted list of integers
    """
    ret=[]

    for item in rangeStr.rstrip().split(','):
	num=item.split('-')
	if (len(num) == 1):
		ret.append(int(num[0]))
	elif (len(num) == 2):
		for val in range(int(num[0]),int(num[1])):
			ret.append(val)

    return ret
		
	
				
	

print url
data=''
for list in lists:
	cur.execute("SELECT DISTINCT num FROM a_chunks WHERE list=%s ORDER BY num ASC",(list,))
	achunks=cur.fetchall()
	arange=rangeConvert(map(lambda x:x[0],achunks))
	cur.execute("SELECT DISTINCT num FROM s_chunks WHERE list= %s ORDER BY num ASC",(list,))
	schunks=cur.fetchall()
	srange=rangeConvert(map(lambda x:x[0],schunks))

	data+=list+';'
	if arange:
		data+='a:'+arange
	if arange and srange:
		data+=':'
	if srange:
		data+='s:'+srange
	data+='\n'


#sys.exit(1)	

print data

#sys.exit(1)
request=urllib2.Request(url,data)


#sys.exit(1)


response=urllib2.urlopen(request)

for line in response.readlines():
	line=line.rstrip()
	(keyword,data)=line.split(':')
	print keyword,data
	if (keyword == 'n'):
		delay=data
	elif (keyword == 'i'):
		list=data
	elif (keyword == 'u'):
		url=data
		redirect_request=urllib2.Request('https://'+url)
		redirect_response=urllib2.urlopen(redirect_request)
		while (True):
			redirect_line=redirect_response.readline()
			if (not redirect_line):
				break
			(action,chunknum,hashlen,chunklen)=redirect_line.split(':')
			print "reading ",int(chunklen)
			print "chunk num ",int(chunknum)
			if (action == 'a'):
				chunk=redirect_response.read(int(chunklen))
				process_chunkA(chunk,int(hashlen),int(chunknum),list)
			elif (action == 's'):
				chunk=redirect_response.read(int(chunklen))
				process_chunkS(chunk,int(hashlen),int(chunknum),list)
			else:
				print "Unknown chunktype"
				sys.exit(1)
				
			print redirect_line
		#sys.exit(1)
			
	elif (keyword == 'ad'):
		print "a delete",data
		nums=rangeSplit(data)
		cur.execute("DELETE FROM a_chunks WHERE num=ANY(%s)",(nums,))
		print nums
	elif (keyword == 'sd'):
		print "s delete",data
		nums=rangeSplit(data)
		print nums
		cur.execute("DELETE FROM s_chunks WHERE num=ANY(%s)",(nums,))
	else:
		print "keyword not recognised"
		sys.exit(1)
conn.commit()

cur.close()
conn.close()
sys.exit(1)
