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

APIKEY='GETYOUROWNKEY'
APPVERSION='1.09'
PVERSION='2.2'
lists=['goog-malware-shavar', 'goog-regtest-shavar', 'goog-whitedomain-shavar', 'googpub-phish-shavar']

url = 'https://safebrowsing.clients.google.com/safebrowsing/gethash?client=api&apikey=%s&appver=%s&pver=%s' % (APIKEY,APPVERSION,PVERSION)

data='4:4\n'
data+='6b331422'.decode('hex')

#data+='51864045'.decode('hex')

#data+='41864045'.decode('hex')
#7901'


#sys.exit(1)	

#sys.exit(1)
request=urllib2.Request(url,data)


#sys.exit(1)


response=urllib2.urlopen(request)

code=response.getcode()

if (code==204):
	print "No match"
elif (code == 200):
	#goog-malware-shavar:127919:32		#
   while (True):
        line=response.readline()
	if (not line):
		break;
	print line
	(list,num,hashlen)=line.rstrip().split(':')
	fullhash=response.read(int(hashlen))
	print fullhash.encode('hex')		
else: 
	print "Error %s" % (code)


