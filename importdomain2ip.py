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
import psycopg2
import sys
import socket

#resp=urllib.urlopen("http://rules.emergingthreats.net/blockrules/compromised-ips.txt")

resp=open(sys.argv[1],'rb')
limit=int(sys.argv[2])


conn=psycopg2.connect("dbname=bgp")

cur=conn.cursor()

for line in range(limit):
  line=resp.readline()
  domain=line.rstrip().split(',')[1]

#  print domain

  for host in [domain,'www.'+domain]:
    try:
    	ips=socket.gethostbyname_ex(host)[2]
    except socket.gaierror:
  	ip=None
  	pass
    for ip in ips:
    	print host,ip 
  	cur.execute("INSERT INTO popular (ip,host) values (%s,%s)", (ip,host))


conn.commit()
cur.close()
conn.close()
