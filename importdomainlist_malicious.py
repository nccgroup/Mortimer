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

import psycopg2
import sys

name=sys.argv[2]

resp=open(sys.argv[1],'rb')
name=sys.argv[2]

conn=psycopg2.connect("dbname=bro") 

cur=conn.cursor()

for line in resp.readlines():

  line=line.decode("utf-8").rstrip()

  if line.startswith('#'):
	continue
  if line == "":
	continue
  domain=line.split("\t")[0]

  cur.execute("INSERT INTO malicious_domain (host,origin) values (%s,%s)", (domain, name))

conn.commit()
cur.close()
conn.close()
