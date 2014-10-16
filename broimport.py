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

import sys
import psycopg2
#import psycopg2.extras
import datetime
import uuid
import string
from multiprocessing import Pool


# DANGER This trusts bro not to perform SQLi attacks!  Optimisation required

def typemap(type,fieldname):
    # Maps bro types to postgres type
    if (type == "addr"):
        # Note: This requested ip4r-2.0 from postgres ppa
        return "ip4"
    if (type == "count" or type=="port"):
        if (type == "count"):
            if (fieldname in ["request_body_len", "response_body_len", "resp_ip_bytes", "orig_ip_bytes", "seen_bytes", "resp_bytes", "orig_bytes", "total_bytes", "trans_id"]):
            #In theory count should be unsigned 64 bit integer but bigint (signed 64) will have to do
                return "bigint"
        # Most will actually fit into a unsigned 32 bit
        return "integer"
    if (type == "interval"):
        return "float"
    if (type == "bool"):
        return "boolean"
    if (type == "time"):
        return "timestamp"
    if (type == "string" and (fieldname == "uid" or fieldname == "fuid" or fieldname == "parent_fuid" or fieldname == "conn_uids")):
        #There are 96 bit base62 encoded uids.  We convert to postgres uuid 128bit uuid type
        return "uuid"
    if (type == "table[addr]"):
        # I've only ever seen a single IP in these fields, so lets keep it simple
        return "ip4"
    if (type == "table[string]"):
        if (fieldname == "conn_uids"):
            return "uuid[]"
        return "character varying[]"
    if (type == "vector[string]"):
        if (fieldname == "resp_fuids" or fieldname == "orig_fuids"):
            return "uuid[]"
        return "character varying[]"

    #Default just store as a string
    return "character varying"

def checkExists(cur,dbname):
    #Check if table exists
    cur.execute("select exists(select * from information_schema.tables where table_name=%s)", (dbname,))
    ret=cur.fetchone()[0]
    return ret

def createDB(cur,dbname,createSQL):
    # This is horrid
    #print createSQL;
    try:
      cur.execute("create table "+dbname+" ( "+createSQL+" )")
    except psycopg2.IntegrityError:
      # Table already exists, another process has beaten us to it
      print "Race condition on CREATE TABLE"
      print "Try bootstrapping database with logs for a single hour"
      print "Needs a proper fix"
      raise;
    #ret=cur.fetchone()[0]

# From stackoverflow (base62 encode/decode)
BASE_LIST = string.digits + string.letters # + '_@'
BASE_DICT = dict((c, i) for i, c in enumerate(BASE_LIST))
BASE_LEN = len(BASE_LIST)

def base_decode(string):
    ret=0
    for char in string[::-1]:
        ret = ret * BASE_LEN + BASE_DICT[char]

# for i, c in enumerate(string[::-1]):
#        ret += (length ** i) * reverse_base[c]
    return ret

def base_encode(integer):
    if not num:
        return BASE_LIST[0]

    encoding=""
    while integer:
        integer,remain = divmod(integer,BASE_LEN)
        encoding += BASE_LIST[integer]

#    length = len(base)
#    ret = ''
#    while integer != 0:
#        ret = base[integer % length] + ret
#        integer /= length
    return encoding

def doInsert(filename):
	#Defaults
	inserted=0
	skipped=0
	header={'separator': ' '}
	tableprefix="bro_"
	print "Processing %s" % (filename)

	conn=psycopg2.connect("dbname=bro")
	cur=conn.cursor()

	logfile=open(filename)

	line=logfile.readline()

	# Read the header which describes the logfile
	while (line[0]=='#'):
	    tmp=line.lstrip('#').rstrip().split(header['separator'])
	    tmp[1]=tmp[1].decode('string_escape')
	    if (len(tmp) > 2):
		header[tmp[0]]=tmp[1:]
	    else:
		header[tmp[0]]=tmp[1]

	    line=logfile.readline()

	if ('fields' not in header):
	    return "Error reading "+filename
	

	# Fixup field names for postgres (remove the .)
	# Fixup SQL reserved words
	createmapping=[]
	valuemapping=[]
	fieldmapping=[]
	typemapping=[]
	for i in range(len(header['fields'])):
	    header['fields'][i]=header['fields'][i].replace(".","")
	    if header['fields'][i] in ['id','user','from','to']:
		header['fields'][i]=header['path']+"_"+header['fields'][i]


	    type=typemap(header['types'][i],header['fields'][i])
	    typemapping.append(type)
	    fieldmapping.append(header['fields'][i])
	    createmapping.append(header['fields'][i]+" "+type)
	    valuemapping.append('%({})s::{}'.format(header['fields'][i],type))


	fieldSQL=str.join(",",fieldmapping)
	valueSQL=str.join(",",valuemapping)
	createSQL=str.join(",",createmapping)

	# Create table if doesn't exist
	if (not checkExists(cur,tableprefix+header['path'])):
	    createDB(cur,tableprefix+header['path'],createSQL)


	#Now process the data
	#Rewind so we can use an iterator (and already have first line
	logfile.seek(0)
	for line in logfile:

	    if line.startswith('#'):
		continue

	#while (line[0]!='#'):
	    # We currently skips lines which contain ipv6 addresses for simplicity
	    skip=False
	    data=line.rstrip().split(header['separator'])
	    #Transform some of the data fields

	    #try:
	    for i,el in enumerate(data):
		#print typemap(header['types'][i],header['fields'][i])
		if (el==header['unset_field'] or el==header['empty_field']):
		    data[i]=None
		elif (typemapping[i]=="timestamp"):
		    if (data[i]):
			data[i]=datetime.datetime.utcfromtimestamp(float(data[i]))
		elif (typemapping[i] == "ip4"):
		    if (data[i] and (data[i].find(":") > 0 or data[i].find(",") > 0)):
			#IPv6 address so skip
			#IPv6 multiple IP address - rarely seen so skip
			skip=True
		elif (typemapping[i] == "uuid"):
		    if (data[i] != "(empty)"):
			data[i]=str(uuid.UUID(int=base_decode(data[i])))
		elif (typemapping[i].endswith("[]")):
		    data[i]=data[i].split(header['set_separator'])

		if (typemapping[i] == "uuid[]"):
		    if (data[i]):
			for j,uid in enumerate(data[i]):
			#next;
			    data[i][j]=str(uuid.UUID(int=base_decode(uid)))
	    if (not skip):
		datadict=dict(zip(header['fields'],data))
		sql="INSERT INTO "+tableprefix+header['path']+" ("+fieldSQL+") VALUES ("+valueSQL+")"
		#print cur.mogrify(sql)
		cur.execute(sql,datadict)
		inserted+=1
	    else:
		skipped+=1
	    #except:
	#       print "Error processing"+line
	#       pass

	    #line=logfile.readline()
	#       sys.exit(0)

	# Fin
	conn.commit()
	cur.close()
	conn.close()
	ret="Inserted %d\t Skipped %d" % (inserted,skipped)
	return ret


if __name__ == '__main__':
	pool=Pool(processes=8)
	print pool.map(doInsert,sys.argv[1:])

