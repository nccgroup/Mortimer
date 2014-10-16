#!/usr/bin/python

'''
Script for loading GeoIP CSV data into a postgresql database
'''

import logging, psycopg2, psycopg2.extensions, sys

from optparse import OptionGroup, OptionParser
from StringIO import StringIO

class GeoIPDataLoader(object):

    def __init__(self, dsn, blocks='GeoLiteCity-Blocks.csv', locations='GeoLiteCity-Location.csv', schema='public', zip=None):
        self.con = psycopg2.connect(dsn)
        # We don't need transactions... right?
        self.con.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        # The data is in ISO8859_15 encoding
        self.con.set_client_encoding('iso8859_15')
        self.cur = self.con.cursor()

        self.blocks_csv = blocks
        self.location_csv = locations
        self.zip = zip
        self.schema = schema
 
    def close(self):
        self.con.close()

    def create_tables(self):
        print 'Creating structure...',
        self.db_execute(
            '''
                CREATE TABLE locations
                (
                  id bigint NOT NULL,
                  country character(2) NOT NULL,
                  region character(2),
                  city character varying(75),
                  postal_code character varying(15),
                  latitude numeric(6,4) NOT NULL,
                  longitude numeric(7,4),
                  metro_code integer,
                  area_code integer,
                  CONSTRAINT locations_pkey PRIMARY KEY (id)
                );
                
                CREATE TABLE blocks
                (
                  start_ip bigint NOT NULL,
                  end_ip bigint NOT NULL,
                  location_id bigint NOT NULL
                );
               
            '''
            )
        print '\033[1;32mDone\033[1;m'
                
    def create_indexes(self, ip4=False):
        print 'Adding Indexes...',
        sys.stdout.flush()
        if not ip4:
            self.db_execute('''
             CREATE INDEX ix_start_end_ip ON blocks 
                USING btree (start_ip, end_ip) WITH (FILLFACTOR=100);
             CREATE INDEX ix_end_start_ip ON blocks 
                USING btree (end_ip, start_ip) WITH (FILLFACTOR=100); 
                ''')
        else:
            self.db_execute('''
                 CREATE INDEX ix_ip_range ON blocks
                   USING gist (ip_range) WITH (FILLFACTOR=100);
                ''')
        print '\033[1;32mDone\033[1;m'
        
    def create_functions(self, ip4=False):
        print 'Adding utility functions...',
        sys.stdout.flush()
        if ip4:
            self.db_execute('''
                CREATE OR REPLACE FUNCTION get_location(inet) RETURNS bigint AS $$
                  SELECT location_id FROM %s.blocks
                  WHERE ip_range >>= ip4($1)
                  LIMIT 1
                $$ LANGUAGE SQL;
                ''' % self.schema)
        else:
            self.db_execute('''
                CREATE OR REPLACE FUNCTION inet_to_bigint(inet) RETURNS bigint AS $$
                    SELECT $1 - inet '0.0.0.0'
                $$ LANGUAGE SQL;
                ''')
        print '\033[1;32mDone\033[1;m'
    
    def create_schema(self):
        try:
            self.db_execute('''CREATE SCHEMA %s;''' % self.schema)
        except psycopg2.ProgrammingError:
          pass   

        self.db_execute('SET search_path TO %s,public;' % self.schema)
        
    def db_execute(self, ddl):
        self.cur.execute(ddl)
#        self.con.commit()
    
    def load_data(self):
        
        if self.zip:
            # Something more clever can be done here... but maybe... later
            from zipfile import ZipFile
            
            zip = ZipFile(self.zip)
            
            for z in zip.infolist():
                if z.filename.endswith(self.location_csv):
                    self.load_table(z.filename, 'locations', data_file=StringIO(zip.read(z.filename)))
                elif z.filename.endswith(self.blocks_csv):
                    self.load_table(z.filename, 'blocks', data_file=StringIO(zip.read(z.filename)))
        else:
            # Load Locations
            self.load_table(self.location_csv, 'locations')
            # Load Blocks
            self.load_table(self.blocks_csv, 'blocks')
    
    def load_table(self, file_name, table_name, data_file=None):
        print 'Loading table \033[1;34m%s\033[1;m from file \033[1;34m%s\033[1;m...' % (table_name, file_name),
        sys.stdout.flush()

        if not data_file:
            data_file = open(file_name)
        
        # Skip the copyright header
        data_file.readline()
        data_file.readline()
        #Remove quotes... psycopg2's `copy` errors on them
        string_data = data_file.read().replace('"', '')
        
        self.cur.copy_from(StringIO(string_data), table_name,  sep=',', null='')
        print '\033[1;32mDone\033[1;m'
    
    def migrate_to_ip4(self):
        print 'Adding ip_range column'        
        self.db_execute('''
                        ALTER TABLE blocks ADD COLUMN ip_range ip4r;
                        ALTER TABLE blocks ALTER COLUMN ip_range SET STORAGE PLAIN;
                        ''')
        
        print 'Migrating data to ip4...',
        sys.stdout.flush()
        self.db_execute('''UPDATE blocks SET ip_range = ip4r(start_ip::ip4, end_ip::ip4)''')
        print '\033[1;32mDone\033[1;m'

        print 'Dropping unneeded columns'
        self.db_execute('''
                        ALTER TABLE blocks DROP COLUMN start_ip;
                        ALTER TABLE blocks DROP COLUMN end_ip;
                        ''')
    def vacuum(self):
        print 'Vaccuming database...',
        sys.stdout.flush()
        self.db_execute('VACUUM FULL ANALYZE')
        print '\033[1;32mDone\033[1;m'

def main():
    DSN = "dbname='%s' user='%s' host='%s'"

    parser = OptionParser()
    # Operational options
    parser.add_option('-c', '--load-ddl', dest='load_ddl', default=False,
                      action='store_true', help='Create database structure')
   
    parser.add_option('-g', '--load-data', dest='load', default=False,
                      action='store_true', help='Load the GeoIP data')

    parser.add_option('-b', '--blocks-file', dest='blocks_csv', default='GeoLiteCity-Blocks.csv',
                      action='store', help='GeoIP Blocks CSV file [default: %default]', metavar='BLOCKS_FILE')
    parser.add_option('-l', '--locations-file', dest='locations_csv', default='GeoLiteCity-Location.csv',
                      action='store', help='GoeIP Locations CSV file [default: %default]', metavar='LOCATIONS_FILE')

    parser.add_option('-z', '--zip', dest='zip',
                      action='store', help='GoeIP Locations ZIP file [default: %default]', metavar='ZIP_FILE')

    db_group = OptionGroup(parser, 'Database Options')
    # Database options
    db_group.add_option('-H', '--host', dest='db_host', default='localhost',
                      action='store', help='Database host [default: %default]', metavar='DB_HOST')
    db_group.add_option('-d', '--database', dest='db_name', default='geoip_db',
                      action='store', help='Database name [default: %default]', metavar='DATABASE_NAME')
    db_group.add_option('-U', '--user', dest='db_user', default='geoip',
                      action='store', help='User [default: %default]', metavar='USER_NAME')
    db_group.add_option('-s', '--schema', dest='schema', default='public',
                      action='store', help='Database Schema [default: %default]', metavar='SCHEMA')

    db_group.add_option('--ip4r', dest='ip4', default=False,
                      action='store_true', help='Use IP4r module [default: %default]')

    parser.add_option_group(db_group)
    
    (options, args) = parser.parse_args()

    data_loader = GeoIPDataLoader("dbname='%s' user='%s' password='geoip' host='%s'" % (options.db_name, options.db_user, options.db_host),
                                  blocks=options.blocks_csv, locations=options.locations_csv, zip=options.zip, schema=options.schema)

    if options.ip4 and not options.load and options.load_ddl:
        print '\033[1;31mERROR\033[1;m Creating a raw IP4 schema breaks data loading.  Use --ip4r switch ONLY during or after loading data'
        return

    if not options.load_ddl and not options.load:
        parser.print_help()
        return

    if options.load_ddl:
        if options.schema != 'public':
            data_loader.create_schema()
        data_loader.create_tables()
 
    if options.load:
        data_loader.load_data()

    if options.ip4:
        data_loader.migrate_to_ip4()

    if options.load:
        data_loader.create_indexes(options.ip4 is True)

    if options.load_ddl:
        data_loader.create_functions(options.ip4 is True)

    data_loader.vacuum()

if __name__ == "__main__":
    main()
