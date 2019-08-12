#! /usr/bin/env python3
'''
This tool reads NVD JSON feed and transcribe it to local sqlite3 database.
(Will update description later.)

'''

import os
import sys
import sqlite3
import getopt
import json
from distutils.version import LooseVersion

DEFAULT_CVEDB_FILE = "/var/db/cvedb"

EXIT_ERROR = 1
EXIT_SUCCESS = 0

class CVE(object):
    def __init__(self):
        """Construct a CVE with default empty values
        """
        self.verbosity = 0
        self.data = {}
        '''generalInfo and cvssInfo correspond to actual segments
           of JSON input.
        '''
        self.generalInfo = [ "lastModifiedDate",
                             "publishedDate"]
        self.cvssInfo = [ "accessComplexity",
                          "accessVector",
                          "authentication",
                          "availabilityImpact",
                          "confidentialityImpact",
                          "integrityImpact",
                          "baseScore" ]

        for info in (self.generalInfo + self.cvssInfo):
            self.data[info] = ""
        self.data['ID'] = ""
        self.data['description'] = ""
        self.data['references'] = []
        self.data['vulnerableSoftwareList'] = []
        self.data['productIdList'] = []
        self.data['productComparisonList'] = []

    def __str__(self):
        '''CVE announcement.
        '''
        description = "%s\n" % self.data['ID']
        keys = self.data.keys()
        keys.sort()
        for k in keys:
            description += "%s : %s\n" % (k.ljust(25), self.data[k])

        return description

    def verbose(self, message, level=1):
        """Print given message to STDERR if the object's verbosity is >=
        the given level.

        Args:
            message (str): a message to be sent to STDERR
            level: verbose output level (currently set to 1)

        Returns: 
            None
        """
        
        if (self.verbosity >= level):
            sys.stderr.write("%s> %s\n" % ('=' * level, message))
        '''

        f = open("log.txt", "a+")
        f.write("%s> %s\n" % ('=' * level, message))
        '''

    def traverse(self, partial_list, rest_value):
        ''' Traverse both partial_list and rest_value, to construct
            a list of possible version numbers.

        Args:
            partial_list (list): a list of the beginning of possible 
                                 versions
            rest_value (list of lists): a list of the remaining elements
                                        in possible version numbers

        Returns:
            result(list): a complete list of possible version numbers
        '''
        result = []
        for i in partial_list:
            current=[]
            for j in rest_value[0]:
                current.append(str(i+"."+j))
            if len(rest_value) > 1:
                current = self.traverse(current, rest_value[1:])
            result += current
        return result

    def all_versions_under(self, vendor_name, product_name,
                           current_version, prev_version, cve_id):

        '''Enumerate possible product IDs and vulnerable software 
           versions between prev_version and current_version. Add these
           entries to the current CVE instance.

           Possible versions are enumerated to each version segment's 
           larger 10th.

        Args:
            vendor_name (str): vendor name, used in ID and version 
                               list construction
            product_name (str): product name, used in ID and version 
                                list construction
            current_version (str): largest version number possible
            prev_version (str): previous smaller version for this software
                                This function aims to find versions between
                                prev_version and current_version.
        

        Returns:
            None
        '''
        version_ints = current_version.split(".")
        prev_version_ints = prev_version.split(".")
        potential_versions = []

        version_num = 0
        prev_version_num = 0
        length = len(version_ints)

        ''' If the prev_version is one segment shorter than the 
            current version... e.g. 14.5 and 14.5.5
        '''
        if len(prev_version_ints) < length:
            prev_version_ints.append("0")

        try:
            for index in range(length):
                potential_versions.append([])
                if index == 0:
                    '''If it is the first segment, then all possibilities
                       must be smaller than itself.
                    '''
                    for num in range(int(prev_version_ints[index]),
                                     int(version_ints[index]) + 1):
                        potential_versions[index].append(str(num))
                else:
                    '''If it is not the first segment, then possibilities
                       are flexed to the upper 10th. e.g. 9 to 10, 81 to 90.

                       This is not the best solution, but it is a reasonable
                       solution considering running effeciency.
                    '''
                    larger = max(int(prev_version_ints[index]),
                                 int(version_ints[index]))
                    for num in range(10*((larger // 10) + 1)):
                        potential_versions[index].append(str(num))
        except ValueError:
            '''If the version number contains letters or words, like "a"
               or "beta", then we just don't try to enumerate smaller versions.
            '''
            product_id = (vendor_name + ":" + product_name + ":" 
                                  + current_version + ":" + cve_id)
            self.data["productIdList"].append(product_id)
            self.data["vulnerableSoftwareList"].append(vendor_name + ":"
                                                       + product_name + ":"
                                                       + current_version)
            
            self.verbose("Product ID: %s" % self.data["productIdList"][-1])
            return

        '''Possible version enumeration
        '''
        versions_list = self.traverse(potential_versions[0],
                                      potential_versions[1:])

        '''Save reasonable possible versions.
        '''
        for version in versions_list:
            if (LooseVersion(version) > LooseVersion(prev_version) and
                LooseVersion(version) <= LooseVersion(current_version)):
                    product_id = (vendor_name + ":" + product_name + ":" 
                                  + version + ":" + cve_id)
                    self.data["productIdList"].append(product_id)
                    self.data["vulnerableSoftwareList"].append(vendor_name + ":"
                                                               + product_name + ":"
                                                               + version)
                    
                    self.verbose("Product ID: %s" % self.data["productIdList"][-1])


    def describeCVE(self, cve_detail, verbosity):
        '''From dictionary, construct 

        Args:
            cve_detail (dict)： 
        '''
        self.verbosity = verbosity

        try:
            self.data['ID'] = cve_detail["cve"]["CVE_data_meta"]["ID"]
        except KeyError:
            sys.stderr.write("JSON format Error in reading CVE ID.\n")
            sys.exit(EXIT_ERROR)

        self.verbose("==========================================") 
        self.verbose("Processing %s :" % self.data['ID']) 

        try:     
            for info in self.generalInfo:
                self.data[info] = cve_detail[info]
                self.verbose(info + ": " + self.data[info])
        except KeyError:
            sys.stderr.write("JSON format Error in reading CVE general info "
                             "for %s.\n" % self.data['ID'])
            pass

        try:
            for info in self.cvssInfo:
                self.data[info] = cve_detail["impact"]["baseMetricV2"]["cvssV2"][info]
                self.verbose(info + ":" + str(self.data[info]))
        except KeyError:
            sys.stderr.write("JSON format Error in reading CVE CVSS info "
                             "for %s.\n" % self.data['ID'])
            pass

        '''
        except KeyError:
            sys.stderr.write("JSON format Error in reading CVE CVSS info "
                             "for %s.\n" % self.data['ID'])
            sys.exit(EXIT_ERROR)
        '''

        '''As of what I briefly observe, the first item of "description_data" is always the 
           English language description. For the sake of running time, index value 0 is used.
           
           Might subject to change.
        '''
        try:
            self.data["description"] = cve_detail["cve"]["description"]["description_data"][0]["value"]
        except KeyError:
            sys.stderr.write("JSON format Error in reading CVE description for %s.\n" % self.data['ID'])
            pass

        try:
            for reference in cve_detail["cve"]["references"]["reference_data"]:
                self.data["references"].append(reference['url'])
                self.verbose("Reference: " + self.data["references"][-1])
        except KeyError:
            sys.stderr.write("JSON format Error in reading CVE reference hyperlinks for "
                             "%s.\n" % self.data['ID'])
            pass
        

        self.verbose("---------PRODUCTS---------")
        try:
            for vendor in cve_detail["cve"]["affects"]["vendor"]["vendor_data"]:
                vendor_name = vendor["vendor_name"]
                for product in vendor["product"]["product_data"]:
                    product_name = product["product_name"]
                    self.verbose("Processing %s(product) from %s(vendor)" 
                                 %(product_name, vendor_name))
                    for version in product["version"]["version_data"]:
                        base_version = version["version_value"]
                        product_id = (vendor_name + ":" + product_name + ":" + base_version
                                      + ":" + self.data['ID'])

                        self.data["productIdList"].append(product_id)
                        self.data["productComparisonList"].append(version["version_affected"])
                        self.data["vulnerableSoftwareList"].append(vendor_name + ":" 
                                                            + product_name + ":" + base_version)
                        print("Product ID: %s" % self.data["productIdList"][-1])
        except KeyError:
            sys.stderr.write("JSON format Error in reading vendors, products, or versions "
                             "for %s.\n" % self.data['ID'])
            pass
       

class CVEDB(object):
    def __init__(self):
        """Construct a new CVEDB with defaults."""
        self.dbfile = DEFAULT_CVEDB_FILE
        self.sourcefile = ''
        self.counter = 0
        self.conn = None
        self.cursor = None
        self.verbosity = 0

    class Usage(Exception):
        """A simple exception that provides a usage statement and a return
        code."""

        def __init__(self, err_val):
            self.err = err_val
            self.msg = 'Usage: %s [-hv] [-d dbfile] [-s source]\n' % os.path.basename(sys.argv[0])
            self.msg += '\t-d dbfile   update this database, default location /var/db/cvedb\n'
            self.msg += '\t-s source   NVD vulnerability data feed in JSON fotmat\n'
            self.msg += '\t-h          print help message and exit\n'
            self.msg += '\t-v          verbose running option\n'

    def verbose(self, message, level=1):
        """Print given message to STDERR if the object's verbosity is >=
        the given lefel."""

        
        if (self.verbosity >= level):
            sys.stderr.write("%s> %s\n" % ('=' * level, message))
        '''

        f = open("log.txt", "a+")
        f.write("%s> %s\n" % ('=' * level, message))
        '''

    def parseOptions(self, command):
        """Parse given command-line optoins and set appropriate
        attributes.

        Arguments:
            inargs -- arguments to parse

        Raises:
            Usage -- if '-h' or invalid command-line args are given
        """

        try:
            options, arguments = getopt.getopt(command, "hvd:s:", 
                                                    ["help", "verbose", "dbfile=", "sourcefile="])
        except getopt.GetoptError:
            raise self.Usage(EXIT_ERROR)

        for option, argument in options:  
            if option in ("-h", "--help"):
                raise self.Usage(EXIT_SUCCESS)
            elif option in ("-v", "--verbose"):
                self.verbosity += 1
            elif option in ("-d", "--dbfile"):
                self.dbfile = argument
            elif option in ("-s", "--sourcefile"):
               self.sourcefile = argument
            else:
                sys.stderr.write("Invalid options.\nPlease refer to -h or --help for manual page.\n")
                raise self.Usage(EXIT_ERROR)
            
        if options == []:
            sys.stderr.write("Invalid options.\nPlease refer to -h or --help for manual page.\n")
            raise self.Usage(EXIT_ERROR)


    def createDB(self):
        """Create a DB with the correct schema."""

        self.verbose("Creating new database as '%s'..." % self.dbfile)
        try:
            self.conn = sqlite3.connect(self.dbfile)
            self.cursor = self.conn.cursor()
            self.cursor.execute('''CREATE TABLE nvd (access_vector varchar,
                                                    access_complexity varchar,
                                                    authentication varchar,
                                                    availability_impact varchar,
                                                    confidentiality_impact varchar,
                                                    cve_id text primary key,
                                                    integrity_impact varchar,
                                                    last_modified_datetime varchar,
                                                    published_datetime varchar,
                                                    score real,
                                                    summary varchar,
                                                    urls varchar,
                                                    vulnerable_software_list)''')

            self.cursor.execute('''CREATE TABLE product (product_id text primary key,
                                                        vendor_name varchar,
                                                        product_name varchar,
                                                        version_value varchar)''')

            self.cursor.execute('''CREATE TABLE map (cve_id text,
                                                    product_id text primary key)''')

            self.conn.commit()
            self.verbose("Table creation finished. Created tables nvd, product, map.")

        except sqlite3.Error as e:
            sys.stderr.write("Unable to create DB file '%s'.\n" % self.dbfile)
            sys.stderr.write("I'd love to tell you why, but the python sqlite3 "
                             "module does not expose the error codes.\n")
            sys.stderr.write("I'm guessing permissions problems.\n")
            sys.exit(EXIT_ERROR)
            # NOTREACHED


    def parseInput(self):
        """Read input (yes, all in one), and parse as XML.
           Operates on stdin, returns an xml.etree.ElementTree"""

        self.verbose("Parsing JSON input %s." % self.sourcefile)
        
        try:
            with open(self.sourcefile, 'r', encoding='utf-8') as json_file:
                cve_content = json.load(json_file)
        except ValueError:
            sys.stderr.write("Unable to parse input as valid JSON: %s\n" % self.sourcefile)
            sys.exit(EXIT_ERROR)

        assert (cve_content["CVE_data_format"]), "JSON data is not in MITRE format."
        return cve_content

    def insertNvd(self, cve):
        self.verbose("------INSERTING INTO DATABASE------")
        self.verbose("\nInserting %s into nvd table..." % cve.data["ID"])

        self.verbose("Checking if %s is already in nvd..." % cve.data["ID"])
        self.cursor.execute('SELECT cve_id FROM nvd where cve_id=?', (cve.data['ID'],))
        if self.cursor.fetchone() != None:
            self.verbose("Previous entry of %s in nvd table. Deleting previous entry..."
                         % cve.data['ID'])
            self.cursor.execute("DELETE from nvd where cve_id=?", (cve.data['ID'],))
        else:
            self.verbose("No previous entry of %s found in nvd table." % cve.data['ID'])
        
        self.verbose("Adding %s to nvd table." % cve.data['ID'])
        try:
            self.cursor.execute("INSERT INTO nvd VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (cve.data['accessVector'],
                     cve.data['accessComplexity'],
                     cve.data['authentication'],
                     cve.data['availabilityImpact'],
                     cve.data['confidentialityImpact'],
                     cve.data['ID'],
                     cve.data['integrityImpact'],
                     cve.data['lastModifiedDate'],
                     cve.data['publishedDate'],
                     cve.data['baseScore'],
                     cve.data['description'],
                     ",".join(cve.data['references']),
                     ",".join(cve.data['vulnerableSoftwareList'])))
            self.verbose("Added %s to nvd table" % cve.data["ID"])
        except sqlite3.Error as e:
            sys.stderr.write("Unable to insert %s into DB.\n" % cve.data['ID'])
            sys.stderr.write(e.args[0] + '\n')

    def insertMap(self, cve):
        self.verbose("\nInserting %s into map table..." % cve.data["ID"])

        self.cursor.execute("SELECT product_id FROM map where cve_id=?", (cve.data['ID'],))
        existing_entries = list(sum(self.cursor.fetchall(), ()))
        # print(existing_entries)

        for pid in cve.data["productIdList"]:
            if pid in existing_entries:
                self.verbose("%s %s already in map table..." %(cve.data["ID"], pid))
            else:
                if pid != None:
                    self.verbose("Adding %s %s to map table..." %(cve.data["ID"], pid))
                    self.cursor.execute("INSERT INTO map VALUES (?,?)",
                                        (cve.data['ID'],
                                         pid))
                    self.verbose("Added to map table.")                


    def insertProduct(self, cve):
        self.verbose("\nInserting %s into product table..." % cve.data["ID"])

        #vendor_name + ":" + product_name + ":" + version_value

        for index in range(len(cve.data["productIdList"])):
            pid = cve.data["productIdList"][index]
            comparison = cve.data["productComparisonList"][index]

            self.verbose("Checking if %s is in product table..." % pid)
            self.cursor.execute('SELECT * FROM product where product_id=?', (pid,))
            
            if self.cursor.fetchall():
                self.verbose("%s already in product table..." % pid)
                pass
            else:

                self.verbose("No previous entry of %s found in product table.")
                pid_segments = pid.split(":")
                self.cursor.execute("INSERT INTO product VALUES (?,?,?,?)",
                                    (pid,
                                     pid_segments[0],
                                     pid_segments[1],
                                     pid_segments[2]))
                self.verbose("Added to product table.")




    def updateDB(self, cve_content):
        try:
            if not self.conn:
                self.conn = sqlite3.connect(self.dbfile)
            if not self.cursor:
                self.cursor = self.conn.cursor()

            # sqlite continues without syncing or journaling
            self.cursor.execute('PRAGMA synchronous = 0')
            self.cursor.execute('PRAGMA journal_mode = OFF')

            self.verbose("Connects database, no syncing, no rollback journals.")

        except sqlite3.Error as e:
            sys.stderr.write("Unable to open DB file '%s'.\n" % self.dbfile)
            sys.stderr.write("I'd love to tell you why, but the python sqlite3 "
                             "module does not expose the error codes.\n")
            sys.stderr.write("I'm guessing permissions problems.\n")
            sys.exit(EXIT_ERROR)

        self.verbose("Update database %s with new JSON data." % self.sourcefile)
        
        for item in cve_content["CVE_Items"]:
            cve = CVE()
            cve.describeCVE(item, self.verbosity)

            self.insertNvd(cve)
            self.insertMap(cve)
            self.insertProduct(cve)

        # update database

        self.conn.commit()
        self.conn.close()
            

if __name__ == "__main__":
    try:
        cvedb = CVEDB()
        try:
            cvedb.parseOptions(sys.argv[1:])
            if not os.path.exists(cvedb.dbfile):
                cvedb.createDB()
            cve_content = cvedb.parseInput()
            cvedb.updateDB(cve_content)

        except cvedb.Usage as u:
            if (u.err == EXIT_ERROR):
                out = sys.stderr
            else:
                out = sys.stdout
            out.write(u.msg)
            sys.exit(u.err)
            # NOTREACHED

    except KeyboardInterrupt:
        # catch ^C, so we don't get a "confusing" python trace
        sys.exit(EXIT_ERROR)