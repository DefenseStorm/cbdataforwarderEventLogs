#!/usr/bin/env python3

import sys,os,getopt
import traceback
import os
import fcntl
import json
import requests
import time
import re
import boto3
import gzip
import datetime

from six import PY2

if PY2:
    get_unicode_string = unicode
else:
    get_unicode_string = str

sys.path.insert(0, './ds-integration')
from DefenseStorm import DefenseStorm

from html.parser import HTMLParser

class integration(object):


    JSON_field_mappings = {
        'type' : 'category',
        'device_external_ip' : 'external_ip',
        'device_os' : 'os_type',
        'process_reputation' : 'reputation',
        'process_username' : 'reputation',
        'sensor_action' : 'action',
        'process_cmdline' : 'command_line',
        'process_hash' : 'hash',
        'parent_cmdline' : 'parent_command_line',
        'parent_pid' : 'parent_process_id',
        'device_name' : 'hostname',
        'local_ip' : 'sensor_ip',
        'event_description' : 'message',
        'device_timestamp' : 'timestamp'
    }

    def get_S3_file_list(self):
        if not os.path.isdir('datadir'):
            os.mkdir('datadir')
        if len(os.listdir('datadir')) > 1:
            self.ds.log('ERROR', "datadir/ is not empty.  A previous run might have failed.  Exiting")
            return None

        obj_list = self.s3_bucket.objects.filter(Prefix = 'dsoffice/org_key=' + self.cb_org)
        file_list = []
        for b_obj in obj_list:
            file_list.append(b_obj.key)
        return file_list

    def process_file(self, s3_file):
        try:
            self.ds.log('INFO', "Downloading file: %s" %(s3_file))
            local_file = 'datadir/' + s3_file.replace('/','_')
            self.s3_bucket.download_file(s3_file, local_file)
            self.ds.log('INFO', "Processing file %s" %(local_file))
            with gzip.open(local_file) as f:
                for line in f:
                    event = json.loads(str(line, 'utf-8'))
                    event['device_timestamp'] = event['device_timestamp'].split('+')[0][:-1].replace(' ', 'T')
                    if 'process_hash' in event.keys() and len(event['process_hash']) == 1:
                        event['process_hash'] = event['process_hash'][0]
                    self.ds.writeJSONEvent(event, JSON_field_mappings = self.JSON_field_mappings)
            self.ds.log('INFO', "Deleting s3 object %s" %(s3_file))
            #self.s3_bucket.delete_object(s3_file)
            self.s3.Object(self.s3_bucket_name, s3_file).delete()
        except Exception as e:
            self.ds.log('ERROR', "Error handling file %s: %s" %(s3_file, e))
            return False
        os.remove(local_file)
        return True

    def delete_SQS_message(self, sqs_rh):
        self.ds.log('INFO', "Deleting SQS Notification: %s" %(sqs_rh))
        try:
            self.sqs.delete_message(QueueUrl = self.sqs_url, ReceiptHandle = sqs_rh)
        except Exception as e:
            self.ds.log('ERROR', "Failed to delete SQS Notification: %s - %s" %(sqs_rh, e))
            return False
        return True

    def cs_main(self): 

        self.s3_key = self.ds.config_get('cb', 's3_key')
        self.s3_secret = self.ds.config_get('cb', 's3_secret')
        self.s3_bucket_name = self.ds.config_get('cb', 's3_bucket')
        self.cb_org = self.ds.config_get('cb', 'org')

        try:
            self.s3 = boto3.resource('s3', aws_access_key_id=self.s3_key, aws_secret_access_key=self.s3_secret)
            self.s3_bucket = self.s3.Bucket(self.s3_bucket_name)
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return

        s3_files = self.get_S3_file_list()
        for s3_file in s3_files:
            self.ds.log('INFO', "Downloading file: %s" %(s3_file))
            if not self.process_file(s3_file):
                self.ds.log('ERROR', "Failed to process file: %s" %(s3_file))
                break


    def run(self):
        try:
            pid_file = self.ds.config_get('cb', 'pid_file')
            fp = open(pid_file, 'w')
            try:
                fcntl.lockf(fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except IOError:
                self.ds.log('ERROR', "An instance of cb defense syslog connector is already running")
                # another instance is running
                sys.exit(0)
            self.cs_main()
        except Exception as e:
            traceback.print_exc()
            self.ds.log('ERROR', "Exception {0}".format(str(e)))
            return
    
    def usage(self):
        print
        print(os.path.basename(__file__))
        print
        print('  No Options: Run a normal cycle')
        print
        print('  -t    Testing mode.  Do all the work but do not send events to GRID via ')
        print('        syslog Local7.  Instead write the events to file \'output.TIMESTAMP\'')
        print('        in the current directory')
        print
        print('  -l    Log to stdout instead of syslog Local6')
        print
    
    def __init__(self, argv):

        self.testing = False
        self.send_syslog = True
        self.ds = None
    
        try:
            opts, args = getopt.getopt(argv,"htnld:",["datedir="])
        except getopt.GetoptError:
            self.usage()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.usage()
                sys.exit()
            elif opt in ("-t"):
                self.testing = True
            elif opt in ("-l"):
                self.send_syslog = False
    
        try:
            self.ds = DefenseStorm('cbdataforwarderEventLogs', testing=self.testing, send_syslog = self.send_syslog)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass


if __name__ == "__main__":
    i = integration(sys.argv[1:]) 
    i.run()
