"""
Output plugin for tiot
See: https://github.com/Phype/telnet-iot-honeypot
"""

from __future__ import absolute_import, division

import json
import logging

from twisted.internet import endpoints, reactor, ssl
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CONFIG

import requests
import requests.exceptions
import requests.auth

import json
import time
import struct

import traceback
import os.path


OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
TYPE_INPUT, TYPE_OUTPUT, TYPE_INTERACT = 1, 2, 3

def readttylog(filename):
    
    fd = open(filename, "rb")
    
    ssize = struct.calcsize('<iLiiLL')
        
    lastin = ""
    firstts = None
    stream = []

    while 1:
        try:
            (op, tty, length, dir, sec, usec) = \
                struct.unpack('<iLiiLL', fd.read(ssize))
            data = fd.read(length)
        except struct.error:
            break

        if op == OP_WRITE:
            
            data = data.decode("ascii", "ignore")
            
            ts = float(sec) + float(usec) / 1000000
            
            if firstts == None:
                firstts = ts
                ts = 0.0
            else:
                ts = ts - firstts
                ts = round((ts) * 1000) / 1000
            
            if dir == TYPE_OUTPUT:
                if lastin.startswith(data):
                    lastin = lastin[len(data):]
                else:
                    # print [1, dir, data]
                    stream.append({
                        "in":False,
                        "ts":ts,
                        "data":data
                    })
            elif dir == TYPE_INPUT:
                lastin = data
                #print [2, dir, data]
                #sys.stdout.write(data)
                stream.append({
                    "in":True,
                    "ts":ts,
                    "data":data
                })
                
        if op == OP_CLOSE:
            break
        
    return stream

class Client:

    def __init__(self, url, user, password):
        self.user     = user
        self.password = password
        self.url      = url
        self.auth     = requests.auth.HTTPBasicAuth(self.user, self.password)

        self.test_login()
    
    def test_login(self):
        try:
            r = requests.get(self.url + "/connections", auth=self.auth, timeout=20.0)
        except Exception as e:
            traceback.print_exc(e)
            raise IOError("Cannot connect to backend")
        try:
            r = requests.get(self.url + "/login", auth=self.auth, timeout=20.0)
            if r.status_code != 200:
                raise IOError()
        except Exception as e:
            traceback.print_exc(e)
            raise IOError("Backend authentification test failed, check config.json")

    def put_session(self, session, retry=True):
        
        try:
            r = requests.put(self.url + "/conns", auth=self.auth, json=session, timeout=20.0)
        except requests.exceptions.RequestException:
            log.msg("Cannot connect to backend")
            return []
        
        if r.status_code == 200:
            return r.json()
        elif retry:
            msg = r.raw.read()
            log.msg("Backend upload failed, retrying (" + str(msg) + ")")
            return self.put_session(session, False)
        else:
            msg = r.raw.read()
            raise IOError(msg)

    def put_sample(self, data, retry=True):
        
        try:
            r = requests.post(self.url + "/file", auth=self.auth, data=data, timeout=20.0)
        except requests.exceptions.RequestException:
            log.msg("Cannot connect to backend")
            return
        
        if r.status_code == 200:
            return
        elif retry:
            msg = r.raw.read()
            log.msg("Backend upload failed, retrying (" + str(msg) + ")")
            return self.put_sample(sha256, filename, False)
        else:
            msg = r.raw.read()
            raise IOError(msg)

class Output(cowrie.core.output.Output):
    """
    Output plugin for HPFeeds
    """

    channel = 'cowrie.sessions'

    def start(self):
        log.msg("WARNING: Beta version of new hpfeeds enabled. This will become hpfeeds in a future release.")

        self.backend_url = CONFIG.get('output_tiot', 'backend_url')
        self.username    = CONFIG.get('output_tiot', 'username')
        self.password    = CONFIG.get('output_tiot', 'password')

        self.meta = {}

        self.client = Client(self.backend_url, self.username, self.password)

    def stop(self):
        pass

    def write(self, entry):
        session = entry["session"]
        if entry["eventid"] == 'cowrie.session.connect':
            self.meta[session] = {
                "type"          : "connection",
                "ip"            : entry["src_ip"],
                "user"          : None,
                "pass"          : None,
                "date"          : time.time(), # entry["timestamp"],
                "stream"        : [],
                "samples"       : [],
            }

        elif entry["eventid"] == 'cowrie.login.success':
            self.meta[session]['user'] = entry['username']
            self.meta[session]['pass'] = entry['password']

        elif entry["eventid"] == 'cowrie.login.failed':
            pass

        elif entry["eventid"] == 'cowrie.command.input':
            ts = round((time.time() - self.meta[session]['date']) * 1000) / 1000
            
            # Add dummy prompt for readability
            self.meta[session]['stream'].append({
                "in":   False,
                "ts":   ts,
                "data": " > "
            })
            
            self.meta[session]['stream'].append({
                "in":   True,
                "ts":   ts,
                "data": entry['input']
            })
            
            # Add newline for readability
            self.meta[session]['stream'].append({
                "in":   True,
                "ts":   ts,
                "data": "\n"
            })

        elif entry["eventid"] == 'cowrie.command.failed':
            pass

        elif entry["eventid"] == 'cowrie.session.file_download':
            
            filepath = None
            filesize = 0
            if entry['outfile'] and os.path.isfile(entry['outfile']):
                filepath = entry['outfile']
                filesize = os.path.getsize(filepath)
            
            self.meta[session]['samples'].append({
                "type":   "sample",
                "url":    entry['url'],
                "name":   entry['destfile'],
                "date":   time.time(),
                "sha256": entry['shasum'],
                "info":   "",
                "length": filesize
            })

        elif entry["eventid"] == 'cowrie.session.file_upload':
            pass

        elif entry["eventid"] == 'cowrie.client.version':
            pass

        elif entry["eventid"] == 'cowrie.log.closed':
            self.meta[session]["stream"] = readttylog(entry["ttylog"])

        elif entry["eventid"] == 'cowrie.session.closed':
            meta = self.meta.pop(session, None)
            if meta:
                log.msg('publishing metadata to tiot', logLevel=logging.DEBUG)
                self.client.put_session(meta)
