#!/usr/bin/python
import logging
import socket
import smtplib
import requests
import urllib
import os
import re
#import signal
import subprocess
import sys
import time

from lxml import etree
from email.mime.text import MIMEText
from ConfigParser import ConfigParser
from optparse import OptionParser

INTERVAL = 60
SENDER = 'ganglia@localhost'
SERVER = 'localhost'
RECIPIENTS = []
SMS_NUMBER = ''
SUBJECT = 'Ganglia Alerts'
ALERTS = []
LOG_FILE = '/var/log/ganglia-alert.log'
PID_FILE = '/var/run/ganglia-alert.pid'
API_KEY = ""
API_SECRET = ""
ACTIONS = []
DEBUG = True

FORMAT = '%(asctime)-15s %(levelname)-8s %(message)s'

def debug(message):
     global DEBUG
     if DEBUG:
         print message
     logging.debug(message)

def read(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    data = ""
    while True:
        bytes = s.recv(4096)
        if len(bytes) == 0:
            break;
        data += bytes
    s.close()
    return data

def parse(s):
    hosts = {}
    root = etree.XML(s)
    for host in root.iter('HOST'):
        name = host.get('NAME')
        hosts[name] = {}
        metrics = hosts[name]
        for m in host.iter('METRIC'):
            metrics[m.get('NAME')] = m.attrib.get("VAL")
    return hosts

def send_mail(message):
    message = MIMEText(message)
    message['From'] = SENDER
    message['To'] = ', '.join(RECIPIENTS)
    message['Subject'] = 'iOla Alerts'
    smtp = smtplib.SMTP(SERVER)
    smtp.sendmail(SENDER, RECIPIENTS, message.as_string())

def send_sms(message):
    api_key = API_KEY
    api_secret = API_SECRET
    url = "https://rest.nexmo.com/sms/json?api_key={0}&api_secret={1}&from=iOla20&to={2}&text={3}".format(api_key, api_secret, SMS_NUMBER, urllib.quote_plus(message))
    #url = "https://sgw01.cm.nl/gateway.ashx?producttoken={0}&body={2}&to={1}&from=iOla&reference=Alert".format(api_key, SMS_NUMBER, message)
    debug(requests.get(url).json())

def check_alerts(host, vars):
    r = ""
    global ACTIONS
    for alert in ALERTS:
        if alert.check(vars):
            r += "{0}: {1} (because: {2})\n".format(alert.severity, alert.message, alert.expression)
            logging.info("On {0} {1} (because: {2})".format(host, alert.message, alert.expression))
            if alert.occurences > 0:
                alert.counter += 1    
                if alert.counter >= alert.occurences:
                    ACTIONS.append(alert.action)
    if r != "":
        r = "On host {0}:\n{1}".format(host,r)
    return r

def main():
    global ACTIONS
    s = read('localhost', 8651)
    hosts = parse(s)
    body = ""
    for h in hosts:
        body += check_alerts(h, hosts[h])
    if body != "":
        debug("Sending mail")
        send_mail(body)
        # debug("Sending SMS")
        ## send_sms("Alerts on iOla. Please check the dahboard for details")
    for action in ACTIONS:
        try:
            debug("Running: "+action)
            subprocess.call(action)
        except:
            pass
    ACTIONS = []

class Alert(object):
    def __init__(self, severity, expression, message, action, occurences=0):
        self.severity = severity
        self.expression = expression
        self.message = message
        self.action = action
        self.occurences = occurences
        self.counter = 0

    def check(self, vars):
        e = self.expression[:]
        for v in vars:
            e = e.replace(v, vars[v])
        return eval(e)

def init(config_file="ganglia-alert.conf"):
    global INTERVAL, SENDER, SERVER, RECIPIENTS, ALERTS, SMS_NUMBER, DEBUG, LOG_FILE, PID_FILE, API_KEY, API_SECRET
    config = ConfigParser()
    try:
        config.read(config_file)
        INTERVAL = config.getint("options", "interval")
        DEBUG = config.getboolean("options", "debug")
        LOG_FILE = config.get("options", "log_file")
        PID_FILE = config.get("options", "pid_file")
        SENDER = config.get("mail", "sender")
        SERVER = config.get("mail", "server")
        RECIPIENTS = [s.strip() for s in config.get("mail", "recipients").split(",")]
        SMS_NUMBER = config.get("sms", "recipient")
        API_KEY = config.get("sms", "api_key")
        API_SECRET = config.get("sms", "api_secret")
        for section in config.sections():
            if section[:5] == 'Alert':
                severity = config.get(section, 'type')
                expression = config.get(section, 'expression')
                message = config.get(section, 'message')
                action = config.get(section, 'action')
                occurences = config.getint(section, 'occurences')
                ALERTS.append(Alert(severity, expression, message, action, occurences))
        logging.basicConfig(format=FORMAT, filename=LOG_FILE, level=logging.DEBUG)
    except:
        debug("Bad configuration");
        sys.exit(2)

def get_pid():
    pid = None
    try:
        pidfile = open(PID_FILE)
        pid = int(pidfile.read())
        pidfile.close()
    finally:
        return pid

def write_pid():
    pidfile = open(PID_FILE, "w")
    pid = os.getpid()
    pidfile.write(str(pid))
    pidfile.close()

def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True

def handler(signum, frame):
    debug("Interrupted")
    sys.exit(3)   

if __name__=="__main__":
    parser = OptionParser()
    parser.add_option("-d", "--daemon", dest="daemon", action="store_true",
                  help="starts the process demonish-ly")
    parser.add_option("-k", "--kill", dest="kill", action="store_true",
                  help="kills the process")
    parser.add_option("-s", "--send", dest="sendAlert", action="store_true",
                  help="don't print status messages to stdout")

    (options, args) = parser.parse_args()

    init("/etc/ganglia/ganglia-alert.conf")

    if options.daemon:
        #signal.signal(signal.SIGINT, handler)
        pid = get_pid()
        if get_pid() != None and check_pid(pid):
            debug("Already running with pid:"+str(get_pid()))
            sys.exit(1)
        write_pid()
        try:
            while True:
                main()
                time.sleep(INTERVAL)
        except KeyboardInterrupt:
            handler(0,0)

    if options.kill:
        pid = get_pid()
        if get_pid() != None and check_pid(pid):
            debug("Stopping pid:"+str(get_pid()))
            os.remove(PID_FILE)
            sys.exit(0)

    if options.sendAlert:
        DEBUG = True
        logging.info("Manual alert sent")
        debug("Sending alert.")
        main()

