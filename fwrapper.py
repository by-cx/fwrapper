#!/usr/bin/env python

# Imports

import sys
import datetime
import shlex
from subprocess import PIPE, POpen

def log(msg):
    date = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    print "%s: %s" % (date, msg)

def run(cmd):
    p = POpen()
    stdout, stderr = p.communicate()
    if stdout:
        print strout
    if stderr:
        print strerr

# Classes

class Firewall(object):
    rules = {
        "filter4": [],
        "filter6": [],
        "nat": [],
    }
    filename = ""
    content = ""

    def __init__(self, filename):
        self.filename = filename
        self.load()
        self.parse()

    def load(self):
        f = open(_script)
        self.content = [x.strip() for x in f.readlines()]
        f.close()

    def parse(self):
        for line in self.content:
            if len(line) and line[0] != "#":
                cmd = shlex.split(line)
                if len(cmd):
                    if cmd[0] == "filter":
                        self.rules["filter4"].append(cmd[1:])
                    elif cmd[0] == "filter4":
                        self.rules["filter4"].append(cmd[1:])
                    elif cmd[0] == "filter6":
                        self.rules["filter4"].append(cmd[1:])
                    elif cmd[0] == "filter46":
                        self.rules["filter4"].append(cmd[1:])
                        self.rules["filter6"].append(cmd[1:])
                    elif cmd[0] == "filter64":
                        self.rules["filter4"].append(cmd[1:])
                        self.rules["filter6"].append(cmd[1:])
                    elif cmd[0] == "nat":
                        self.rules["nat"].append(cmd[1:])
                    else:
                        log("Warning: wrong rule (%s)" % " ".join(cmd))
    def stop_rules(self):
        pass

    def rule_format(self, rule):
        chain = ""
        action = ""
        options = []
        last = ""
        for parm in rule:
            if last == "chain":
                chain = parm
            elif last == "jump":
                action = parm

            if parm in ["-A", "-N"]:
                last = "chain"
                continue
            elif parm in ["-j"]:
                last = "jump"
                continue
            elif last == "":
                options.append(parm)

            last = ""
        return chain, " ".join(options), action

    def print_rules(self):
        for ruletype in self.rules:
            if ruletype == "filter4":
                print "Firewall for IPv4"
                print 
            if ruletype == "filter6":
                print "Firewall for IPv6"
                print 
            if ruletype == "nat":
                print "Firewall - NAT"
                print 
            print "|",
            print "Chain".ljust(20),
            print "|",
            print "Options".ljust(55),
            print "|",
            print "Action".ljust(20),
            print "|"

            for rule in self.rules[ruletype]:
                chain, options, action = self.rule_format(rule)

            print 


# Script load

if len(sys.argv) < 2:
    log("No script to load")
    sys.exit(1)

_script = sys.argv[1]

firewall = Firewall(_script)

if len(sys.argv) < 3:
    print " Usage:"
    print "  %s start|restart|stop|list" % _script
    sys.exit(1)
_action = sys.argv[2]

# Functions

def start():
    pass

def stop():
    pass

def restart():
    stop()
    start()

# Actions

if _action == "start":
    start()
    log("Fw %s started")
elif _action == "stop":
    stop()
    log("Fw %s stopped")
elif _action == "restart":
    restart()
    log("Fw %s restarted")
elif _action == "list":
    firewall.print_rules()
else:
    print " Usage:"
    print "  %s start|restart|stop|list" % _script

