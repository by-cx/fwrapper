#!/usr/bin/env python2

# Imports

import os
import sys
import datetime
import shlex
import pickle
from subprocess import PIPE, Popen

state_path = "/var/cache/fwrapper/fw.state"
try:
    os.makedirs("/var/cache/fwrapper")
except OSError, e:
    pass

def log(msg):
    date = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    print "%s: %s" % (date, msg)

def run(cmd):
    if "debug" in sys.argv:
        print " ".join(cmd)
    if "off" in sys.argv:
        return

    p = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    if stdout and "debug" in sys.argv:
        log(stdout)
    if stderr:
        print "Error:", " ".join(cmd)
        log(stderr)
        print "----------------------------------------------------"
    return stdout

# Classes

class FWrapperException(Exception): pass

class Color:
    header = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[93m'
    RED2 = '\033[91m'
    ENDC = '\033[0m'

    def disable(self):
        self.HEADER = ''
        self.OKBLUE = ''
        self.OKGREEN = ''
        self.WARNING = ''
        self.FAIL = ''
        self.ENDC = ''

class Firewall(object):
    rules = {
        "filter4": [],
        "filter6": [],
        "nat": [],
        "mangle": [],
    }
    policy = {
            "INPUT": "ACCEPT",
            "OUTPUT": "ACCEPT",
            "FORWARD": "ACCEPT",
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
                    if cmd[0] in ["filter", "filter4", "filter64", "filter46"]:
                        self.rules["filter4"].append(cmd[1:])
                    if cmd[0] in ["filter6", "filter64", "filter46"]:
                        self.rules["filter6"].append(cmd[1:])
                    if cmd[0] == "nat":
                        self.rules["nat"].append(cmd[1:])
                    if cmd[0] == "mangle":
                        self.rules["mangle"].append(cmd[1:])
                    if cmd[0] in ["forward", "output", "input"]:
                        self.policy[cmd[0].upper()] = cmd[1].upper()

    def start_cmd_generator(self):
        cmds = []

        for ruletype in self.rules:
            for rule in self.rules[ruletype]:
                if ruletype in ["filter", "filter4", "filter64", "filter46"]:
                    cmds.append(["iptables", "-t", "filter"] + rule)
                if ruletype in ["filter6", "filter64", "filter46"]:
                    cmds.append(["ip6tables", "-t", "filter"] + rule)
                if ruletype == "nat":
                    cmds.append(["iptables", "-t", "nat"] + rule)
                if ruletype == "mangle":
                    cmds.append(["iptables", "-t", "mangle"] + rule)

        for chain in self.policy:
            cmds.append(["iptables", "-P", chain, self.policy[chain]])
            cmds.append(["ip6tables", "-P", chain, self.policy[chain]])

        self.save_state()
            
        return cmds

    def clean_chains(self):
        tables = {
            "filter": ("INPUT", "OUTPUT", "FORWARD"),
            "nat": ("POSTROUTING", "INPUT", "OUTPUT", "PREROUTING"),
            "mangle": ("POSTROUTING", "INPUT", "FORWARD", "OUTPUT", "PREROUTING"),
        }

        def clean(table, ignore, iptables):
            stdout = run([iptables, "-t", table, "-L"])
            for line in [x.split() for x in stdout.split("\n") if "Chain" in x.split()]:
                run([iptables, "-t", table, "-F", line[1]])
                if line[1] not in ignore: 
                    run([iptables, "-t", table, "-X", line[1]])
        for table in ("nat", "filter", "mangle"):
            clean(table, tables[table], "iptables")
            if table not in ("nat", "filter"): clean(table, tables[table], "ip6tables")

    def clean_cmd_generator(self):
        pass

    def stop_cmd_generator(self):
        cmds = []

        try:
            data = self.load_state()
        except FWrapperException, e:
            log("Load state from file problem")
            sys.exit(1)
        
        for ruletype in data:
            rules = self.rules[ruletype]
            rules.reverse()
            for rule in rules:
                rule = map(lambda x: "-X" if "-N" == x else x, rule)
                rule = map(lambda x: "-D" if "-A" == x else x, rule)
                if ruletype in ["filter", "filter4", "filter64", "filter46"]:
                    cmds.append(["iptables", "-t", "filter"] + rule)
                if ruletype in ["filter6", "filter64", "filter46"]:
                    cmds.append(["ip6tables", "-t", "filter"] + rule)
                if ruletype == "nat":
                    cmds.append(["iptables", "-t", "nat"] + rule)
                if ruletype == "mangle":
                    cmds.append(["iptables", "-t", "mangle"] + rule)

        for chain in self.policy:
            cmds.append(["iptables", "-P", chain, "ACCEPT"])
            cmds.append(["ip6tables", "-P", chain, "ACCEPT"])

        return cmds

    def start(self):
        """Run commands to start firewall
        """
        cmds = self.start_cmd_generator()
        for cmd in cmds:
            run(cmd) 

    def stop(self):
        # Total clean
        self.clean_chains()

        for chain in self.policy:
            run(["iptables", "-P", chain, "ACCEPT"])
            run(["ip6tables", "-P", chain, "ACCEPT"])

        return 

        # Just what I've added
        cmds = self.stop_cmd_generator()
        for cmd in cmds:
            run(cmd) 

    def save_state(self):
        data = pickle.dumps(self.rules)
        try:
            f = open(state_path, "w")
            f.write(data)
            f.close()
        except OSError:
            raise FWrapperException("Save state problem")

    def load_state(self):
        try:
            f = open(state_path)
            data = pickle.loads(f.read())
            f.close()
        except OSError:
            raise FWrapperException("Load state problem")
        except IOError:
            raise FWrapperException("Load state problem")
        if not data:
            FWrapperException("Load state problem")
        return data

    def rule_format(self, rule):
        chain = ""
        prefix = ""
        action = ""
        options = []
        last = ""
        for parm in rule:
            if last == "chain":
                chain = parm
            elif last == "jump":
                action = parm

            if parm == "-A":
                last = "chain"
                prefix = "ADD to"
                continue
            if parm == "-N":
                last = "chain"
                prefix = "NEW   "
                continue
            elif parm in ["-j"]:
                last = "jump"
                continue
            elif last == "":
                options.append(parm)

            last = ""
        return "%s %s" % (prefix, chain), " ".join(options), action
            
    def print_rules(self):
        for ruletype in self.rules:
            if not self.rules[ruletype]: continue
            
            if ruletype == "filter4":
                print "Firewall for IPv4"
                print 
            if ruletype == "filter6":
                print "Firewall for IPv6"
                print 
            if ruletype == "nat":
                print "Firewall - NAT"
                print 
            print "-------------------------------------------------------------------------------------------------------"
            print "|",
            print "Chain".ljust(20),
            print "|",
            print "Options".ljust(55),
            print "|",
            print "Action/Jump".ljust(18),
            print "|"
            print "-------------------------------------------------------------------------------------------------------"

            for rule in self.rules[ruletype]:
                chain, options, action = self.rule_format(rule)
            
                print "|",
                print chain.ljust(20),
                print "|",
                print options.ljust(55),
                print "|",
                print action.ljust(18),
                print "|"
            print "-------------------------------------------------------------------------------------------------------"

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
    firewall.start()

def stop():
    firewall.stop()

def restart():
    stop()
    start()

# Actions

def main():
    if _action == "start":
        start()
        log("Fw %s started" % _script)
    elif _action == "stop":
        stop()
        log("Fw %s stopped" % _script)
    elif _action == "restart":
        restart()
        log("Fw %s restarted" % _script)
    elif _action == "list":
        firewall.print_rules()
    else:
        print " Usage:"
        print "  %s start|restart|stop|list" % _script

if __name__ == "__main__":
    main()
