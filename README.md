fwrapper
========

Wrapper for iptables - foundation for init script

This is simple low level wrapper for iptables scripts. Just write your *-A* and *-N* rules and then use this script. It can handle *start*/*stop*/*restart* actions and with *list* parameter it shows you list of rules.

Instalation
-----------

1. Clone repo
2. python setup.py install

Usage
-----

    fwrapper script.fw start|stop|restart|list

**start** - generate right ip(6)tables calls and run them
**stop** - generate opposit ip(6)tables calls and run them (-N becomes -X, -A becomes -D)
         - default policy will be set to ACCEPT
**restart** - run *stop* and then *start*
**list** - list of rules

Example of script.fw
--------------------

    #!/usr/local/bin/fwrapper

    # Default policy for IPv4 and IPv6
    input DROP
    output ACCEPT
    forward DROP

    # Rules for IPv4 and IPv6
    filter64 -N TEST
    filter64 -A FORWARD -j TEST
    filter64 -A TEST --dport 80 -j ACCEPT
    filter64 -A TEST --dport 443 -j ACCEPT
    filter64 -A TEST --dport 5000 -j ACCEPT
    filter64 -A TEST --dport 53 -j ACCEPT
    
    # Rules for IPv6
    filter6 -A TEST --dport 25 -j ACCEPT
    filter6 -A TEST -s 2002::/16 -j DROP

    # Rules for IPv4
    filter -A TEST --dport 111 -j ACCEPT
    filter -A TEST -s 2.2.2.0/24 -j ACCEPT

    # NAT rules
    nat -A POSTROUTING -o eth0 -j MASQUERADE
    nat -A POSTROUTING -o eth1 -j MASQUERADE

You can use this options:

* filter - rules for IPv4
* filter4 - rules for IPv4
* filter6 - rules for IPv6
* filter46 - rules for IPv4 and IPv6
* filter64 - rules for IPv4 and IPv6
* nat - NAT rules
