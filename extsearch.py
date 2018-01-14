#!/usr/bin/python

import sys
import subprocess
import re
import os.path
import logging

SCR_VERSION = "1.0.0"

log = logging.getLogger('scripts.extsearch')

# Print formatting
CSI = "\x1B["
RESET = CSI + "0m"
UNDERLINE = CSI + '4m'
NORMAL = CSI + '0m'
GREY = CSI + '0;49;90m'
GREEN = CSI + '0;49;92m'
RED = CSI + '0;49;91m'
PURPLE = '0;49;95m'
BLUE = CSI + '0;49;94m'
MAGENTA = '0;49;96m'
YELLOW = CSI + '0;49;93m'

VENDOR_COLORS = {
    'Yealink': GREEN,
    'Cisco': MAGENTA,
    'Linksys': BLUE,
    'NEC': PURPLE,
    'LG': RED,
    'Gigaset': YELLOW,
}

def asterisk_rx(cmd):
    p = subprocess.Popen(["/usr/sbin/asterisk", "-rx", cmd], stdout=subprocess.PIPE)
    lines = []
    for ln in p.stdout:
        lines.append(ln.decode('utf-8'))
    return lines


def ext_command(cmd, args):
    p = subprocess.Popen([cmd, args], stdout=subprocess.PIPE)
    lines = []
    for ln in p.stdout:
        lines.append(ln.decode('utf-8'))

    return lines


def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


class Peer:
    def __init__(self, ext, ip=None, mac=None, name=None, model=None,
                 context=None, is_registered=False, busy_level=0, clid=None,
                 did=None, pickup=None, queue=None):
        self.ext = ext
        self.ip = ip
        self.mac = mac
        self.name = name
        self.model = model
        self.context = context
        self.is_registered = is_registered
        self.busy_level = busy_level
        self.clid = clid
        self.did = did
        self.pickup = pickup
        self.queue = queue

    @property
    def vendor(self):
        vendor = None
        if 'Yealink' in self.model:
            vendor = 'Yealink'
        elif 'Cisco' in self.model:
            vendor = 'Cisco'
        elif 'Linksys' in self.model:
            vendor = 'Linksys'
        elif 'NEC' in self.model:
            vendor = 'NEC'
        elif 'LG' in self.model:
            vendor = 'LG'
        elif re.compile("C[1-9][0-9][0-9]*").match(self.model):
            vendor = 'Gigaset'

        return vendor

    def display(self, vendor_highlight=False, export_level=0):
        display = ''
        color = NORMAL
        if not self.is_registered:
            color = GREY
        elif vendor_highlight:
            vendor_color = VENDOR_COLORS.get(self.vendor or '')
            if vendor_color:
                color = vendor_color
        else:
            if self.busy_level == 1:
                color = YELLOW
            elif self.busy_level == 2:
                color = GREEN

        if export_level < 1:
            # TODO display extra columns
            display = '%s %-10s %-20s %-20s %-25s %-30s %-20s %s' % \
                      (color, self.ext, self.ip, self.mac, self.name,
                       self.model, self.context, NORMAL)
        elif export_level == 1:
            display = '%s;%s;%s;%s;%s;%s' % (self.ext, self.ip, self.mac,
                                             self.name, self.model,
                                             self.context)
        elif export_level > 1:
            display = '%s;%s;%s;%s;%s;%s;%d;%d;%s;%s;%s;%s' % \
                      (self.ext, self.ip, self.mac, self.name, self.model,
                       self.context, 1 if self.is_registered else 0,
                       self.busy_level, self.clid, self.did, self.pickup,
                       self.queue)

        return display


def get_peer_info(show_clids=False, show_dids=False,
                  show_pickup_groups=True, show_queues=False):
    extlist = []
    channeltemp = []
    channels = []
    astdb_cidnames = []
    astdb_outboundcids = []
    dialplan_dids = []
    direct_dids = {}
    ext_ip_dict = {}
    queues = {}
    is_arp = False

    initpeers = asterisk_rx("sip show peers")
    if initpeers:
        initpeers = initpeers[2:]

    showpeers = initpeers

    for line in showpeers:
        line = line.split()
        ext = line[0].split("/")[0]
        ip = line[1]
        ext_ip_dict[ext] = ip

    #Getting arp table
    try:
        maclist = ext_command("arp", "-an")
        is_arp = True
    except OSError:
        maclist = ext_command("ip", "n")

    #Getting list of dhcpd leases
    if os.path.exists("/var/lib/dhcpd/dhcpd.leases"):
        leases = ' '.join(ext_command("cat", "/var/lib/dhcpd/dhcpd.leases")).split("}")
    else:
        leases = ""

    # Getting asterisk globals if globals file exists
    if show_clids or show_dids:
        globals = asterisk_rx("dialplan show globals")
    else:
        globals = ""

    if show_queues:
        queue_parts = ' '.join(asterisk_rx("queue show")).split('Callers')
        for part in queue_parts:
            group = None
            members = []
            for line in part.splitlines():
                if 'strategy' in line:
                    if line.split()[0] != ':':
                        group = line.split()[0]
                    else:
                        group = None
                if 'SIP/' in line:
                    members.append(line.split('/')[1].split()[0])
            if group:
                queues[group] = members

    #Getting active channels
    showchannels = asterisk_rx("core show channels concise")

    for channel in showchannels:
        try:
            channeltemp = []
            channeltemp.append(channel.split("!")[0])
            channeltemp.append(channel.split("!")[4])
        except IndexError:
            pass

        channeltemp = "!".join(channeltemp)
        channels.append(channeltemp)

    channels = "#".join(channels)

    numexts = len(showpeers)

    #Getting peer information via subproccess
    peers_info_dict = {}
    peer_results = {}

    for ext in ext_ip_dict.keys():
        peer_results[ext] = subprocess.Popen(['/usr/sbin/asterisk -rx "sip show peer ' + ext + '"'], shell=True, stdout=subprocess.PIPE)
        peers_info_dict[ext] = ""

    while True:
        not_done = False

        for extension, result in peer_results.items():
            if result.poll == None:
                not_done = True
            else:
                peers_info_dict[extension] = result.stdout.read().decode('utf-8').splitlines()
        if not not_done:
            break

    #Iterating over list of peers
    for ext in sorted(ext_ip_dict):

        ip = ext_ip_dict[ext]
        mac = "(N/A)"
        model = "(N/A)"
        clid = "(N/A)"
        did = "(N/A)"
        pickup = "(N/A)"
        queue = ""
        is_registered = False
        busy_level = 0
        context = ''
        name = ''
        num = ext

        #Protection against older versions of asterisk or messages popping up
        if ip == "sip" or ext == "Privilege":
            numexts -= 1
            continue

        #Getting mac address from arp table
        if is_arp:
            for macline in maclist:
                if "(" + ip + ")" in macline:
                    mac = macline.split()
                    mac = mac[3]
                    mac = re.sub('[:]', '', mac)
                    mac = mac.lower()
        else:
            for macline in maclist:
                if ip + " " in macline:
                    mac = macline.split()
                    mac = mac[4]
                    mac = re.sub('[:]', '', mac)
                    mac = mac.lower()

        #If mac not found in arp table, trying to find it in dhcpd.leases file
        if mac == "(N/A)" or not mac:
            for lease in leases:
                if ip in lease:
                    lease = lease.splitlines()
                    for line in lease:
                        if "hardware ethernet" in line:
                            mac = line.split()[2]
                            mac = re.sub('[:]', '', mac)
                            mac = re.sub('[;]', '', mac)
                            mac = mac.lower()

        #Getting further peer information
        peerinfo = peers_info_dict[ext]    #asterisk_rx("sip show peer " + ext).splitlines()

        for line in peerinfo:
            if "Callerid" in line:
                name = line.split("\"")[1]
                num = line.split('<')[1].split('>')[0]

                # Patch for freePBX callerid name
                if name == "device":
                    try:
                        # Getting asterisk database
                        if len(astdb_cidnames) == 0:
                            asterisk_database = asterisk_rx('database show')
                            for line in asterisk_database:
                                if "cidname" in line:
                                    astdb_cidnames.append(line)
                                if "outboundcid" in line:
                                    astdb_outboundcids.append(line)
                                for dbline in astdb_cidnames:
                                    if "AMPUSER/"+ ext +"/cidname" in dbline:
                                        name = dbline.split(":")[1]
                                        name = " ".join(name.split())
                                if show_clids:
                                    for dbline in astdb_outboundcids:
                                        if "AMPUSER/"+ ext +"/outboundcid" in dbline:
                                            clid = dbline.split(":")[1].strip()
                    except IndexError:
                        pass

                    if show_dids:
                        try:
                            if len(dialplan_dids) == 0:
                                dialplan_dids = asterisk_rx('dialplan show ext-did-0002')
                                for dialplan_line in dialplan_dids:
                                    if '=>' in dialplan_line:
                                        found_did = dialplan_line.split("'")[1]
                                        direct_dids[found_did] = ''

                                dialplan_results = {}
                                dialplan_exts = {}
                                for direct_did in direct_dids.keys():
                                    dialplan_results[direct_did] = subprocess.Popen(['/usr/sbin/asterisk -rx "dialplan show ' \
                                                                   + direct_did + '@ext-did-0002"'], shell=True, stdout=subprocess.PIPE)
                                    dialplan_exts[direct_did] = ''

                                while True:
                                    not_done = False
                                    for direct_did, result in dialplan_results.items():
                                        if result.poll == None:
                                            not_done = True
                                        else:
                                            dialplan_exts[direct_did] = str(result.stdout.read()).splitlines()
                                    if not not_done:
                                        break

                                for direct_did, extension in direct_dids.items():
                                    for did_line in dialplan_exts[direct_did]:
                                        if 'from-did-direct' in did_line:
                                            try:
                                                direct_dids[direct_did] = did_line.split(',')[1]
                                            except IndexError:
                                                try:
                                                    direct_dids[direct_did] = did_line.split('|')[1]
                                                except IndexError:
                                                    pass
                            for direct_did, extension in direct_dids.items():
                                if extension == ext:
                                    did = direct_did
                        except KeyError:
                            pass

            if "Useragent" in line:
                model = line.split(":")[1].strip()

            if "Context" in line:
                context = line.split(":")[1].strip()

            if "Pickupgroup" in line and show_pickup_groups:
                pickup = line.split(":")[1].strip()

            #Getting peer status
            if "Status" in line:
                if "OK" in line and mac != "<incomplete>" and ip != "(Unspecified)":
                    is_registered = True
                elif "UNKNOWN"  or "Unmonitored" in line:
                    if ip == "(Unspecified)" or mac == "<incomplete>":
                        is_registered = False
                    else:
                        is_registered = True
                else:
                    is_registered = False
                if "UNREACHABLE" in line:
                    is_registered = False

            if "Reg. Contact" in line:
                if is_registered == False and ip == "(Unspecified)":
                    try:
                        ip = line.split("@")[1]
                        ip = ip.split(":")[0]
                    except IndexError:
                        pass

            if show_clids and 'CLID' in line and ' = ' in line:
                clid = line.split()[-1]

        #Checking if peer is busy
        extchannel = "SIP/" + ext

        if extchannel in channels:
            channeltemp = channels.split("#")

            for channel in channeltemp:
                if extchannel in channel:
                    if channel.split("!")[1] == "Up":
                        busy_level = 2
                        break
                    else:
                        busy_level = 1
        else:
            busy_level = 0
        # Checking for globals
        if (show_clids or show_dids) and globals != "":
            for line in globals:
                if not line.startswith(';'):
                    if clid == '(N/A)' and 'CLID' + num +'=' in line:
                        clid = line.split('=')[1].strip()
                    if not is_number(ext[0:1]) and clid == '(N/A)' and 'CLID' + ext[1:] +'=' in line:
                        clid = line.split('=')[1].strip()
                    if 'DID' in line and ('=' + ext in line or '=' + num in line):
                        did = line.split('=')[0].replace('DID','').strip()

        # Checking for queues
        for queue_name, members in queues.items():
            if ext in members:
                queue += queue_name + ' '

        peer = Peer(ext=ext, ip=ip, mac=mac, name=name, model=model,
                    context=context, is_registered=is_registered,
                    busy_level=busy_level, clid=clid, did=did, pickup=pickup,
                    queue=queue)

        if peer.ext not in [p.ext for p in extlist]:
            extlist.append(peer)

    return extlist


if __name__ == '__main__':
    patterns = []
    vendor_highlight = False
    show_clids = False
    show_dids = False
    show_queues = False
    show_pickup_groups = False
    export_level = 0

    for index, arg in enumerate(sys.argv):
        if index == 0:
            continue
        if arg.startswith("-"):
            if "v" in arg:
                vendor_highlight = True
            if "c" in arg:
                show_clids = True
            if "d" in arg:
                show_dids = True
            if "p" in arg:
                show_pickup_groups = True
            if "q" in arg:
                show_queues = True
            if "e" in arg and export_level < 1:
                export_level = 1
            if "m" in arg:
                export_level = 2
            if "h" in arg or "--help" in arg and len(sys.argv == 1):
                print "Extsearch " + SCR_VERSION
                print "Usage: extsearch [option] [pattern] [pattern] ..."
                print "	Lists all sip peers with following data: Extension number, IP address, MAC address, Extension name, Vendor and Context"
                print "	Inactive extensions are dimmed, busy extensions are highlighted in yellow."
                print "	Filters according to [pattern(s)]."
                print "Options:"
                print "	-v	Vendor highlight view - highlights extensions according to vendor."
                print "	-c	CLID option - adds CallerID column to output (if available)."
                print "	-d	DID option - adds Direct Inward Dial column to output (if available)."
                print "	-p	PICKUP group option - adds Pickup group column (if available)."
                print "	-q	QUEUE group option - adds Queue column (if available)."
                print "	-e	Export mode - exports registered extension data (extension, IP address, MAC address and name) in form of a CSV."
                print "	-m	Machine Export mode - exports all available extension data in form of a CSV."
                raise SystemExit
        else:
            patterns.append(arg)

    peers = get_peer_info(show_clids=show_clids, show_dids=show_dids,
                          show_pickup_groups=show_pickup_groups,
                          show_queues=show_queues)

    for peer in peers:
        print(peer.display(vendor_highlight=vendor_highlight,
                           export_level=export_level))

    num_peers = len(peers)
    num_registered = sum(1 for p in peers if p.is_registered)
    num_unregistered = sum(1 for p in peers if not p.is_registered)
    num_busy = sum(1 for p in peers if p.busy_level > 0)

    print ''
    print 'Extensions: %d - registered: %d, not registered: %d, busy: %d' %\
              (num_peers, num_registered, num_unregistered, num_busy)
    print ''

