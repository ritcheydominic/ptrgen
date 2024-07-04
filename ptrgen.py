import argparse
import iptools
import socket
import sys

def getIpv4ArpaDomainName(addr):
    addr = iptools.ipv4.ip2long(addr)
    bytes = [-1] * 4
    for i in range(len(bytes)):
        bytes[i] = addr // (256 ** (3 - i)) % 256
    return "{}.{}.{}.{}.in-addr.arpa.".format(bytes[3], bytes[2], bytes[1], bytes[0])

def getIpv6ArpaDomainName(addr):
    addr = iptools.ipv6.ip2long(addr)
    nibbles = [-1] * 32
    for i in range(len(nibbles)):
        nibbles[i] = (addr // (16 ** (31 - i))) % 16
    
    domainName = ""
    for i in range(len(nibbles)):
        domainName += hex(nibbles[31 - i])[2:] + "."
    return domainName + "ip6.arpa."

def generateIpv4PtrRecord(addr, zone="", ttl="", hostname=""):
    if iptools.ipv4.validate_ip(addr):
        arpaDomainName = truncatedArpaDomainName = getIpv4ArpaDomainName(addr)
        if zone != "":
            truncatedArpaDomainName = arpaDomainName.replace(".{}".format(zone), "")

        if hostname == "":
            return "{} {} IN PTR {}".format(truncatedArpaDomainName, ttl, arpaDomainName)
        else:
            return "{} {} IN PTR {}".format(truncatedArpaDomainName, ttl, hostname)
    else:
        sys.exit("Error: Invalid IPv4 address/range encountered ({})".format(addr))

def generateIpv6PtrRecord(addr, zone="", ttl="", hostname=""):
    if iptools.ipv6.validate_ip(addr):
        arpaDomainName = truncatedArpaDomainName = getIpv6ArpaDomainName(addr)
        if zone != "":
            truncatedArpaDomainName = arpaDomainName.replace(".{}".format(zone), "")

        if hostname == "":
            return "{} {} IN PTR {}".format(truncatedArpaDomainName, ttl, arpaDomainName)
        else:
            return "{} {} IN PTR {}".format(truncatedArpaDomainName, ttl, hostname)
    else:
        sys.exit("Error: Invalid IPv6 address/range encountered ({})".format(addr))

def getIpsFromHostname(host):
    return { str(i[4][0]) for i in socket.getaddrinfo(host, 80) }

def printPtrRecords(query, ipv4_zone="", ipv6_zone="", ttl=""):
    if iptools.ipv6.validate_cidr(query) == True:
        query = iptools.IpRangeList(query)
        for addr in query:
            print(generateIpv6PtrRecord(addr, zone=ipv6_zone, ttl=ttl))
    elif iptools.ipv6.validate_ip(query) == True:
        print(generateIpv6PtrRecord(query, zone=ipv6_zone, ttl=ttl))
    elif iptools.ipv4.validate_cidr(query) == True:
        query = iptools.IpRangeList(query)
        for addr in query:
            print(generateIpv4PtrRecord(addr, zone=ipv4_zone, ttl=ttl))
    elif iptools.ipv4.validate_ip(query) == True:
        print(generateIpv4PtrRecord(query, zone=ipv4_zone, ttl=ttl))
    else:
        try:
            ips = getIpsFromHostname(query)
            if not query.endswith("."):
                query += "."

            for ip in ips:
                if iptools.ipv6.validate_ip(ip):
                    print(generateIpv6PtrRecord(ip, zone=ipv6_zone, ttl=ttl, hostname=query))
                elif iptools.ipv4.validate_ip(ip):
                    print(generateIpv4PtrRecord(ip, zone=ipv4_zone, ttl=ttl, hostname=query))
                else:
                    sys.exit("Error: Invalid IP address/range encountered ({})".format(ip))
        except:
            sys.exit("Error: Invalid query")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generate PTR records for IP addresses')
    parser.add_argument('objects', metavar='O', type=str, nargs='+', help='IP address, subnet or domain name to create PTR record for')
    parser.add_argument('-z4', type=str, nargs=1, default=[''], dest='ipv4_zone', help='DNS zone for IPv4 addresses')
    parser.add_argument('-z6', type=str, nargs=1, default=[''], dest='ipv6_zone', help='DNS zone for IPv6 addresses')
    parser.add_argument('-ttl', type=str, nargs=1, default=[''], dest='ttl', help='TTL value for PTR records')

    args = parser.parse_args()

    for obj in args.objects:
        printPtrRecords(obj, ipv4_zone=args.ipv4_zone[0], ipv6_zone=args.ipv6_zone[0], ttl=args.ttl[0])