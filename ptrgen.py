import iptools
import socket
import sys

def getIpv4ArpaDomainName(addr):
    addr = iptools.ipv4.ip2long(addr)
    bytes = [-1] * 4
    for i in range(len(bytes)):
        bytes[i] = (int) (addr / (256 ** (3 - i))) % 256
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

def generateIpv4PtrRecord(addr, ttl="", hostname=""):
    if iptools.ipv4.validate_ip(addr):
        arpaDomainName = getIpv4ArpaDomainName(addr)

        if hostname == "":
            return "{} {} IN PTR {}".format(arpaDomainName, ttl, arpaDomainName)
        else:
            return "{} {} IN PTR {}".format(arpaDomainName, ttl, hostname)
    else:
        sys.exit("Error: Invalid IP address/range encountered")

def generateIpv6PtrRecord(addr, ttl="", hostname=""):
    if iptools.ipv6.validate_ip(addr):
        arpaDomainName = getIpv6ArpaDomainName(addr)

        if hostname == "":
            return "{} {} IN PTR {}".format(arpaDomainName, ttl, arpaDomainName)
        else:
            return "{} {} IN PTR {}".format(arpaDomainName, ttl, hostname)
    else:
        sys.exit("Error: Invalid IP address/range encountered")

def getIpsFromHostname(host):
    return { str(i[4][0]) for i in socket.getaddrinfo(host, 80) }

def printPtrRecords(query, ttl=""):
    if iptools.ipv6.validate_cidr(query) == True:
        query = iptools.IpRangeList(query)
        for addr in query:
            print(generateIpv6PtrRecord(addr, ttl))
    elif iptools.ipv6.validate_ip(query) == True:
        print(generateIpv6PtrRecord(query, ttl))
    elif iptools.ipv4.validate_cidr(query) == True:
        query = iptools.IpRangeList(query)
        for addr in query:
            print(generateIpv4PtrRecord(addr, ttl))
    elif iptools.ipv4.validate_ip(query) == True:
        print(generateIpv4PtrRecord(query, ttl))
    else:
        try:
            ips = getIpsFromHostname(query)
            if not query.endswith("."):
                query += "."

            for ip in ips:
                if iptools.ipv6.validate_ip(ip):
                    print(generateIpv6PtrRecord(ip, ttl, hostname=query))
                elif iptools.ipv4.validate_ip(ip):
                    print(generateIpv4PtrRecord(ip, ttl, hostname=query))
                else:
                    sys.exit("Error: Invalid IP address/range encountered")
        except:
            sys.exit("Error: Invalid query")

if len(sys.argv) < 2:
    sys.exit("Error: Too few arguments")
elif len(sys.argv) == 2:
    printPtrRecords(sys.argv[1])
elif len(sys.argv) == 3:
    printPtrRecords(sys.argv[1], ttl=sys.argv[2])
else:
    sys.exit("Error: Too many arguments")