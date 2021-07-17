import iptools
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

def generateIpv4PtrRecord(addr, ttl=""):
    if iptools.ipv4.validate_ip(addr):
        arpaDomainName = getIpv4ArpaDomainName(addr)
        return "{} {} IN PTR {}".format(arpaDomainName, ttl, arpaDomainName)
    else:
        sys.exit("Error: Invalid IP address/range encountered")

def generateIpv6PtrRecord(addr, ttl=""):
    if iptools.ipv6.validate_ip(addr):
        arpaDomainName = getIpv6ArpaDomainName(addr)
        return "{} {} IN PTR {}".format(arpaDomainName, ttl, arpaDomainName)
    else:
        sys.exit("Error: Invalid IP address/range encountered")

def printPtrRecords(range, ttl=""):
    if iptools.ipv6.validate_cidr(range):
        range = iptools.IpRangeList(range)
        for addr in range:
            print(generateIpv6PtrRecord(addr, ttl))
    elif iptools.ipv6.validate_ip(range):
        print(generateIpv6PtrRecord(range, ttl))
    elif iptools.ipv4.validate_cidr(range):
        range = iptools.IpRangeList(range)
        for addr in range:
            print(generateIpv4PtrRecord(addr, ttl))
    elif iptools.ipv4.validate_ip(range):
        print(generateIpv4PtrRecord(range, ttl))
    else:
        sys.exit("Error: Invalid IP address/range encountered")

if len(sys.argv) < 2:
    sys.exit("Error: Missing arguments")
elif len(sys.argv) == 2:
    printPtrRecords(sys.argv[1])
elif len(sys.argv) == 3:
    printPtrRecords(sys.argv[1], ttl=sys.argv[2])
else:
    sys.exit("Error: Too many arguments")