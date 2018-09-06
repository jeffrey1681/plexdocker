""" This is a simple python script for updating the
    DNS Custom Records in Dreamhost Nameservers using
    Dreamhost API commands.
    
    Provided under the MIT License (MIT). See LICENSE for details.

    """

import sys
# import syslog
import http.client
import re
import ssl
import uuid
import logging
import socket

# Set the logging level.
logging.basicConfig(level=logging.ERROR)


class DNS:
    def __init__(self, API_Key, domain, CheckIPV6):
        self.API_Key = API_Key
        self.domain = domain
        self.CHECKIPV6 = CheckIPV6

        self.API_url = "api.dreamhost.com"
        self.IP_Addr = ""
        self.IPv6_Addr = ""
        self.DNS_IP = "NO_RECORD"
        self.DNS_IPV6 = "NO_RECORD"

    def get_dns_records(self):
        response = self.speak_to_DH("dns-list_records")
        relevant_records = []
        for line in response.splitlines():
            if self.domain in line:
                relevant_records.append(line)
        logging.debug('All relevant DNS Records for %s: \n %s', self.domain, relevant_records)
        return relevant_records

    def speak_to_DH(self, command):
        """str->str"""
        logging.debug('Will try to speak to Dreamhost, here is what I will tell: %s', command)
        substring = self.make_url_string(command)
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        conn = http.client.HTTPSConnection(self.API_url, 443, context=context)
        conn.request("GET", substring)
        body = conn.getresponse().read().decode('UTF-8')
        logging.debug('Here is what Dreamhost responded: %s', body)
        return body

    def make_url_string(self, command):
        """"str->str"""
        url = "/?key=" + self.API_Key + "&cmd=" + command + "&unique_id=" + self.rand_uuid()
        return url

    def rand_uuid(self):
        unique_id = str(uuid.uuid4())
        return unique_id

    def get_dns_ip(self, records):
        """str->str"""
        for line in records:
            values = line.expandtabs().split()
            if values[2] == self.domain:
                if values[3] == "AAAA":    # IPv6
                    logging.info('Current %s record for %s is: %s', "ipv6", self.domain,  values[-2])
                    self.DNS_IPV6 = values[-2]
                elif values[3] == "A":      # IPv4
                    self.DNS_IP = values[-2]

        if self.DNS_IPV6 == "" and self.DNS_IP == "":
            logging.warning('No %s record found for %s', self.domain)

    def get_host_IP_Address(self, protocol='ip'):
        try:
            conn = http.client.HTTPConnection('checkipv6.dyndns.com')
            conn.request("GET", "/index.html")
            body = self.cleanhtml(conn.getresponse().read().decode("UTF-8"))
            IP_Addr_list = body.rsplit()
            self.IPv6_Addr = IP_Addr_list[-1]
        except socket.gaierror:
            logging.error("IPv6 Address check failed")

        try:
            conn = http.client.HTTPConnection('checkip.dyndns.com')
            conn.request("GET", "/index.html")
            body = self.cleanhtml(conn.getresponse().read().decode("UTF-8"))
            IP_Addr_list = body.rsplit()
            self.IP_Addr = IP_Addr_list[-1]
        except socket.gaierror:
            logging.error("IPv4 Address check failed")

    def cleanhtml(self, raw_html):
        cleanr = re.compile('<.*?>')
        cleantext = re.sub(cleanr, '', raw_html)
        return cleantext


#     def update_dns_record(self, protocol='ip'):
#         if protocol == 'ipv6':
#             dns_check = self.DNS_IPV6
#         else:
#             dns_check = self.DNS_IP
#         logging.debug('dns_check: %s', dns_check)
#         if dns_check == "NO_RECORD":
#             add_dns_record(protocol)
#         else:
#             del_dns_record(protocol)
#             add_dns_record(protocol)
#
#
# def del_dns_record(protocol='ip'):
#     global DNS_IPV6
#     global DNS_IP
#     record = ""
#     if protocol == 'ipv6':
#         rec_type = 'AAAA'
#         record = DNS_IPV6
#         print(record)
#         print(DNS_IPV6)
#     else:
#         rec_type = 'A'
#         record = DNS_IP
#         print(record)
#         print(DNS_IP)
#     logging.info('The current %s record is: %s', protocol, record)
#     if record == '':
#         logging.error("Can't delete record, value passed is empty")
#         sys.exit("Weird")
#     command = "dns-remove_record&record=" + domain + "&type=" + rec_type + "&value=" + record
#     response = speak_to_DH(command)
#     if 'error' in response:
#         logging.error('Error while deleting %s record: \n %s', protocol, response)
#     logging.debug('Tried to del %s record and here is what Dreamhost responded: \n %s', protocol, response)
#
# def add_dns_record(protocol='ip'):
#     global IPv6_Addr
#     global IP_Addr
#     Address = ""
#     if protocol == "ipv6":
#         rec_type = "AAAA"
#         Address = IPv6_Addr
#     else:
#         rec_type = "A"
#         Address = IP_Addr
#     logging.info('Our current %s address is: %s', protocol, Address)
#     command = "dns-add_record&record=" + domain + "&type=" + rec_type + "&value=" + Address
#     response = speak_to_DH(command)
#     if 'error' in response:
#         logging.error('Error while adding %s record: \n %s', protocol, response)
#     logging.debug('Tried to add %s record and Dreamhost responded with: \n %s', protocol, response)



def main():
    # Python version check
    if sys.version_info.major < 3:
        msg = 'Python 3 required. I refuse to run!'
        syslog.syslog(syslog.LOG_ERR, msg)
        sys.exit(msg)

    # Domain can be the root or a subdomain.
    # example.com or sub.exmple.com
    API_Key = "QPPJKVPZEZR6SWA4"
    domain = "plex.jeffreyfogel.com"
    # Set this to True if you want to update IPv6 record.
    CheckIPV6 = False

    dns = DNS(API_Key, domain, CheckIPV6)

    if dns.API_Key == '' or dns.domain == '':
        msg = 'API_Key and/or domain empty. Edit dreampy_dns.py and try again.'
        # syslog.syslog(syslog.LOG_ERR, msg)
        sys.exit(msg)

    current_records = dns.get_dns_records()

    dns.get_dns_ip(current_records)
    logging.debug('DNS_IP: %s', dns.DNS_IP)

    dns.get_host_IP_Address()
    logging.debug('IP_Addr: %s', dns.IP_Addr)

    # if dns.DNS_IP != dns.IP_Addr:
    #     logging.info('Address different, will try to update.')
    #     update_dns_record()
    # else:
    #     logging.info('IP Record up-to-date.')
    #
    # if CHECKIPV6:
    #     dns.get_dns_ip(current_records, "ipv6")
    #     dns.get_host_IP_Address('ipv6')
    #     if dns.DNS_IPV6 != dns.IPv6_Addr:
    #             update_dns_record('ipv6')
    #     else:
    #         logging.info('IPv6 Record up-to-date.')


main()
