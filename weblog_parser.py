# Python Version - 3.10.0

import argparse
import re
import logging
import ipaddress


# Logging module is used tracking events that happen when program executes.
logging.basicConfig(level=logging.INFO)

# You can comment the previous logging.basicConfig and uncomment the below line if you would like to write the
# output into a new logfile
# logging.basicConfig(filename='results.log', level=logging.INFO, format='%(message)s')


def validate_and_search(ip_address, input_file):
    """ This function validates the input IP address with regular expression pattern before function call of
        parse_logfile/parse_logfile_cidr function.

        Args:
            :param ip_address: IP address is validates using regular expressing pattern
            :param input_file: Input logfile passed as param to function call

            ip_pattern : Regular expression pattern for IPv4 address without CIDR network
            ip_pattern_cidr : Regular expression pattern for IPv4 address with CIDR network
    """
    try:
        ip_pattern = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}'
                                '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$')

        ip_pattern_cidr = re.compile(r'^(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){3}'
                                     '([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]?)'
                                     '(/([0-9]|1[0-9]|2[0-9]|3[0-2]))$')

        if re.search(ip_pattern, ip_address):
            parse_logfile(ip_address, input_file)

        elif re.search(ip_pattern_cidr, ip_address):
            parse_logfile_cidr(ip_address, input_file)

        else:
            raise Exception("Invalid IP address format")
    except Exception as msg:
        logging.error(__name__ + ": IP Address validation: " + str(msg))
        return None


def parse_logfile(ip_address, input_file):
    """ This function return all IP address that corresponds to given source IP address.

        Args:
            :param ip_address: IP address without CIDR to be searched in the log file
            :param input_file: Input logfile

    """
    with open(input_file, 'r') as file:
        file_contents = file.readlines()
        for each_log in file_contents:
            if re.search(ip_address + r'(([ -]{2})+([ \[.*\]])+([ \"[A-Z]).)', each_log):
                logging.info("Match found: {}".format(each_log))
    file.close()


def parse_logfile_cidr(ip_address, input_file):
    """ This function return all IP address that corresponds to given source IP address.

        Args:
            :param ip_address: IP address with CIDR to be searched in the log file
            :param input_file: Input logfile

    """
    list_of_ip = []
    ip_range = ipaddress.ip_network(ip_address, False)
    for ip in ip_range.hosts():
        ip_string_format = ip.__str__()
        list_of_ip.append(ip_string_format)

    with open(input_file, 'r') as file:
        file_contents = file.readlines()
        for each_ip in list_of_ip:
            for each_log in file_contents:
                if re.search(each_ip + r'(([ -]{2})+([ \[.*\]])+([ \"[A-Z]).)', each_log):
                    logging.info("Match found: {}".format(each_log))
    file.close()


# The main function will parse arguments via the parser variable.  These
# arguments will be defined by the user on the console.  This will pass
# the ip address as argument by the user to parse along with the filename
# of the the logfile user wants to use, and also provide help text if the
# user does not correctly pass the arguments.

def main():
    parser = argparse.ArgumentParser(description='Run Weblog Helper')
    parser.add_argument("-v", help="logging informational events", action="store_true")
    parser.add_argument("-vv", help="detailed logging for events", action="store_true")
    parser.add_argument("-ip", "--ip", required=True, metavar="IP_ADDRESS", type=str, help="provide an IP address")
    parser.add_argument("-i", "--input", required=True, metavar="INPUT_FILE", type=str, help="provide a log file")

    args = parser.parse_args()

    ip_address = args.ip
    input_file = args.input
    validate_and_search(ip_address, input_file)


if __name__ == '__main__':
    main()

