from datetime import datetime
import tldextract
import subprocess
import ipaddress 


def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        #print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        #print("IP address {} is not valid".format(address))
        return False


def parse_domain(target):
    return tldextract.extract(target).fqdn
    #print(self.target)


def start(target):
    t = target
    if validate_ip_address(target) == False:
        t = parse_domain(target)
        if t == '':
            print('could not parse input')
            return None, 255

    current_time = int(datetime.now().timestamp())
    fn = '/tmp/' + t + str(current_time) + '.json'
    rt = subprocess.run(['testssl', '-q', '-P', '-p', '-e', '--jsonfile-pretty', fn, t], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    return fn, rt
