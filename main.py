import json
from bcolors import bcolors
import ncs_tls
import testssl

def main1(target_file):
    f = open(target_file)
    data = json.load(f)
    result = ncs_tls.ncs_tls(data)    
    print(result)
    f.close()


def main2(target):
    filename, rt = testssl.start(target)
    if rt != 0:
        print("General Error!")
        return
        
    f = open(filename)
    data = json.load(f)
    result = ncs_tls.ncs_tls(data)    
    print(result)
    f.close()

if __name__== "__main__" :
    try:
        print(bcolors.OKCYAN + "Welcome to NCS compliance test for TLS" + bcolors.ENDC)
        while True:
            print(bcolors.OKBLUE + "Please enter the domain or IP address of the target" + bcolors.ENDC)
            target = input('Enter test target: ')
            print('Please wait, this will take some time')
            main2(target)
    except Exception as e:
        print("Somthing wrong happend, this incident have been reported and will be fixed ASAP!")
    #main1('logs/data.json')
    #main1('logs/data2.json')
    #main1('logs/aldaihan.info1657530108.json')
    #main1('logs/splonline.com.sa1657529853.json')
    #main2('webmail.cloud.moi.gov.sa')
    #main2('splonline.com.sa')
    #main2('aldaihan.info')  