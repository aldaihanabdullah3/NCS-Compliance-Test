import json
import ncs_tls
import testssl

def main1(target_file):
    f = open(target_file)
    data = json.load(f)
    result = ncs_tls.ncs_tls(data)    
    print(result)
    f.close()


def main2(target):
    ts = testssl.testssl(target)
    f = open(ts.filename)
    data = json.load(f)
    result = ncs_tls.ncs_tls(data)    
    print(result)
    f.close()

if __name__== "__main__" :
    main1('logs/data.json')
    main1('logs/data2.json')
    main1('logs/aldaihan.info1657530108.json')
    main1('logs/splonline.com.sa1657529853.json')
    #main2('webmail.cloud.moi.gov.sa')
    #main2('splonline.com.sa')
    #main2('aldaihan.info')  