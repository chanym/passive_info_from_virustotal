#!/usr/bin/python

import sys, requests, re, time

def printinfo(res):
    print("\n")
    if res['response_code'] == 1:  
        fields = res.keys()
        special = ['detected_downloaded_samples', 'undetected_downloaded_samples', 'undetected_referrer_samples', \
                'domain_siblings', 'Webutation domain info', 'resolutions', 'categories', 'subdomains', \
                'detected_referrer_samples', 'detected_urls', 'detected_communicating_samples', \
                'undetected_communicating_samples']
        
        if 'detected_downloaded_samples' in fields:
            print('\ndetected Downloaded Samples')
            print(len('detected Downloaded Samples') * '=')
            for i in res['detected_downloaded_samples']:
                print("Date: {0}\nSHA256: {1}\n".format(i['date'], i['sha256']))

        if 'undetected_downloaded_samples' in fields:
            print('\nUndetected Downloaded Samples')
            print(len('Undetected Downloaded Samples') * '=')
            for i in res['undetected_downloaded_samples']:
                print("Date: {0}\nSHA256: {1}\n".format(i['date'], i['sha256']))
            
        if 'undetected_referrer_samples' in fields:
            print('\nUndetected Referrer Samples - SHA256')
            print(len('Undetected Referrer Samples - SHA256') * '=')
            for i in res['undetected_referrer_samples']:
                print (i['sha256'])

        if 'detected_referrer_samples' in fields:
            print('\nDetected Referrer Samples - SHA256')
            print(len('Detected Referrer Samples - SHA256') * '=')
            for i in res['detected_referrer_samples']:
                print (i['sha256'])

        if 'detected_urls' in fields:
            print('\nDetected URLS')
            print(len('Detected URLS') * '=')
            for i in res['detected_urls']:
                print ("url: {0}\npositives: {1}\nscan date: {2}\n".format(i['url'], i['positives'], i['scan_date']))

        if 'domain_siblings' in fields:
            print('\nDomain Siblings')
            print(len('Domain Siblings') * '=')
            for i in res['domain_siblings']:
                print(i)

        if 'Webutation domain info' in fields:
            print('\nWebutation domain info')
            print(len('Webutation domain info') * '=')
            print("Verdict: {0}\nAdult Content: {1}\nSafety Score: {2}\n".format(res['Webutation domain info']['Verdict'], \
                    res['Webutation domain info']['Adult content'], \
                    res['Webutation domain info']['Safety score']))

        if 'resolutions' in fields:
            print('\nResolutions')
            print(len('resolutions') * '=')
            for i in res['resolutions']:
                iphost = i.keys()
                if 'ip_address' in iphost:
                    print("Last Resolved: {0}\nip address: {1}\n".format(i['last_resolved'], i['ip_address']))
                if 'hostname' in iphost:
                    print("Last Resolved: {0}\nhostname: {1}\n".format(i['last_resolved'], i['hostname']))

        if 'detected_communicating_samples' in fields:
            print('\nDetected Communicating Samples')
            print(len('Detected Communicating Samples') * '=')
            for i in res['detected_communicating_samples']:
                print("Date: {0}\nPositives: {1}\nSHA256: {2}\n".format(i['date'], i['positives'], i['sha256']))

        if 'undetected_communicating_samples' in fields:
            print('\nUndetected Communicating Samples')
            print(len('Undetected Communicating Samples') * '=')
            for i in res['undetected_communicating_samples']:
                print("Date: {0}\nPositives: {1}\nSHA256: {2}\n".format(i['date'], i['positives'], i['sha256']))
        
        
        if 'categories' in fields:
            print('\nCategories')
            print(len('categories') * '=')
            for i in res['categories']:
                print(i)

        if 'subdomains' in fields:
            print('\nSubdomains')
            print(len('subdomains') * '=')
            for i in res['subdomains']:
                print(i)

        for i in fields:
            if i not in special:
                print('\n{0}: {1}'.format(i, res[i]))

    else:
        print("Currently no Domain data found...\n")
            
def vt(data_list):
    """Get passive info from virustotal - 
    Usage: passiveinfo.vt(['<domain or IP>'])
    example passviveinfo.vt(['www.github.com', '8.8.8.8'])"""

    count = 0
    num = 0
    key = '' #api key needs to be key here 

    while num < len(data_list):
        if count < 4:
            if re.search(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', data_list[num]):
                payload = {"ip": data_list[num], 'apikey': key}
                print("\n\n---------- {0} ----------".format(data_list[num]))
                page = requests.get('http://www.virustotal.com/vtapi/v2/ip-address/report', params=payload)
                result = page.json()
                printinfo(result)
                count += 1
                num += 1
            else:
                payload = {'domain': data_list[num], 'apikey': key}
                print("\n\n---------- {0} ----------".format(data_list[num]))
                page = requests.get('http://www.virustotal.com/vtapi/v2/domain/report', params=payload)
                result = page.json()
                printinfo(result)
                count += 1
                num += 1
        else:
            time.sleep(0)
            count = 0

def main():
    if len(sys.argv) != 2:
	print ("""\nUsage - ./passiveDns.py <file containing ip>
File must contain one ip or one url on each line\n""")    
        quit()

    else:
        print ("""\n***	Passive dns from virustotal using own api key		***
***	This script will query against virustotal 4 times per minute	***
***	as I am using a public key.			***\n\n""")

        data = []
        content = open(sys.argv[1], "r")
        for line in content.readlines():
            data.append(line.strip())

        content.close()
        vt(data)


if __name__ == "__main__":
    main()
