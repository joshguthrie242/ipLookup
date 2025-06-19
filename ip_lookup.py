import requests
import json
import certifi
import ssl
import http.client

'''
ip_file = open("ipfile.txt", 'r')
results = open('results.csv', 'w')
'''

#ip = input("What is the IP address? ")
ip = '172.56.164.98'
# results.write('IP Address,ISP,Country,City,State,Proxy,VPN,Spam,Blacklist,Malware,Malware Activity,Notes')

#for ip in ip_file:
isp = ''
country = ''
city = ''
state = ''
proxy = ''
vpn = ''
spam = ''
blocklist = ''
malware = ''
malware_activity = ''
notes = ''

print(f"Using CA bundle: {certifi.where()}")

# Test a request to Google to check SSL globally
try:
    google_req = requests.get('https://www.google.com', verify=False)
    print(f"Google request status: {google_req.status_code}")
except requests.exceptions.SSLError as e:
    print(f"SSL error with Google: {e}")
except Exception as e:
    print(f"Other error with Google: {e}")

# IP Location
try:
    req = requests.get('https://api.iplocation.net/?ip=' + ip, verify=certifi.where())
    response = json.loads(req.text)
    print(response)
    if (response['response_code'] == '200'):
        isp = response['isp']
        country = response['country_name']
    else:
        print('For IP address ' + ip + ' IP Location failed to retrieve any information.\n')
except requests.exceptions.SSLError as e:
    print(f"SSL error with api.iplocation.net: {e}")
except Exception as e:
    print(f"Other error with api.iplocation.net: {e}")

# DNSlytics
# Free API access limited to 2500 API requests per day
'''
api_key = ''
# req = requests.get('https://api.dnslytics.net/v1/ipinfo/' + ip + '?apikey=' + api_key)
req = requests.get('https://freeapi.dnslytics.net/v1/ip2asn/' + ip)
response = json.loads(req.text)

if (response.status_code == '200'):
    if (isp == ''):
        isp = response['shortname']
    if (country == ''):
        country = response['country']

    # Need to get more information about blocklist

else: 
    print("For IP address " + ip + ' DNSlytics failed to retrieve any information.')
'''
'''
# DNSlytics internal API
url = 'https://a.dnslytics.com/v1/report/ip'
data = {
    'q': ip,
    'dataset': 'ip',
}
req = requests.request('', json=data)
response = json.loads(req.text)

if (response.status_code == "200"):
    print('success')

    for bl in response['ip']['dnsbl']:
        if bl['listed'] == True:
            blocklist += bl['name'] + '\n '
else:
    print("DNSlytics request error.")


# Abuse IP DB
# Requires an API key
api_key = ''

querystring = {
    'ipAddress': ip
}

headers = {
    'Accept': 'application/json',
    'Key': api_key
}

req = requests.request(method='GET', url='https://api.abuseipdb.com/api/v2/check', headers=headers, params=querystring)
response = json.loads(req.text)

abuseipdb_categories = {1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack', 5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP', 
                        9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam', 13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection', 
                        17: 'Spoofing', 18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host', 21: 'Web App Attack', 22: 'SSH', 23: 'IoT Targeted'}

if (response.status_code == '200'):
    if (isp == ''):
        isp = response['data']['isp']
    if (country == ''):
        country = response['data']['country']

    if (response['data']['totalReports'] > 0):
        reported_all = ''
        categories = ''
        # !! need to add double quotes to prevent text from being put into columns
        for report in response['data']['reports']:
            reported_all += '(' + report['reportedAt'][:10] + '; '
            for code in report['categories']:
                reported_all += abuseipdb_categories[code] + ', '

            reported_all -= ', '
            reported_all += '), '
        reported_all -= ', '

        notes += 'https://www.abuseipdb.com/check/' + ip + " " + reported_all


# Stop Forum Spam 
# https://www.stopforumspam.com/usage


# Shodan 
# Requires API key
# https://shodan.readthedocs.io/en/latest/


# 





















#results.write(ip + ',' + country + ',' + city + ',' + state + ',' + proxy + ',' + vpn
#              + spam + ',' + blocklist + ',' + malware + ',' + malware_activity + ',' + notes)

'''
