'''
This program will download CVEs from the NVD and plot them
'''

# Must install requests: pip install requests
import requests
import json #inserted, was not included originally
# Must install plotly: pip install plotly
from plotly.graph_objs import Bar, Scatter
from plotly import offline
# You may alternatively use matplotlib instead of plotly if desired

import urllib.parse
import os.path, hashlib
# For storing the results
import csv


def request_cve_list(year, month):
    ''' Get CVE info from NIST using requests and return a json object '''

    API_KEY = '2dd62f77-e6ae-4832-b1a9-8cf711a14287' #my generated key

    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0' #nvd url for the json file
    headers_nist = {'apikey': API_KEY}

#dictionary of the last days of each month
    month_end_date = {
        1: '31',
        2: '28',
        3: '31',
        4: '30',
        5: '31',
        6: '30',
        7: '31',
        8: '31',
        9: '30',
        10: '31',
        11: '30',
        12: '31',
    }
    # month_end_date[month]
   # full_url = f'{base_url}?pubStartDate=' #After question mark arguments come


#Stating where I want to look with date all the way to milliseconds
    params = {
        'pubStartDate': f'{year}-{month:02d}-01T00:00:00.000', 
        'pubEndDate': f'{year}-{month:02d}-{month_end_date[month]}T23:59:59.999',
        'noRejected' : None
    }
    
    params = '&'.join([k if v is None else f"{k}={v}" for k, v in params.items()])
    #print (params)

    json_filename = f'vulns_{year}_{month}.json'
    if not os.path.isfile(json_filename):
        json_response = requests.get(url=base_url, params=params) #pulls the url and inserts the entered dates
        json_result = json_response.json() #gives result and formats to json

        with open(json_filename, 'w') as file:
            json.dump(json_result, file, indent=2) #typed json_response instead of json_result lol
    else:
        with open(json_filename, 'r') as file:
            json_result = json.load(file) 

    return json_result #output of json 

    #json_response = requests.get(url=full_url,params=params)

    #pass


def write_CVEs_to_csv(year, month):
    ''' Task 1: write a CSV with key info in it '''
    
    filename = f"cve-{year}-{month:02d}.csv"

    if not os.path.isfile(filename):
        cve_json = request_cve_list(year, month)
        # Parse the JSON and write to CSV
    else:
        print(f"The following file already exists: {filename}")


def plot_CVEs(year,month,topnum=40):
    ''' Task 2: read that out and do a plot '''

    filename = f"cve-{year}-{month:02d}.csv"

    if not os.path.isfile(filename):
        cve_json = request_cve_list(year,month)
        
        #parse JSON and write to CSV

        #crete list of header field that we care about
        header_fields = [
            'cveid',
            'month',
            'year',
            'published',
            'lastModified',
            'exploitabilityScore',
            'impactScore',
            'vectorString',
            'attackVector',
            'attackComplexity',
            'privilegesRequired',
            'userInteraction',
            'scope',
            'confidentialityImpact',
            'integrityImpact',
            'availabilityImpact',
            'baseScore',
            'baseSeverity',
            'description'
        ]

    #Open CSV
    with open(filename, 'w') as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(header_fields)

        for cve in cve_json['vulnerabilities']:
            cveid = cve['cve']['id']
            published = cve['cve']['published']
            lastModified = cve['cve']['lastModified']
            description = cve['cve']['descriptions'][0]['value']

            #try:
            if "cvssMetricV31" in cve['cve']['metrics'].keys():
                metric_base = cve['cve']['metics']['cvsMetricV31']
                exploitabilityScore = metric_base['cvssData']['exploitabilityScore']
                impactScore = metric_base['impactScore']

                vectorString =['cvssData']['vectorString']
                attackVector =['cvssData']['attackVector']
                attackComplexity =['cvssData']['attackComplexity']
                privilegesRequired =['cvssData']['previlegesRequired']
                userInteraction =['cvssData']['userInteraction']
                scope =['cvssData']['scope']
                confidentialityImpact =['cvssData']['confidentialityImpact']
                integrityImpact =['cvssData']['integrityImpact']
                availabilityImpact =['cvssData']['availabilityImpact']
                baseScore =['cvssData']['baseScore']
                baseSeverity =['cvssData']['baseSeverity']
            else:
                print(f'CVSS 3.1 Metrics not found for: {cveid}')
            '''except:
            print(f'CVSS 3.1 Metrics not found for: {cveid}')'''
        
            writer.writerow([cveid, month, year, published, lastModified, exploitabilityScore, 
                            impactScore, vectorString, attackVector, attackComplexity, privilegesRequired, 
                            userInteraction, scope, confidentialityImpact, integrityImpact, availabilityImpact, 
                            baseScore, baseSeverity, description])
        
           

        else:
            print(f"The following file already exists: {filename}")

def plot_CVEs(year,month,topnum=40):
    '''Task 2L read that out and do a plot'''
    filename = f"cve-{year}-{month:02d}.csv"
    with open(filename, 'r', newline='') as csv_file:
        reader = csv.reader(csv_file)
        csv_rows = []
        for row in reader[1:]:
            csv_rows.append(row[16], [row[0], row[5], row[18]])
        csv_rows.sort(reverse=True)

        cveids = []
        scores = []


       # for row in csv_rows:
         #   cveids.append(row[1])   
# new list with 4 columns with sublists of those columns for the plots

    pass

if __name__ =="__main__":
    # Do not modify
    year = 2022
    month = 2

    write_CVEs_to_csv(year, month)
    plot_CVEs(year, month)
    h = hashlib.new('sha1')
    h.update(open("cve-2022-02.csv").read().encode("utf-8"))
    print(h.hexdigest())
