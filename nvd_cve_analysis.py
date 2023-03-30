'''
This program will download CVEs from the NVD and plot them
'''

# Must install requests: pip install requests
import requests

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

    API_KEY = '2dd62f77-e6ae-4832-b1a9-8cf711a14287'

    base_url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    headers_nist = {'apikey': API_KEY}

   # full_url = f'{base_url}?pubStartDate=' #After question mark arguments come

    params = {
        'pubStartDate': '2022-02-01T00:00:00.000', 
        'pubEndDate': '2022-02-28T23:59:59.999',
    }
    
    json_filename = f'vulns_{year}_{month}.json'
    if not os.path.isfile(json_filename):
        json_response = requests.get(url=base_url, params=params)

    else:    

    #json_respone = requests.get(url=full_url,params=params)

        pass


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
