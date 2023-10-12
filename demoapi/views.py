from urllib import response
from django.shortcuts import render
from django.http import HttpResponse
import requests, json
import pandas as pd
from django.core.paginator import Paginator

def cves(req):
    try:
        response = requests.get('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
            
    except AttributeError:
        pass
        
    # Load the JSON data from the response
    jd = json.loads(response.text)

    # Initialize empty lists
    cveID_list = []
    vendorProject_list = []
    product_list = []
    dateAdded_list = []
    vulnerabilityName_list = []
    shortDescription_list = []
    ref_list = []

    # Iterate over the list of dictionaries
    # Extract the desired values from the 'vulnerabilities' array
    for item in jd['vulnerabilities']:
        cveID_list.append(item['cveID'])
        vendorProject_list.append(item['vendorProject'])
        product_list.append(item['product'])
        dateAdded_list.append(item['dateAdded'])
        vulnerabilityName_list.append(item['vulnerabilityName'])
        shortDescription_list.append(item['shortDescription'])
        ref_list.append(item['notes'])
        
    rcve = cveID_list[::-1]
    rdate = dateAdded_list[::-1]
    rvendr = vendorProject_list[::-1]
    rprod = product_list[::-1]
    rvname = vulnerabilityName_list[::-1]
    rdesc = shortDescription_list[::-1]
    rref = ref_list[::-1]
    

    info = {'ID':rcve,'DATES':rdate,'VENDOR':rvendr,'PRODUCT':rprod,'VULNAME':rvname,'DESC':rdesc,'REF':rref}
    
    df = pd.DataFrame.from_dict(info)
    
    jrec = df.reset_index().to_json(orient='records')
    data = []
    data = json.loads(jrec)
    
    # Creating our paginator object
    paginator = Paginator(data, 30)  # Show 30 records per page.
    
    # Get current page number from query string. (If not provided, defaults to 1)
    page_number = req.GET.get('page', 1)

    # Get records in current page
    page_of_data = paginator.get_page(page_number)
	
    # Add pagination data to context
    context = {'c': page_of_data}

    return render(req, "vuln.html", context)
