from bs4 import BeautifulSoup
import requests as req
from logzero import logger
from urllib.parse import quote, urlencode

import config.form_method as form_method
from utils.cookies import cookie_parser 

# global config
URL = 'http://localhost/vulnerabilities/xss_d/'
CREDENTIALS = "PHPSESSID=mde6rg83uor0b4k8b64kvm95m0; security=low"


with open('payload.txt','r') as file:
    payloads = file.read().splitlines()

def filterInputTag(tag):
    if tag.has_attr('type'):
        if tag['type'] != 'submit':
            return tag
    else:
        return tag

def filterButtonTag(tag):
    if tag.name == 'input':
        if tag.has_attr('type'):
            if tag['type'] == 'submit':
                return tag
    if tag.name == 'button':
        return tag

def main():
    logger.info(f"Running Reflected XSS Scanner")

    filtered_input_tags = []
    filtered_submit_button = []
    filtered_select_tags = []

    raw_js_files = []
    res = req.get(URL, cookies=cookie_parser(CREDENTIALS))
    
    # checking response if has history
    history = res.history

    if len(history) > 0:
        if history[0].status_code == 302:
            logger.error('Stopped, Need Credentials')
            exit(1)
    
    parsed = BeautifulSoup(res.content, 'html.parser')
    # get js file
    # if loading js file
    # get all script file
    if(parsed.find_all('script')):
        script_tags = parsed.find_all('script')
        if len(script_tags) > 0:
            for script_tag in script_tags:
                try:
                    js_file = req.get(f"{URL}/{script_tag['src']}")
                    raw_js_files.append(js_file.content)
                except:
                    pass
    
    # get all input tag
    if parsed.find_all('input'):
        input_tags = parsed.find_all('input')
        if len(input_tags) > 0:
            filtered_input_tags = list(filter(filterInputTag, input_tags))
            filtered_submit_button += list(filter(filterButtonTag, input_tags))
    if parsed.find_all('button'):
        button_tags = parsed.find_all('button')
        if len(button_tags) > 0:
            filtered_submit_button += button_tags
    if parsed.find_all('select'):
        select_tags = parsed.find_all('select')
        filtered_select_tags += select_tags

    # Schema 1
    # via form get request
    if parsed.form:
        if parsed.form['method'].lower() == form_method.GET:
            logger.info(f"Searching possibility reflected XSS")
            queries = []
            logger.info(f"Schema #1")
            for input_tag in filtered_input_tags:
                try:                    
                    queries.append(input_tag['name'])
                except:
                    pass
            for select_tag in filtered_select_tags:
                try:
                    queries.append(select_tag['name'])
                except:
                    pass
            
            # if parameter url not found
            if len(queries) == 0:
                logger.warning('Stopped, no possibility was found')

            if len(queries) > 0:
                for payload in payloads:
                    params = [(quote(query), quote(payload)) for query in queries]
                    res = req.get(
                        URL,
                        params=params,
                        cookies=cookie_parser(CREDENTIALS)
                    )
                    logger.warning(f"Testing {URL}?{urlencode(params)}")
                    logger.warning(f"{payload} (PAYLOADS)")
                    if res.status_code == 200:
                        # print(f"Len data: {len(res.content)}")
                        print(f"Status Code: {res.status_code}")
                        # print(f"{res.content}")
                    if res.status_code != 200:
                        logger.error(f"Error Status Code : {res.status_code}")
                
    
    # logger.debug(f"Filtered Input Tags")
    # logger.debug(filtered_input_tags)
    # logger.debug(f"Filtered Submit Button")
    # logger.debug(filtered_submit_button)
    # logger.debug(f"Filtered Raw JS File")
    # logger.debug(raw_js_files)
    
    
    

if __name__ == "__main__":
    main()