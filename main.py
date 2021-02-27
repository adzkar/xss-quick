from bs4 import BeautifulSoup
import requests as req
from logzero import logger
import config.form_method as form_method
from urllib.parse import quote

# global config
URL = 'http://localhost/vulnerabilities/xss_r/'
payloads = open('payload.txt','r').read().splitlines()

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
    raw_js_files = []
    res = req.get(URL)
    parsed = BeautifulSoup(res.content, 'html.parser')
    # get js file
    # if loading js file
    # get all script file
    if(parsed.find_all('script')):
        script_tags = parsed.find_all('script')
        if len(script_tags) > 0:
            for script_tag in script_tags:
                js_file = req.get(f"{URL}/{script_tag['src']}")
                raw_js_files.append(js_file.content)
    # print(payloads)
    # get all input tag
    if(parsed.find_all('input')):
        input_tags = parsed.find_all('input')
        if len(input_tags) > 0:
            filtered_input_tags = list(filter(filterInputTag, input_tags))
            filtered_submit_button += list(filter(filterButtonTag, input_tags))
    if(parsed.find_all('button')):
        button_tags = parsed.find_all('button')
        if len(button_tags) > 0:
            filtered_submit_button += button_tags
    
    logger.info(f"Searching possibility reflected XSS")
    # Schema 1
    # via form get request
    if parsed.form:
        if parsed.form['method'].lower() == form_method.GET:
            queries = []
            logger.info(f"Schema #1")
            for input_tag in filtered_input_tags:
                queries.append(input_tag['name'])
            for payload in payloads:
                params = [(quote(query), quote(payload)) for query in queries]
                res = req.get(
                    URL,
                    params=params
                )
                logger.warning(f"Testing {URL}")
                logger.warning(f"{payload} (PAYLOADS)")
                if res.status_code == 200:
                    print(f"Len data: {len(res.content)}")
                if res.status_code != 200:
                    logger.error(f"Error Status Code : {res.status_code}")
                print(f"Status Code: {res.status_code}")
                
    
    # logger.debug(f"Filtered Input Tags")
    # logger.debug(filtered_input_tags)
    # logger.debug(f"Filtered Submit Button")
    # logger.debug(filtered_submit_button)
    # logger.debug(f"Filtered Raw JS File")
    # logger.debug(raw_js_files)
    
    
    

if __name__ == "__main__":
    main()