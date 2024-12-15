# Basic skeleton of a mitmproxy addon.

# Run as follows: mitmproxy -s count.py

# mitmdump -s "path\to\file\vskan.py"


import logging
import re
import copy
import random
from urllib.parse import urlparse
from known_risks_data import compomised_external_sites
from mitmproxy import ctx
import networkx as nx

G = nx.Graph()



def parse_csp(csp_value: str):
    if not csp_value:
        return None
        
    directives = csp_value.split(';')
    directives = [ d.strip() for d in directives]
    directives = [ d.split() for d in directives]

    return {c[0]: c[1:] for c in directives}


def check_response_headers_csp(flow):
    # logging.info("response header iss %s" % flow.response.headers)

    csp_header = flow.response.headers.get("content-security-policy")

    # logging.info("response header iss %s" % csp_header)

    csp_directives = parse_csp(csp_header)
    logging.info("csp directives arre  %s" % csp_directives)
    # logging.info("csp directives arre  %s" % )

    # 1. Check for XSS

    # 2. Check for IFrame



    # x_frame_option_header = flow.response.headers["X-Frame-Options"]

    #3. Check for Clickjacking https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Clickjacking

    #TODO: check for sec fetch headers https://www.zaproxy.org/docs/alerts/90005/






def check_cookie_http_only(flow):
    # TODO read: https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/352.1.html
    cookies_in_response = flow.response.cookies

    if(len(cookies_in_response) > 0):
        # logging.info("List of cookies in response: %s" % flow.response.cookies)
        # logging.info("List of cookies in response: %s" % flow.response.cookies.fields)

    
        # for f, val in flow.response.cookies.fields:
        #     for v, attrs in val:
        #         logging.info("attrs: %s" % attrs)


        for x in iter(cookies_in_response):
            # logging.info("x: %s" % x)
            val = cookies_in_response.get_all(x)

            for v in val:
                # logging.info("v: %s" % v[0])
                attr_keys = list(v[1].keys())
                # logging.info("v[1]: %s" % attr_keys)
                
                if('Secure' in attr_keys):
                    logging.debug("%s is set securely.. OK" % x)
                else:
                    #TODO check if is a session
                    logging.warn("%s is not set securely.." % x)
                

                if('SameSite' in attr_keys):
                    logging.debug("%s is set with SameSite.. OK" % x)
                else:
                    #TODO check if is a session
                    logging.warn("%s is not set SameSite.." % x)


                if('HttpOnly' in attr_keys):
                    logging.debug("%s is set with HttpOnly.. OK" % x)
                else:
                    #TODO check if is a session
                    logging.warn("%s is not set HttpOnly.." % x)


def simple_header_set_check(flow):

    x_content_type_options_header_value = flow.response.headers.get("X-Content-Type-Options") 

    if not x_content_type_options_header_value:
        logging.warn("X-Content-Type-Options is not set")

    if x_content_type_options_header_value != "nosniff":
        #TODO: read the multiple stack answers: https://stackoverflow.com/questions/18337630/what-is-x-content-type-options-nosniff
        # TODO: read https://en.wikipedia.org/wiki/Content_sniffing
        # TODO: read about mime types: https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types#structure_of_a_mime_type
        logging.warn("X-Content-Type-Options exists but not set to nosniff")

def simple_config_file_exposure_check(flow):


    flow_referrrer = flow.request.headers.get('Referer')
    # have to add one more r to compensate for this^

    flow_domain = urlparse(flow_referrrer).netloc
    logging.info(f"Will try htaccess on this domain: {flow_domain}")

    # Check .htaccess 
    htaccess_check_flow = flow.copy()
    htaccess_check_flow.request.path = '/.htaccess'
    ctx.master.commands.call('replay.client', [htaccess_check_flow])

    # Check .env file
    env_check_flow = flow.copy()
    env_check_flow.request.path = '/.env'
    ctx.master.commands.call('replay.client', [env_check_flow])

    # Check .git file
    git_check_flow = flow.copy()
    git_check_flow.request.path = '/.git'
    ctx.master.commands.call('replay.client', [git_check_flow])
    

def code_disclosure_check(flow):
    # WEB_INF
    # TODO: ZAP code: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SourceCodeDisclosureWebInfScanRule.java

    # Source code inclusion
    #TODO: https://www.zaproxy.org/docs/alerts/43/


    # Swagger

    pass

def check_https_usage(flow):

    #TODO: check cipher suites
    if flow.request.scheme == 'http':
        if flow.response.status_code < 400:
            logging.error(f"Got a non error response when using http for {flow.request.host} {flow.request.path}")

    

def http_redirect_check(flow_saves):
    # Get 5 from the saved flow

    flows_ = copy.deepcopy(flow_saves)
    random.shuffle(flows_)
    flows_ = [f for f in flows_ if f.request.method == 'GET']

    logging.info(f"Got {len(flows_)} with 'GET'")



    # This is a for probing only and limiting the number.. Increase it / remove filter at the caller if want to attack
    
    flows_to_probe_http = flows_[:5] if len(flows_) > 5 else flows_

    # With port modified
    for f in flows_to_probe_http:
        f_copy = f.copy()
        f_copy.request.method = 'http'

        if f_copy.request.port in [8443, 443]:
            f_copy.request.port = 80

        ctx.master.commands.call('replay.client', [f_copy])

    # With port as is
    for f in flows_to_probe_http:
        f_copy = f.copy()
        f_copy.request.method = 'http'

        ctx.master.commands.call('replay.client', [f_copy])

    pass

def hsts_header_check(flow_saves):
    flows_ = copy.deepcopy(flow_saves)
    flows_ = [f for f in flows_ if f.request.method == 'GET']

    hsts_value = [f.response.headers.get('Strict-Transport-Security') for f in flows_]

    truthy_hsts_value = [h for h in hsts_value if h]

    if not len(truthy_hsts_value):
        logging.warn("HSTS header doesn't seem to be set")
        return

    included_subdomains = [h for h in truthy_hsts_value if 'includeSubDomains' in h]

    if not len(included_subdomains):
        logging.warn("HSTS header doesn't include subdomains")
        
    

def simple_header_info_leak_check(flow):
    x_powered_by_header_value = flow.response.headers.get("X-Powered-By") 
    x_backend_server_header_value = flow.response.headers.get("X-Backend-Server") 

    if x_powered_by_header_value:
        # TODO read more: https://www.zaproxy.org/docs/alerts/10037/
        logging.warn("X-Powered-By is not suppressed")


    if x_backend_server_header_value:
        logging.warn("X-Backend-Server is not suppressed")

    if flow.response.headers.get("X-AspNet-Version"):
        logging.warn("X-Backend-Server is not suppressed")



def check_cors(flow, flow_site_id, skan_mode):

    #TODO read header forbidden: https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name

    access_control_header = flow.response.headers.get("Access-Control-Allow-Origin")



    if not access_control_header:
        logging.warn("Access control header not set")
        return
    
    if access_control_header.strip() == '*':
        logging.warn("Access control header is allowing all")

    
    if skan_mode == 'probe':
        pass
        # TODO check for server generated custom header allowing
        # https://portswigger.net/web-security/cors



def check_known_compromised_site(flow):
    matched_with_known_risks = [ c for c in compomised_external_sites if flow.request.host in c]

    if len(matched_with_known_risks) == 0:
        return

    logging.warn(f"Attempted to connect to following compromised exteranal sites: {matched_with_known_risks}")

def check_sensitive_in_get(flow):
    #TODO: read https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/598.3.html
    pass


def slow_lorris_attack(floew):
    pass


class Skanner:
    def __init__(self):
        pass


    target_sites = {
    # !! First matching rule will apply
    'owasp_juice' : {
            'url_regex': 'https?://juice-shop-p0va.onrender.com*',
            'scan_mode': 'probe', # 'probe' | 'attack'
            'flow_saves': [],

    },

    'all' : {
            'url_regex': '.*',   
            'scan_mode': 'watch', # 'probe' | 'attack'
            'flow_saves': [],
    }


    }

    scan_results = {
        'csp': [],
        'xss': [],
        

        # Leaked information

        'env_leak': [],
        'htcaccess_leak': [],

        # cors

        'cors': []
        # --
    }

    running_attacks = {}
    completed_attacks = {}


    # Active checks 
    # https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/#active-checks

    def check_csp(self, flow):
        logging.debug("Request header is %s" % flow.request.headers)

    def request(self, flow):
      
        flow_attack_mode = None
        flow_site_id = None

        flow_referer = flow.request.headers.get('Referer')

        if not flow_referer:
            #TODO handle this case of avoid early return
            return


        for site_id, site_info in self.target_sites.items():
            if re.compile(site_info['url_regex']).match(flow_referer):
                flow_attack_mode = site_info['scan_mode']
                flow_site_id = site_id
                break

        if not flow_site_id:
            return

        # attack mode is >= watch here

        if flow.request.method == 'GET':
            check_known_compromised_site(flow)




    def response(self, flow):

        if flow.is_replay == 'request':
            logging.info(f"Got a replay's response [{flow.response.status_code }] with {flow.request.method} host {flow.request.host} and path {flow.request.path}")
    
    
            if flow.request.path == '/.htaccess' and flow.response.status_code < 400:
                logging.warn(f"Got non error response for htcaccess with content {flow.response.content}")

                response_test = flow.response.content.decode('utf-8')

                htcaccess_file_keywords = ['AuthName', 'AuthType', 'AddHandler']
                htcaccess_file_keywords_in_response_body = [k in response_test for k in htcaccess_file_keywords].count(True)

                if htcaccess_file_keywords_in_response_body > 0:
                    logging.warn(f"Found {htcaccess_file_keywords_in_response_body} keywords in htcaccess body")



            if flow.request.path == '/.env' and flow.response.status_code < 400:
                logging.warn(f"Got non error response for env file with content {flow.response.content}")

            if flow.request.path == '/.git' and flow.response.status_code < 400:
                logging.warn(f"Got non error response for /.git")

            check_https_usage(flow)

            # Process the replay and return. To avoid infinite loop
            return

        flow_referer = flow.request.headers.get('Referer')

        if not flow_referer:
            logging.info("No flow referer..")
            return
        
        flow_attack_mode = None
        flow_site_id = None

        for site_id, site_info in self.target_sites.items():
            if re.compile(site_info['url_regex']).match(flow_referer):
                flow_attack_mode = site_info['scan_mode']
                flow_site_id = site_id
                break

        if not flow_site_id:
            logging.info("Not scanning site %s" % flow_referer)
            return


        # logging.info(f"Scanning id %s at level %s" % flow_site_id, flow_attack_mode)
        logging.info(f"[{flow_site_id}] ::> {flow_attack_mode}")

        # check_response_headers_csp(flow)
        
        check_cookie_http_only(flow)

        check_cors(flow, flow_site_id, flow_attack_mode)

        check_https_usage(flow)




        if flow_attack_mode in ['probe', 'attack']:
            # Save flows to be used later
            if flow.request.method in ['GET', 'POST']:
                self.target_sites[flow_site_id]['flow_saves'].append(flow.copy())

                if len(self.target_sites[flow_site_id]['flow_saves']) % 20 == 0:
                    logging.info(f"{flow_site_id} has {len(self.target_sites[flow_site_id]['flow_saves'])} saved flows !")

                if len(self.target_sites[flow_site_id]['flow_saves']) > 5_000:
                    logging.warn(f"{flow_site_id} has more than 5000 saved flows !")

            

            

        if flow_attack_mode == 'probe':

            if (
                not self.completed_attacks.get(f"simple_config_exposure_{flow_site_id}") 
                and flow.request.method == 'GET'

            ):
                # To avoid unnecessary repetition
                self.completed_attacks[f"simple_config_exposure_{flow_site_id}"] = True
                
                simple_config_file_exposure_check(flow)


            if (
                not self.completed_attacks.get(f"https_reditect_{flow_site_id}") 
                and len(self.target_sites[flow_site_id]['flow_saves']) > 20
                and flow.request.method == 'GET'
            ):
                # To avoid unnecessary repetition
                self.completed_attacks[f"https_reditect_{flow_site_id}"] = True
                
                http_redirect_check(self.target_sites[flow_site_id]['flow_saves'])


            if (
                not self.completed_attacks.get(f"hsts_{flow_site_id}") 

                # HSTS not strictly needed in every request.. but best to include it in the first few
                and len(self.target_sites[flow_site_id]['flow_saves']) > 10
                and flow.request.method == 'GET'
            ):
                # To avoid unnecessary repetition
                self.completed_attacks[f"hsts_{flow_site_id}"] = True

                logging.info(f"Checking hsts for {flow_site_id}")
                
                hsts_header_check(self.target_sites[flow_site_id]['flow_saves'])

            



        if flow_attack_mode == 'attack':
            #TODO wrtie attacking tests

            # Resubmit form with http

            # resubmit form with injection

            
            # Slow Lorris

                
            pass

    # def done():
    #     logging.info("Shutting down.. Will generate report")





addons = [Skanner()]