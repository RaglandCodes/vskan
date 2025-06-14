# Basic skeleton of a mitmproxy addon.

# Run as follows: mitmproxy -s count.py

# mitmdump -s "path\to\file\vskan.py"


import logging
import re
import copy
import hashlib
import random
import socket
import time
import json
import ssl
# from markdown_it import MarkdownIt
# from mdit_py_plugins.front_matter import front_matter_plugin
# from mdit_py_plugins.footnote import footnote_plugin





from urllib.parse import urlparse

from enum import Enum
from known_risks_data import compomised_external_sites
from vuln_types import SkannedVulnerabilityType
from remediations import remediations_dict
from ssl_utils import skan_domain_ssl
from mitmproxy import ctx
import networkx as nx


G = nx.Graph()
# md = (
#     MarkdownIt('commonmark' ,{'breaks':True,'html':True})
#     .use(front_matter_plugin)
#     .use(footnote_plugin)
#     .enable('table')
# )




    #-- Information only and not directly a vulnerability






class SkannedVulnerability:
    def __init__(self, vuln_type: SkannedVulnerabilityType, short_message: str, long_message: str) -> None:
        self.vuln_type = vuln_type
        self.short_message = short_message
        self.long_message = long_message

    def list_id(self) -> str:
        return hashlib.md5(f"{self.short_message}+{self.long_message}+{random.randint(1000, 9990000)}".encode("utf-8")).hexdigest()

    def vuln_type_display(self) -> str:
        return self.vuln_type.name

class PublishVulnerabilities:
    discoverd_vulns : list[SkannedVulnerability] = []
    
    def add(self, v: SkannedVulnerability):
        self.discoverd_vulns += [v]
        self.update_data()

    def extend(self, v: list[SkannedVulnerability]):
        self.discoverd_vulns += v
        self.update_data()

    def update_data(self):
        path_to_data_out = r"C:\Users\ragla\Documents\coding_projects\vskan\mitm-addon\ui_server\data.json"
        with open(path_to_data_out, "w") as f:
            list_for_ui = [{'id': d.list_id() , 'vuln_type': d.vuln_type_display(),
                    'short_message': d.short_message,
                    'long_message': d.long_message,
                    'remediation_method': remediations_dict.get(d.vuln_type)
                    # 'remediation_method': md.render(remediations_dict.get(d.vuln_type))
            } for d in self.discoverd_vulns]


            f.write(
                f"{json.dumps(list_for_ui)}")
        

        # logging.info(f"sv from c: {self.discoverd_vulns}")

pl = PublishVulnerabilities()

def parse_csp(csp_value: str):
    if not csp_value:
        return None
        
    directives = csp_value.split(';')
    directives = [ d.strip() for d in directives]
    directives = [ d.split() for d in directives]
    directives = [ d for d in directives if d]
    logging.info("directives are %s" % directives)

    return {c[0]: c[1:] for c in directives}


def check_response_headers_csp(flow):
    #logging.info("response header iss %s" % flow.response.headers)

    csp_header = flow.response.headers.get("content-security-policy")

#    logging.info("csp header iss %s" % csp_header)

 #   csp_directives = parse_csp(csp_header)
  #  logging.info("csp directives arre  %s" % csp_directives)
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
                    pl.add(SkannedVulnerability(SkannedVulnerabilityType.COOKIE_SECURE, 
                        'Cookie not set securely'
                        , f"Cookie {x} not set securely"))

                

                if('SameSite' in attr_keys):
                    logging.debug("%s is set with SameSite.. OK" % x)
                else:
                    #TODO check if is a session
                    logging.warn("%s is not set SameSite.." % x)
                    pl.add(SkannedVulnerability(SkannedVulnerabilityType.COOKIE_SAME_SITE, 
                        'Cookie not set with same site attribute'
                        , f"Cookie {x} not set with same site attribute"))


                if('HttpOnly' in attr_keys):
                    logging.debug("%s is set with HttpOnly.. OK" % x)
                else:
                    #TODO check if is a session
                    logging.warn("%s is not set HttpOnly.." % x)
                    pl.add(SkannedVulnerability(SkannedVulnerabilityType.COOKIE_HTTP_ONLY, 
                        'Cookie not set with http only attribute'
                        , f"Cookie {x} not set with same http only attribute"))


def simple_header_set_check(flow):

    x_content_type_options_header_value = flow.response.headers.get("X-Content-Type-Options") 

    if not x_content_type_options_header_value:
        logging.warn("X-Content-Type-Options is not set")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.CONTENT_TYPE_OPTIONS, 
                        'X-Content-Type-Options  header is not set'
                        , None))

    if x_content_type_options_header_value != "nosniff":
        #TODO: read the multiple stack answers: https://stackoverflow.com/questions/18337630/what-is-x-content-type-options-nosniff
        # TODO: read https://en.wikipedia.org/wiki/Content_sniffing
        # TODO: read about mime types: https://developer.mozilla.org/en-US/docs/Web/HTTP/MIME_types#structure_of_a_mime_type
        logging.warn("X-Content-Type-Options exists but not set to nosniff")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.CONTENT_TYPE_OPTIONS_NOSNIFF, 
                        'Content type options is not set to nosniff'
                        , 'X-Content-Type-Options exists but not set to nosniff'))


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
    
#TODO: file upload mechanisms

#TODO : detect server stack


def code_disclosure_check(flow):
    # WEB_INF, META-INF
    # TODO: ZAP code: https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SourceCodeDisclosureWebInfScanRule.java

    # Source code inclusion
    #TODO: https://www.zaproxy.org/docs/alerts/43/

    # WEB-INF /web.xml
    # https://stackoverflow.com/q/66812529

    #/conf/server.xml/ from https://security.stackexchange.com/a/198200
    # Swagger

    # TODO : check directory indexing enabled
    pass


def probe_send_spring_actuator_info_leak(flow):
    #TODO
    # - https://www.zaproxy.org/docs/alerts/40042/
    pass


def probe_test_spring_actuator_info_leak(flow):
    #TODO
    # - https://www.zaproxy.org/docs/alerts/40042/
    pass

def watch_known_web_server_software(flow):
    x_powered_by_header_value = flow.response.headers.get("X-Powered-By") 


    # Java 

    # - #TODO: Check if ..jsp in url
    if('.jsp' in flow.request.url):
        logging.warn("Web app powered by Java")

    # ASP.NET
    if('.aspx' in flow.request.url or '.asp' in flow.request.url ):
        logging.warn("Web app powered by ASP.NET")


    # Wordpress
        #TODO: Check for /wp-admin

    # PHP
    if('.php' in flow.request.url):
        logging.warn("Web app powered by php")


    if(x_powered_by_header_value and ('php' in x_powered_by_header_value.lower())):
        logging.warn(f"Using PHP software stack: {x_powered_by_header_value}")

    # --- Frontend ---

    # React

    # Vue

    # Angular

    # Bootstrap

    pass

def watch_known_web_server_infra(flow):
    x_powered_by_header_value = flow.response.headers.get("X-Powered-By") 
    x_server_header_values = flow.response.headers.get_all("Server") or []

    if(x_powered_by_header_value):
        logging.warn(f"X-Powered-By is not suppressed. It's value is {x_powered_by_header_value}")

    if(x_server_header_values):
        logging.warn(f"Server values in header: {x_server_header_values}")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.INFO_SERVER_INFRA_HOSTING_PROVIDER, 
                 'Server value in header'
                , f"Server: {x_server_header_values}"))

    # Apache
    # - TODO.. The header contains "Apache"

    # nginx
    # - TODO.. The header contains `nginx`

    # MS
    if(x_powered_by_header_value and 'ASP.NET' in x_powered_by_header_value):
        logging.warn("Server software uses ASP.NET")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.INFO_SERVER_SOFTWARE, 
                 "Server software uses ASP.NET"
                , None))

    for k, v in flow.response.headers.items(multi=False):
        if 'AspNet' in k:
            logging.warn(f"ASP.NET header found. {k}: {v}")

    headers_indicating_msft_stack = [m for m in x_server_header_values if ('Microsoft' in m) or ('IIS' in m)]
    
    if(headers_indicating_msft_stack):
        logging.warn(f"Found headers indicating server run on Windows server tech: {headers_indicating_msft_stack}")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.INFO_SERVER_SOFTWARE, 
                f"Found headers indicating server run on Windows server tech"
                , f"Headers: {headers_indicating_msft_stack}"))

    # Hosting provider

    # Azure

    # GCP

    # Cloudflare

    pass

def check_https_usage(flow):

    #TODO: check cipher suites
    if flow.request.scheme == 'http':
        if flow.response.status_code < 400:
            logging.warn(f"Got a non error response when using http for {flow.request.host} {flow.request.path}")
            pl.add(SkannedVulnerability(SkannedVulnerabilityType.HTTP_SCHEME_USAGE, 
                 'Site uses http protocol'
                , None))
    

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
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.HEADER_HSTS_SET, 
                 'HSTS header is not set'
                , None))
    
        return

    included_subdomains = [h for h in truthy_hsts_value if 'includeSubDomains' in h]

    if not len(included_subdomains):
        logging.warn("HSTS header doesn't include subdomains")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.HEADER_HSTS_SUBDOMAIN, 
                 'HSTS header does not include subdomain'
                , None))
    
        
    

def simple_header_info_leak_check(flow):
    x_powered_by_header_value = flow.response.headers.get("X-Powered-By") 
    x_backend_server_header_value = flow.response.headers.get("X-Backend-Server") 
    x_debug_token_header_value = flow.response.headers.get("X-Debug-Token") 
    x_debug_token_link_header_value = flow.response.headers.get("X-Debug-Token-Link") 

    if x_powered_by_header_value:
        # TODO read more: https://www.zaproxy.org/docs/alerts/10037/
        logging.warn("X-Powered-By is not suppressed")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.HEADER_LEAK_X_POWERED_BY, 
                 f"X-Powered-By : {x_powered_by_header_value}"
                , None))
    


    if x_backend_server_header_value:
        logging.warn("X-Backend-Server is not suppressed")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.HEADER_LEAK_X_BACKEND_SERVER, 
                 f"X-Backend-Server : {x_backend_server_header_value}"
                , None))
    

    if x_debug_token_header_value or x_debug_token_link_header_value:
        logging.warn("X-Debug-Token is not suppressed")


    if flow.response.headers.get("X-AspNet-Version"):
        logging.warn("AspNet version header is not suppressed")

    if (flow.response.headers.get("X-ChromeLogger-Data") or
        flow.response.headers.get("X-ChromePhp-Data")
    ):
        logging.warn("Backend data sent using debug tools")



def check_cors(flow, flow_site_id, skan_mode):

    #TODO read header forbidden: https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name

    access_control_header = flow.response.headers.get("Access-Control-Allow-Origin")



    if not access_control_header:
        logging.warn("Access control header not set")

        pl.add(SkannedVulnerability(SkannedVulnerabilityType.CORS_SET, 
                 f"CORS header is not set"
                , None))
    
        return
    
    if access_control_header.strip() == '*':
        logging.warn("Access control header is allowing all")
        pl.add(SkannedVulnerability(SkannedVulnerabilityType.CORS_ALL_ALLOWED, 
                 f"CORS allows all origins"
                , None))

    
    if skan_mode == 'probe':
        pass
        # TODO check for server generated custom header allowing
        # https://portswigger.net/web-security/cors


def check_known_analytics_provider(flow):
    pass

def check_known_compromised_site(flow):
    matched_with_known_risks = [ c for c in compomised_external_sites if flow.request.host in c]

    if len(matched_with_known_risks) == 0:
        return

    logging.warn(f"Attempted to connect to following compromised exteranal sites: {matched_with_known_risks}")
    pl.add(SkannedVulnerability(SkannedVulnerabilityType.CONNECT_COMPROMISED_SITE, 
                 f"Attempt to connect to known compromised sites"
                , f"{matched_with_known_risks} are compromised."))

def check_sensitive_in_get(flow):
    #TODO: read https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/598.3.html
    pass


def slow_lorris_https(flow):
    pass

def slow_lorris_attack_http(flow, for_https = False):
    # code from https://github.com/gkbrk/slowloris/blob/master/slowloris.py
    logging.info("Attempting slowloris")
    flow_referrrer = flow.request.headers.get('Referer')
    # have to add one more r to compensate for this^

    flow_domain = urlparse(flow_referrrer).netloc

    ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:49.0) Gecko/20100101 Firefox/49.0"
    # Your target domain and port
    host = flow_domain
    port = 80  # Use 443 for HTTPS (you'll need to use ssl.wrap_socket then)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)

    if for_https:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=host)

    s.connect((host, port))
    

    s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode('utf-8'))

    s.send(f"User-Agent: {ua}\r\n".encode('utf-8'))
    s.send("Accept-language: en-US,en,q=0.5\r\n".encode('utf-8'))

    head_ctr = 0;
    sleep_time_interval = 1
    max_try_to_warn = 10
    # Slowly send headers, one at a time
    try:
        while True:
            s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode('utf-8'))
            logging.info(f"[{head_ctr}]: Sent a keep-alive header...")
            time.sleep(sleep_time_interval)  # Wait between sending headers
            head_ctr += 1
            
            if head_ctr == max_try_to_warn:

                pl.add(SkannedVulnerability(SkannedVulnerabilityType.ATTACK_SERVER_SLOWLORIS, 
                 'Site is suceptible to Slowloris attack'
                , f"Server kept HTTP connection open for {sleep_time_interval * max_try_to_warn} seconds"))
             
                s.close()
                return

    except Exception as e:
        logging.info(f"Exiting due to {e}")

    finally:
        s.close()
        logging.info("Finishing slowloris")
        return


def http_host_header_attack(flow):
    # https://portswigger.net/web-security/host-header/exploiting#connection-state-attacks
    pass

def form_fill_xss_attack(flow):
    # https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#context-specific-decoding
    pass

def get_parameter_xss_attack(flow):
    pass

def watch_jwt(flow):
    pass

def attack_jwt_none_alg(flow):

    did_attack = False
    return did_attack

def watch_ssl_vuln(flow):
    r = skan_domain_ssl(flow)
    logging.info(r)
    pl_ = [SkannedVulnerability(SkannedVulnerabilityType.INFO_SERVER_INFRA_TLS, m, None) for _, m in r]
    
    pl.extend(pl_)

class Skanner:
    def __init__(self):
        pass


    target_sites = {
    # !! First matching rule will apply
    'owasp_juice' : {
            'url_regex': 'https?://juice-shop-p0va.onrender.com*',
            'scan_mode': 'attack', # 'watch' | 'probe' | 'attack'
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
            check_known_analytics_provider(flow)


    def response(self, flow):

        if flow.is_replay == 'request':
            logging.info(f"Got a replay's response [{flow.response.status_code }] with {flow.request.method} host {flow.request.host} and path {flow.request.path}")
    
    
            if flow.request.path == '/.htaccess' and flow.response.status_code < 400:
                logging.warn(f"Got non error response for htcaccess with content {flow.response.content}")
                pl.add(SkannedVulnerability(SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_HTACCESS, None, None))

                response_test = flow.response.content.decode('utf-8')

                htcaccess_file_keywords = ['AuthName', 'AuthType', 'AddHandler']
                htcaccess_file_keywords_in_response_body = [k in response_test for k in htcaccess_file_keywords].count(True)

                if htcaccess_file_keywords_in_response_body > 0:
                    logging.warn(f"Found {htcaccess_file_keywords_in_response_body} keywords in htcaccess body")



            if flow.request.path == '/.env' and flow.response.status_code < 400:
                logging.warn(f"Got non error response for env file with content {flow.response.content}")
                pl.add(SkannedVulnerability(SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_ENV, 
                'Request to /.env did not return an error response'
                , None))



            if flow.request.path == '/.git' and flow.response.status_code < 400:
                logging.warn(f"Got non error response for /.git")
                pl.add(SkannedVulnerability(SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_GIT, 
                 'Request to /.git did not return an error response'
                , None))


            if 'actuator/health' in flow.request.path:
                probe_test_spring_actuator_info_leak(flow)

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

        check_response_headers_csp(flow)
        
        check_cookie_http_only(flow)

        if (not self.completed_attacks.get(f"cors_{flow_site_id}")):
            check_cors(flow, flow_site_id, flow_attack_mode)
            self.completed_attacks[f"cors_{flow_site_id}"] = True


        check_https_usage(flow)


        if len(self.target_sites[flow_site_id]['flow_saves']) < 40:
            # Not running forever, to avoid unnecessary noise
            watch_jwt(flow)

            watch_known_web_server_software(flow)

            if (not self.completed_attacks.get(f"hosting_provider_{flow_site_id}")):
                watch_known_web_server_infra(flow)
                self.completed_attacks[f"hosting_provider_{flow_site_id}"] = True


        if flow_attack_mode in ['probe', 'attack']:
            # Save flows to be used later
            if flow.request.method in ['GET', 'POST']:
                self.target_sites[flow_site_id]['flow_saves'].append(flow.copy())

                if len(self.target_sites[flow_site_id]['flow_saves']) % 20 == 0:
                    logging.info(f"{flow_site_id} has {len(self.target_sites[flow_site_id]['flow_saves'])} saved flows !")

                if len(self.target_sites[flow_site_id]['flow_saves']) > 5_000:
                    logging.warn(f"{flow_site_id} has more than 5000 saved flows !")

            

            

        if flow_attack_mode in ['probe', 'attack']:

            if (
                not self.completed_attacks.get(f"simple_config_exposure_{flow_site_id}") 
                and flow.request.method == 'GET'

            ):
                # To avoid unnecessary repetition
                self.completed_attacks[f"simple_config_exposure_{flow_site_id}"] = True
                
                simple_config_file_exposure_check(flow)

            if (
                not self.completed_attacks.get(f"ssl_watch_{flow_site_id}") 
                and flow.request.method == 'GET'

            ):
                watch_ssl_vuln(flow)
                self.completed_attacks[f"ssl_watch_{flow_site_id}"] = True

            if (
                not self.completed_attacks.get(f"code_exposure_{flow_site_id}") 
                and flow.request.method == 'GET'

            ):
                # To avoid unnecessary repetition
                self.completed_attacks[f"code_exposure_{flow_site_id}"] = True
                
                code_disclosure_check(flow)
            
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
             if (
                not self.completed_attacks.get(f"slow_lorris_{flow_site_id}") 
            ):
                slow_lorris_attack_http(flow)  
                self.completed_attacks[f"slow_lorris_{flow_site_id}"] = True
                logging.info(f"completed attacks: {self.completed_attacks}")



            # HTTP host header

                

    # def done():
    #     logging.info("Shutting down.. Will generate report")





addons = [Skanner()]