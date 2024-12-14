# Basic skeleton of a mitmproxy addon.

# Run as follows: mitmproxy -s count.py

# mitmdump -s "C:\Users\ragla\Documents\coding_projects\vskan\mitm-addon\count.py"


from mitmproxy import http
from enum import Enum
from typing import Literal
import logging


target_sites = [
    # !! First matching rule will apply
    {
        'url_regex': '*',
        'scan_mode': 'watch' # 'probe' | 'attack'
    }
]


# Active checks 
# https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/#active-checks

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






def check_cookie_http_only(flow: http.HTTPFlow):
    # TODO read: https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/352.1.html
    cookies_in_response = flow.response.cookies

    if(len(cookies_in_response) > 0):
        logging.info("List of cookies in response: %s" % flow.response.cookies)
        # logging.info("List of cookies in response: %s" % flow.response.cookies.fields)

    
        # for f, val in flow.response.cookies.fields:
        #     for v, attrs in val:
        #         logging.info("attrs: %s" % attrs)


        for x in iter(cookies_in_response):
            logging.info("x: %s" % x)
            val = cookies_in_response.get_all(x)

            for v in val:
                logging.info("v: %s" % v[0])
                attr_keys = list(v[1].keys())
                logging.info("v[1]: %s" % attr_keys)
                
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



def check_cors(flow, skan_mode):

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




def check_sensitive_in_get(flow):
    #TODO: read https://docs.gitlab.com/ee/user/application_security/dast/browser/checks/598.3.html
    pass





class Counter:
    def __init__(self):
        pass


    def check_csp(self, flow):
        logging.debug("Request header is %s" % flow.request.headers)

    def request(self, flow):
       pass

        #logging.info("Flow headers %s" % flow.request.headers)

    def response(self, flow):
        # check_response_headers_csp(flow)
        # check_cookie_http_only(flow)

        check_cors(flow, 'watch')


addons = [Counter()]