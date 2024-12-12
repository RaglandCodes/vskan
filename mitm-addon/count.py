# Basic skeleton of a mitmproxy addon.

# Run as follows: mitmproxy -s count.py

# mitmdump -s "C:\Users\ragla\Documents\coding_projects\vskan\mitm-addon\count.py"


from mitmproxy import http
from enum import Enum
from typing import Literal
import logging

class CspDirective(enum.Enum):
    CHILD_SRC = '1'
    CONNECT_SRC = '2'
    DEFAULT_SRC = '3'
    FENCED_FRAME_SRC = '4'
    FONT_SRC = '5'
    FONT_SRC = '6'
    IMG_SRC = '7'
    MANIFEST_SRC = '8'
    MEDIA_SRC = '9'
    OBJECT_SRC = '10'
    PREFETCH_SRC = '11'
    SCRIPT_SRC = '12'
    SCRIPT_SRC_ELEM = '13'
    SCRIPT_SRC_ATTR = '14'
    STYLE_SRC = '15'
    STYLE_SRC_ELEM = '16'
    STYLE_SRC_ATTR = '17'
    WORKER_SRC = '18'


def parse_csp(csp_value: str):
    directives = csp_value.split(';')
    directives = [ d.strip() for d in directives]
    directives = [ d.split() for d in directives]



def check_response_headers_csp(flow):
    logging.info("response header iss %s" % flow.response.headers)



def check_cookie_http_only(flow: http.HTTPFlow):
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
                

                
                    



    


class Counter:
    def __init__(self):
        pass


    def check_csp(self, flow):
        logging.debug("Request header is %s" % flow.request.headers)

    def request(self, flow):
       pass

        #logging.info("Flow headers %s" % flow.request.headers)

    def response(self, flow):
        check_response_headers_csp(flow)
        # check_cookie_http_only(flow)


addons = [Counter()]