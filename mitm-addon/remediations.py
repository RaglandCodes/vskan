from vuln_types import SkannedVulnerabilityType



remediations_dict = {
    SkannedVulnerabilityType.COOKIE_SECURE : """\
        To minimize the scope for cookie vulnerabilities on your site, limit access to cookies as much as possible. This can be done via sensible usage of the following directives of the Set-Cookie header:

        ### Resources:
        
        https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies
    
        """,

    SkannedVulnerabilityType.COOKIE_SAME_SITE : """\
        Setting same site cookie attirbute controls whether or not a cookie is sent with cross-site requests: that is, requests originating from a different site, including the scheme, from the site that set the cookie. This provides some protection against certain cross-site attacks, including cross-site request forgery (CSRF) attacks.
    
        ### Resources:
        https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF#defense_in_depth_samesite_cookies
        """,

    SkannedVulnerabilityType.COOKIE_HTTP_ONLY : """ \
            Ensure that cookies are sent securely and aren't accessed by unintended parties or scripts in one of two ways: with the Secure attribute and the HttpOnly attribute

            https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#security

            """,

    # HEADER_X_CONTENT_TYPE_OPTIONS = 4
    # HEADER_HSTS_SET = 11
    # HEADER_HSTS_SUBDOMAIN = 12

    # HEADER_LEAK_X_POWERED_BY = 13
    # HEADER_LEAK_X_BACKEND_SERVER = 14
    # HEADER_LEAK_X_ASPNET_VERSION = 15

    # CONFIG_FILE_EXPOSURE_HTACCESS = 5
    SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_ENV: """ \
            .env files exposure could grant access to hidden configuation

            ### Resources:
            https://www.zaproxy.org/docs/alerts/40034/

            """,
    SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_GIT: """ \
            Disclosing source code could allow more targeted attacks based on implementation details.

            ### Resources:
            https://www.zaproxy.org/docs/alerts/41/

            """,
    # # CONFIG_FILE_EXPOSURE_HTACCESS = 8

    # JWT_WELL_KNOWN_SECRET = 30
    # JWT_NO_VERIFICATION = 31
    # JWT_SELF_SIGNED_INJECT = 32
    # # JWT_WELL_KNOWN_SECRET = 33
    # # JWT_WELL_KNOWN_SECRET = 34
    # # JWT_WELL_KNOWN_SECRET = 35



    # HTTP_SCHEME_USAGE = 9
    # HTTP_REDIRECT = 10

    # CORS_SET = 20
    # CORS_ALL_ALLOWED = 21

    # CONNECT_COMPROMISED_SITE = 22

    # INFO_IP_ADDRESS = 40
    # INFO_OPEN_PORT = 41
    # INFO_SERVER_INFRA_HOSTING_PROVIDER = 42
    # INFO_SERVER_INFRA_LOAD_BALANCE = 43
    # INFO_SERVER_INFRA_TLS = 44
    # INFO_SERVER_INFRA_TLS_SAN = 44
    # INFO_SERVER_SOFTWARE = 45

    # ATTACK_SERVER_SLOWLORIS = 47
}
