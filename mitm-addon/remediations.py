from vuln_types import SkannedVulnerabilityType



remediations_dict = {
    SkannedVulnerabilityType.COOKIE_SECURE : """\

        <p>To minimize the scope for cookie vulnerabilities on your site, limit access to cookies as much as possible. This can be done via sensible usage of the following directives of the Set-Cookie header:</p>
        <h3 id="resources-">Resources:</h3>
        <ul>
        <li><a href="https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies">MDN</a></li>
        </ul>

        """,

    SkannedVulnerabilityType.COOKIE_SAME_SITE : """\
            <p>  Setting same site cookie attirbute controls whether or not a cookie is sent with cross-site requests: that is, requests originating from a different site, including the scheme, from the site that set the cookie. This provides some protection against certain cross-site attacks, including cross-site request forgery (CSRF) attacks.</p>
            <h3 id="resources-">Resources:</h3>
            <ul>
            <li><a href="https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF#defense_in_depth_samesite_cookies">MDN</a></li>
            </ul>

        """,

    SkannedVulnerabilityType.COOKIE_HTTP_ONLY : """ \
            <p>Ensure that cookies are sent securely and aren&#39;t accessed by unintended parties or scripts in one of two ways: with the Secure attribute and the HttpOnly attribute</p>
            <p><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#security">MDN</a></p>
            """,

    SkannedVulnerabilityType.HEADER_X_CONTENT_TYPE_OPTIONS : """ \
                <p> The header allows you to avoid MIME type sniffing by specifying that the MIME types are deliberately configured.</p>
                <p><a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Content-Type-Options">MDN</a></p>
            """,
    
    SkannedVulnerabilityType.HEADER_HSTS_SET : """ \
            <p>HTTP Strict Transport Security lets a website inform the browser that it should never load the site using HTTP</p>
            <p><a href="https://developer.mozilla.org/en-US/docs/Glossary/HSTS">MDN</a></p>
            """,


    SkannedVulnerabilityType.HEADER_HSTS_SUBDOMAIN : """ \
            <p>HTTP Strict Transport Security lets a website inform the browser that it should never load the site using HTTP</p>
            <p><a href="https://developer.mozilla.org/en-US/docs/Glossary/HSTS">MDN</a></p>


            """,

    # HEADER_LEAK_X_POWERED_BY = 13
    # HEADER_LEAK_X_BACKEND_SERVER = 14
    # HEADER_LEAK_X_ASPNET_VERSION = 15

    # CONFIG_FILE_EXPOSURE_HTACCESS = 5
    SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_ENV: """ \
            <p><code>.env</code> files exposure could grant access to hidden configuation</p>
            <h3 id="resources-">Resources:</h3>
            <p><a href="https://www.zaproxy.org/docs/alerts/40034/">ZAP alert doc</a></p>
            """,
    SkannedVulnerabilityType.CONFIG_FILE_EXPOSURE_GIT: """ \
            <p>Disclosing source code could allow more targeted attacks based on implementation details.</p>
            <h3 id="resources-">Resources:</h3>
            <ul>
            <li><a href="https://www.zaproxy.org/docs/alerts/41/">Zap alert doc</a></li>
            </ul>


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
    SkannedVulnerabilityType.CORS_ALL_ALLOWED:  """ \
            <p>The origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported.</p>
            <h3 id="resources-">Resources:</h3>
            <ul>
            <li><a href="https://www.zaproxy.org/docs/alerts/40040-1/">Zap Alert doc</a></li>
            </ul>
            """,

    # CONNECT_COMPROMISED_SITE = 22

    # INFO_IP_ADDRESS = 40
    # INFO_OPEN_PORT = 41
    # INFO_SERVER_INFRA_HOSTING_PROVIDER = 42
    # INFO_SERVER_INFRA_LOAD_BALANCE = 43
    # INFO_SERVER_INFRA_TLS = 44
    # INFO_SERVER_INFRA_TLS_SAN = 44
    # INFO_SERVER_SOFTWARE = 45

    SkannedVulnerabilityType.ATTACK_SERVER_SLOWLORIS: """ \
            <p>  Allowing clients to maintain long running connections can allow malicious actors to overwhelm the server with request</p>
            <h3 id="resources-">Resources:</h3>
            <ul>
            <li><a href="https://www.cloudflare.com/learning/ddos/ddos-attack-tools/slowloris/">Cloudflare learning doc</a></li>
            </ul>
            """
}
