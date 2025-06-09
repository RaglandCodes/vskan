# TODO: To learn:

# - TLS Hussein Nasser playlist: https://www.youtube.com/watch?v=AlE5X1NlHgg&list=PLQnljOFTspQW4yHuqp_Opv853-G_wAiH-
# - https://youtu.be/0TLDTodL7Lc?si=srFQbykDVZwGAo8C
# - https://youtu.be/86cQJ0MMses?si=UOthC_vZWpEaQhvw
# - https://youtu.be/s22eJ1eVLTU?si=UMQyCVwRd0FdOwsf
# - https://youtu.be/j9QmMEWmcfo?si=UTeNzIhnaNmAntqJ
# - https://youtu.be/kAaIYRJoJkc?si=v-Xw7gjPSNC5hRaJ
# - https://youtu.be/T4Df5_cojAs?si=-mmK32bNxs-zsfeY
# - https://youtu.be/vsXMMT2CqqE?si=gOI9U0jaMAY6mKkW
# - https://youtu.be/0ctat6RBrFo?si=EQCcsrG2F4szW5W4
# - https://youtu.be/x_I6Qc35PuQ?si=oUzw4icQ-rdA_mZY


import logging
import ssl
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID, PublicKeyAlgorithmOID
import datetime

cert_data = ssl.get_server_certificate(('juice-shop-p0va.onrender.com', 443))
#print(cert_data.encode())


def decode_pem(cert_data):
    cert = x509.load_pem_x509_certificate(cert_data)
    print(cert.serial_number)
    print(cert.not_valid_before_utc)
    print(cert.not_valid_after_utc)
    print(cert.issuer)
    print(cert.subject)
    print(cert.signature_hash_algorithm)
    print(cert.signature)


def is_signature_valid(cert_data) -> tuple[bool, str]:
    return False, 'not yet implemented'

def is_strong_public_key_algo(cert_data) -> tuple[bool, str]:
    cert = x509.load_pem_x509_certificate(cert_data)
    alg = cert.public_key_algorithm_oid
    logging.info(f"p key oid: {alg}")


def is_strong_sign_algo(cert_data) -> tuple[bool, str]:
    cert = x509.load_pem_x509_certificate(cert_data)
    alg = cert.signature_hash_algorithm

    weak_algos = {
                "md5",
                "sha1",
        }
    # Check algorithm

    print(f"alg is {alg}")
    print(f"alg name is is {alg.name}")

    if not alg:
        return False, 'Certificate not sighed'

    if alg.name.lower() in weak_algos:
        return False, f"Using weak signing algorithm : {alg.name}"
        
    return True, f"Cert signed using : {alg.name}"



def is_short_validity_duration(cert_data) -> tuple[bool, str]:
    cert = x509.load_pem_x509_certificate(cert_data)

    # Check if currently valid
    start_date = cert.not_valid_before_utc

    # Check if duration is not too long

    expiry_date = cert.not_valid_after_utc



    return False, 'not yet implemented'

def is_from_trusted_issuer(cert_data) -> tuple[bool, str]:
    return False, 'not yet implemented'

def is_domain_in_san(cert_data) -> tuple[bool, str]:
    cert = x509.load_pem_x509_certificate(cert_data)
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)

    dns_names_from_san = ext.value.get_values_for_type(x509.DNSName)

    if(not dns_names_from_san):
        return True, f"Has domain names in SAN : {dns_names_from_san}"

    return False, "Has no domain names in SAN extension"


#decode_pem(cert_data.encode())

def skan_domain_ssl(flow) -> list[tuple[bool, str]]:
    flow_referrrer = flow.request.headers.get('Referer')
    flow_domain = urlparse(flow_referrrer).netloc

    logging.info(f"Doing SSL skanning for domain {flow_domain}")
    cert_data = ssl.get_server_certificate((flow_domain, 443))
    
    return [
        is_domain_in_san(cert_data.encode()),
        # is_strong_public_key_algo(cert_data.encode()),
        is_strong_sign_algo(cert_data.encode())
    ]