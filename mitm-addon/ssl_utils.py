# TODO: To learn:

# - https://youtu.be/r1nJT63BFQ0?si=1-syXPSATz9uAY0j
# - https://youtu.be/0TLDTodL7Lc?si=srFQbykDVZwGAo8C
# - https://youtu.be/86cQJ0MMses?si=UOthC_vZWpEaQhvw
# - https://youtu.be/s22eJ1eVLTU?si=UMQyCVwRd0FdOwsf
# - https://youtu.be/j9QmMEWmcfo?si=UTeNzIhnaNmAntqJ
# - https://youtu.be/kAaIYRJoJkc?si=v-Xw7gjPSNC5hRaJ
# - https://youtu.be/T4Df5_cojAs?si=-mmK32bNxs-zsfeY
# - https://youtu.be/vsXMMT2CqqE?si=gOI9U0jaMAY6mKkW
# - https://youtu.be/0ctat6RBrFo?si=EQCcsrG2F4szW5W4
# - https://youtu.be/x_I6Qc35PuQ?si=oUzw4icQ-rdA_mZY


import ssl

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID, ExtensionOID
import datetime

cert_data = ssl.get_server_certificate(('google.com', 443))
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

def is_strong_sign_algo(cert_data) -> tuple[bool, str]:
    # Check algorithm

    # Check public key size
    return False, 'not yet implemented'



def is_short_validity_duration(cert_data) -> tuple[bool, str]:
    # Check if currently valid

    # Check if duration is not too long

    return False, 'not yet implemented'

def is_from_trusted_issuer(cert_data) -> tuple[bool, str]:
    return False, 'not yet implemented'

def is_domain_in_san(cert_data) -> tuple[bool, str]:
    return False, 'not yet implemented'


decode_pem(cert_data.encode())