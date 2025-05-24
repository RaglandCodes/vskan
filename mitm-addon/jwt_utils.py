import base64
import json

valid_algs = set(
    'HS256' ,
'HS384' ,
'HS512' ,
'RS256' ,
'RS384' ,
'RS512' ,
'ES256' ,
'ES384' ,
'ES512' ,
'PS256' ,
'PS384' ,
'PS512' ,
'none' 
)
def decode_jwt(jwt):
    print()
    split_token = jwt.split('.')

    print(split_token[1])
    header_decoded = (base64.b64decode(split_token[0])).decode('utf-8')
    body_decoded = (base64.b64decode(split_token[1] + '==')).decode('utf-8')

    return {
        'header': json.loads(header_decoded),
        'payload': json.loads(body_decoded),
        'signature': split_token[-1]
    }
    

def is_valid_alg(token):
    return token['header']['alg'] in valid_algs

def is_secure_alg(token):
    if not is_valid_alg(token):
        return False

    if token['header']['alg'] == 'none':
        return False

    return True

def set_alg_to_none(token):
    token['header']['alg'] = 'None'
    token['signature'] = ''


def jwt_from_str(string):
    if string.count('.') < 2:
        return None
    
    if string.count('ey') < 2:
        return None

    

    

s = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

# sojdoio  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c osijo

print(f"{decode_jwt(s)}")
