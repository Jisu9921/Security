from Crypto.PublicKey import RSA

PUBLIC_KEY = 1
PRIVATE_KEY = 2


def get_rsa_key(key_type):
    key_file = open('mykey.pem', 'rb')
    try:
        key = RSA.importKey(key_file.read())
    except IndexError:
        key = RSA.generate(2048)
        new_file = open('mykey.pem', 'wb')
        new_file.write(key.exportKey('PEM'))
        new_file.close()
    finally:
        if key_type is 1:
            public_key = key.publickey()
            return public_key
        elif key_type is 2:
            return key


def en_crypto(crypto_var):
    public_key = get_rsa_key(PUBLIC_KEY)
    rsa_security = public_key.encrypt(crypto_var.encode(), 32)
    return rsa_security


def de_crypto(rsa_security_var):
    private_key = get_rsa_key(PRIVATE_KEY)
    original_var = private_key.decrypt(rsa_security_var)
    return original_var


