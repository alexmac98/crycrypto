from datetime import datetime
from email import message
from re import L
from typing import Union
from cryptography.exceptions import (
    InvalidSignature
)
from cryptography.hazmat.primitives import (
    serialization,
    hashes,
)
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    padding,
    dh
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_and_store_private_key( public_exponent: int=65537, 
                                    key_size: int=2048, 
                                    path: str="./private_key.pem",
                                    encoding: serialization.Encoding=serialization.Encoding.PEM,
                                    format: serialization.PrivateFormat=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm: Union[serialization.BestAvailableEncryption, serialization.KeySerializationEncryption]=serialization.BestAvailableEncryption,
                                    password: Union[str, bytes]="password"):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size
    )

    if type(password) == str:
        password = bytes(password, encoding="utf-8")

    with open(path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=encoding,
            format=format,
            encryption_algorithm=encryption_algorithm(password)
        ))

def load_private_key(private_key_path: str, password: Union[str, bytes], encoding: serialization.Encoding):
    if type(password) == str:
        password = bytes(password, encoding="utf-8")
    
    with open(private_key_path, "rb") as f:
        private_key_bytes = f.read()

        if encoding == serialization.Encoding.DER:
            private_key = serialization.load_der_private_key(data=private_key_bytes, password=password)
        
        elif encoding == serialization.Encoding.PEM:
            private_key = serialization.load_pem_private_key(data=private_key_bytes, password=password)

        elif encoding == serialization.Encoding.OpenSSH:
            private_key = serialization.load_ssh_private_key(data=private_key_bytes, password=password)

        return private_key


def generate_and_store_certificate_signing_request( private_key: bytes, 
                                                    signing_hash_algorithm: hashes.HashAlgorithm,
                                                    path: str,
                                                    encoding: serialization.Encoding,
                                                    country: str, 
                                                    province: str, 
                                                    locality: str, 
                                                    organization_name: str, 
                                                    common_name: str,
                                                    sites: list[str]=[]):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(
        attributes=[
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
            x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    ))

    if len(sites) > 0:
        csr = csr.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(site) for site in sites]
            ),
            critical=False
        )

    csr = csr.sign(private_key=private_key, algorithm=signing_hash_algorithm)

    with open(path, "wb") as f:
        f.write(csr.public_bytes(encoding))


def generate_and_store_self_signed_certificate( private_key: bytes, 
                                                signing_hash_algorithm: hashes.HashAlgorithm,
                                                path: str,
                                                encoding: serialization.Encoding,
                                                country: str, 
                                                province: str, 
                                                locality: str, 
                                                organization_name: str, 
                                                common_name: str,
                                                not_valid_before: datetime,
                                                not_valid_after: datetime, 
                                                sites: list[str]=[]):
    subject = issuer = x509.Name(attributes=[
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, province),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    )

    if len(sites) > 0:
        cert = cert.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(site) for site in sites]
            ),
            critical=False
        )

    cert = cert.sign(private_key=private_key, algorithm=signing_hash_algorithm)

    with open(path, "wb") as f:
        f.write(cert.public_bytes(encoding))


def generate_signature(private_key: bytes, message: Union[str, bytes], algorithm: hashes.HashAlgorithm):
    if type(message) is not bytes:
        message = bytes(message, encoding="utf-8")

    return private_key.sign(
        message, 
        padding.PSS(
            mgf=padding.MGF1(algorithm=algorithm),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm
    )

def verify_signature(public_key: bytes, signature: bytes, message: Union[str, bytes], algorithm: hashes.HashAlgorithm):
    if type(message) is not bytes:
        message = bytes(message, encoding="utf-8")

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(algorithm=algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            algorithm
        )

        return True
    except InvalidSignature:
        return False

def encrypt(public_key: bytes, message: Union[str, bytes], algorithm: hashes.HashAlgorithm):
    if type(message) is str:
        message = bytes(message, encoding="utf-8")
    
    return public_key.encrypt(  message,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=algorithm),
                                    algorithm=algorithm, 
                                    label=None)
                                )

def decrypt(private_key: bytes, ciphertext: bytes, algorithm: hashes.HashAlgorithm):
    
    return private_key.decrypt( ciphertext,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=algorithm),
                                    algorithm=algorithm, 
                                    label=None)
                                )


def generate_diffie_hellman_ephemeral():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    shared_key = private_key.exchange(public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data"
    ).derive(shared_key)

    return private_key, public_key, shared_key, derived_key

    
    
if __name__ == '__main__':
    private_key = load_private_key(private_key_path="./private_key.pem", password="password", encoding=serialization.Encoding.PEM)
    public_key = private_key.public_key()

    signature = generate_signature(private_key=private_key, message="a very secret message", algorithm=hashes.SHA256())
    
    valid_signature = verify_signature(public_key=public_key, signature=signature, message="a very secret message", algorithm=hashes.SHA256())
    print(f"The signature is {signature}")
    print(f"Is it verified? {valid_signature}")

    ciphertext = encrypt(public_key=public_key, message="a very secret message", algorithm=hashes.SHA256())

    print(f"Ciphertext: {ciphertext}")

    message_decrypted = decrypt(private_key=private_key, ciphertext=ciphertext, algorithm=hashes.SHA256())
    
    print(f"Decrypted: {message_decrypted}")

    priv_key, pub_key, shared_key, derived_key = generate_diffie_hellman_ephemeral()

    print()
    print("--- DiffieHellman Ephemeral---")
    print(f"--> Generated private key: {priv_key}")
    print(f"--> Generated public key: {pub_key}")
    print(f"--> Generated shared key: {shared_key}")
    print(f"--> Generated derived key: {derived_key}")



