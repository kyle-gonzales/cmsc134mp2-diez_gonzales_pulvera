import base64

from cryptography import exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils

SIGNING_KEY_PATH = "./verification_key.pem"
PRIVATE_KEY_PATH = "./private_key.pem"


def generate_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    return private_key, public_key


def serialize_keys(
    private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey
) -> tuple:
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # print(private_key_pem)
    return private_key_pem, public_key_pem


def encrypt(message: str, public_key: rsa.RSAPublicKey) -> bytes:
    ciphertext = public_key.encrypt(
        str.encode(message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext


def decrypt(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    try:
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except ValueError:
        return "HA! Your Private Key is Invalid! You cannot read this message."


def sign(ciphertext: bytes, signing_key: rsa.RSAPrivateKey) -> bytes:
    return signing_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )


def verify(signature: bytes, message: str, verification_key: rsa.RSAPublicKey):
    try:
        verification_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except exceptions.InvalidSignature:
        return False


def save_key(private_key, path="./private_key.pem"):
    with open(path, "wb") as f:
        f.write(private_key)


def load_key(path="./private_key.pem"):
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
        return private_key, private_key.public_key()
