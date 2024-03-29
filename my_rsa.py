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


def simulate_message_transmission(
    message: str,
    private_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    signing_key: rsa.RSAPrivateKey,
    verification_key: rsa.RSAPublicKey,
):
    ciphertext = encrypt(message, public_key)
    signature = sign(ciphertext, signing_key)

    print("Transmitting Ciphertext and Signature over channel...")
    print(f"Ciphertext (base-64):\n{base64.b64encode(ciphertext).decode()}\n")
    print(f"Signature (base-64):\n{base64.b64encode(signature).decode()}\n")

    if verify(signature, ciphertext, verification_key):
        message = decrypt(ciphertext, private_key)
        print(f"The message Is: {message}")
    else:
        print("Invalid signature.")


def main(load_key_from_file=True):

    private_key = None
    public_key = None

    signing_key = None
    verification_key = None

    if load_key_from_file:
        private_key, public_key = load_key(PRIVATE_KEY_PATH)
        signing_key, verification_key = load_key(SIGNING_KEY_PATH)
    else:
        private_key, public_key = generate_keys()
        signing_key, verification_key = generate_keys()

        private_key_pem, public_key_pem = serialize_keys(private_key, public_key)
        signing_key_pem, verification_key_pem = serialize_keys(
            signing_key, verification_key
        )

        save_key(private_key_pem, path=PRIVATE_KEY_PATH)
        save_key(signing_key_pem, path=SIGNING_KEY_PATH)

    bad_private_key, bad_public_key = generate_keys()
    bad_signing_key, bad_verification_key = generate_keys()

    while True:
        print()
        print("Select Scenario: ")
        print("1 - Ciphertext Sent and Received Successfully")
        print("2 - Digital Signature protects against Spoofing")
        print("3 - Encryption protects against Eavesdropping")
        print("4 - Quit")

        op = input("Input: ")
        print()

        if op not in list("1234"):
            print("Invalid Operation...")
            break
        elif op == "4":
            print("Exiting...")
            break

        message = input("Input Message: ")
        print()

        if op == "1":
            simulate_message_transmission(
                message, private_key, public_key, signing_key, verification_key
            )
        elif op == "2":
            simulate_message_transmission(
                message, private_key, public_key, bad_signing_key, verification_key
            )
        elif op == "3":
            simulate_message_transmission(
                message, bad_private_key, public_key, signing_key, verification_key
            )


if __name__ == "__main__":
    main()


######################################

# message = b"hello"

# private_key, public_key = generate_keys()
# signing_key, verification_key = generate_keys()

# ciphertext = encrypt(message, public_key)
# signature = sign(ciphertext, signing_key)

# private_key_pem, public_key_pem = serialize_keys(private_key, public_key)

# save_key(private_key_pem)

# sk = load_key()


# if verify(signature, ciphertext, verification_key):
#     message = decrypt(ciphertext, sk)
#     print(f"The message is: {message}")
# else:
#     print("Invalid signature")
