from cryptography.hazmat.primitives.asymmetric import rsa
from dataclasses import dataclass
from my_rsa import generate_keys


class User:
    def __init__(self, user_name: str) -> None:
        self.user_name: str = user_name
        self.private_key, self.public_key = generate_keys()
        self.signing_key, self.verification_key = generate_keys()
        



