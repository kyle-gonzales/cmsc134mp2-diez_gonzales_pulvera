# Machine Problem 2

_By:_ \
_Diez, Reca Jane_ \
_Gonzales, Kyle Angelo_ \
_Pulvera, Eusib Vincent_

---

Our initial strategy for this Machine Problem can be broken down into three parts:

1. Create functions to implement RSA-OAEP
2. Simulate the _encrypt-sign_ and _verify-decrypt_ schemes in the console
3. Create an end-to-end encryption chat app to simulate a more realistic transmission of an encrypted message over an insecure channel

### Implementing RSA-OAEP Functionality

We decided to use Python's [`cryptography`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa) library. It contains low-level cryptographic primitives which allow us to implement security schemes using the concepts that we learned in class.

The RSA-OAEP requires several functions, which are described below:

#### `generate_keys()`

This function generates an RSA keypair (private key, public key). This function can also be used to generate a keypair for signing and verification.

Following the modular expnentiation:
$$ (m^e) \equiv \ \mod(n) $$
where $n = pq$

We selected a `public_exponent` ($e$) of 65537 (`0x10001`) as it is more secure against attacks compared to smaller exponents.
We also used the recommended `key_size` of 2048. This means that the modulus $n$ is 2048 bits long.

#### `encrypt(message, public_key)`

This function encrypts a message using RSA-OAEP encryption scheme.

In the Optimal Asymmetric Encryption Padding (OAEP) scheme, we use the `MGF1` scheme to generate a random symmetric key to scramble the message before encrypting the scrambled message and generated random key. Additionally, we use the `SHA-256` algorithm for the mask generation function.

#### `decrypt(ciphertext, private_key)`

This function decrypts a message using RSA-OAEP encryption scheme.

It also uses the same mask generation function (`MGF1`) and hash algorithm (`SHA-256`) with `encrypt()` for the OAEP scheme

#### `sign(ciphertext, signing_key)`

This function signs a message using RSA-PSS signature scheme.

It uses the Probabalistic Signature Scheme (`PSS`), which is the recommendeed padding scheme for RSA signatures. It uses the MGF1 (which uses the `SHA-256` algorithm) and the max salt length.

#### `verify(signature, message, verification_key)`

This function verifies the signature of a message using RSA-PSS signature scheme.

It also uses the same `PSS` configuration as `sign()`.

### Console Simulation

We implemented a generic function to simulate the encryption-to-decryption process:

```python
#1. Generate Keys
private_key, public_key = generate_keys()
signing_key, verification_key = generate_keys()
def simulate_message_transmission(
    message,
    private_key,
    public_key,
    signing_key,
    verification_key,
):
    #2. Sending Message
    ciphertext = encrypt(message, public_key)  #2.1 Encrypt Message
    signature = sign(ciphertext, signing_key) #2.2 Sign Message
    #---------------------------------------------------#
    #3. Receiving Message
    if verify(signature, ciphertext, verification_key): #3.1 Verify Message
        message = decrypt(ciphertext, private_key) #3.2 Decrypt Message
        print(f"The message Is: {message}")
    else:
        print("Invalid signature.")
```

In order to further contextualize this simulation, consider the following situation:

1. Alice wants to send a message to Bob.
2. Bob generates a keypair for encryption-decryption. Alice generates a keypair for signing-verification.

   _Note: Though this was not implemented in the project, Alice's verification key and Bob's public key should be publicly available. These keys would typically be distributed via a trusted Certificate Authority or Public-Key Infrastructure. Additionally, Bob's private key and Alice's signing key are kept secret. These keys are typically stored in a secure keystore (e.g. [Azure Key Vault](https://azure.microsoft.com/en-us/products/key-vault))._

Now, we wanted to simulate different scenarios:

#### Scenario 1. Alice Successfully Sends a Message to Bob

In this scenario, Alice uses Bob's public key to encrypt the message. This ensures the confidentiality of the message. Then, Alice signs the ciphertext with her signing key to guarantee the integrity and authenticity of the message. Bob receives the ciphertext and signature. He uses Alice's verification key to ensure that the ciphertext indeed belongs to her. After verifying Alice's integrity and authenticity, Bob uses his private key to decrypt the message.

The scenario is described as code below:

```python
simulate_message_transmission(
    message,
    private_key,       # Bob's private key
    public_key,        # Bob's public key
    signing_key,       # Alice's signing key
    verification_key   # Alice's verification key
)
```

Simulation output:

```
Kyle@JPC512 MINGW64 ~/OneDrive/2023-2024/CMSC 134/mp2 (main)
$ python main.py

Select Scenario:
1 - Ciphertext Sent and Received Successfully
2 - Digital Signature protects against Spoofing
3 - Encryption protects against Eavesdropping
4 - Quit
Input: 1

Input Message: Hello Bob! I can't wait for later tonight! xoxo  -Alice

Transmitting Ciphertext and Signature over channel...
Ciphertext (base-64):
WZZvAjkpjhbKZIieyfphKg4c0+WTw6DQRBVVvuSdzEUaomymzFAPi/t5BRvuFZ4ixJCAyvEVlogLD/qNpFexO9nLWLE5d+BWiToAAoXidolQ9uEgdF1rCxX9fM0RkHuDzoOZUB7WCkfSz9oyVjx89boW3WXagd4DNZA20E7pY/DzF02SfHF6V1Tflh76oZifmDykFhxT3Ay+stn9TGqraVuXoF+KyD587K3QNPXI2/JNfYB1E/xSQw8z/Zbo+dGnfEcjIVMtdW7dd8GBrcAm73Fg3Fv+c14LtU96GJHHzBin9axPONPz+XKedxe20UdqbiS3AElttuIg7s+VP52reQ==

Signature (base-64):
SVl4+YL5Ia/Pu9bD3fVgiICQBr9qcKzp0o6Jc8ZuUeYou/7BVEWido3O4ZzYnI1uVweX4283qD7KpmN6TTsQMcjJLNyG6cxm0YS351bc6SVqEZVr88LdJ9vN9LGj72y0oEf/L+YD5nQPV/WnGXbBj5RsUFEWU/Z3emthv8AWPBKHM8CORGp+zox8q2x/wOjnM1BHTBEeKzjRAYqHju9PPNSfcZQiZcFgwHYan9YmnUnC3U1psvyWC90fa4KG1Et2/0wQS9rp7XdWdvOs9uMIzfiveLOaQkKSntU46hLbQjdhpKOcyXgwRy1/k3DsFNTMyoQrDHtjoTwNTbbpR1zI0g==

The message Is: b"Hello Bob! I can't wait for later tonight! xoxo  -Alice"
```

#### Scenario 2. Mallory Sends a Message to Bob Pretending to be Alice (Spoofing)

In this scenario, Mallory uses Bob's public key to encrypt the message. But, she isn't very familiar about digital signatures so she uses her signing key to generate a signature of the message. Mallory sends the message to Bob pretending to be Alice. When Bob receives a message, supposedly from Alice, he uses Alice's verification key to verify the signature. However, Bob realizes that the signatures don't match. He realizes that the message must not be from Alice. Bob discards the message.

The scenario is described as code below:

```python
simulate_message_transmission(
    message,
    private_key,       # Bob's private key
    public_key,        # Bob's public key
    bad_signing_key,   # Mallory's signing key
    verification_key   # Alice's verification key
)
```

Simulation Output:

```
Kyle@JPC512 MINGW64 ~/OneDrive/2023-2024/CMSC 134/mp2 (main)
$ python main.py

Select Scenario:
1 - Ciphertext Sent and Received Successfully
2 - Digital Signature protects against Spoofing
3 - Encryption protects against Eavesdropping
4 - Quit
Input: 2

Input Message: Hello Bob! This is definitely Alice. My grandmother got into a very bad accident and I need you to send me $6940 immediately. I'll pay you back. I promise -Alice

Transmitting Ciphertext and Signature over channel...
Ciphertext (base-64):
gVb+C0Vh9Hv26mwmEmsqNn3N4mZ9Q4egsgp9G/BaBFJa9TyViQ1tvIkV4P4UIvt4sinMkIUuyET5wuxH1XGxe8c7hmp8gFsuWtwFhNIs2rl/I2thkOBBlKa8sNvlN9nH13MqzPD3qhhHCP+dRw5+UrZfwytQ6ROUk/0cs6PZp0MUsL4pdwcxPTmTIrJn/De9BoJjYxWGWANcscx4tNtrzve6k7QslTi42zaItYAAEPJQJCyteByWaSyMx5ac8EzAXJxuBWVRHJQ3LMSvVVDdhd5688LHXOJ4fNy/oPQkNPitpuwNnOE6sp1rFXfzPJqQpJz1o7u9CHzTd1OsMQdlaQ==

Signature (base-64):
Wwjy8L5HO6u8ymF3qDSd6AAddSTRwTDNUrw+oI0odNQVlxga5bMA7GhP7OeU2YBqfDRxp/yXZ7Pdlha7OWoJfwNuUcwmAYqYgJKA/KwJS467cbOCLhy7R97yTYU49jqaEC3Sno6rg4KRCvzZieeKnkWMwKwOqS1jtMCBMx4Uhh8nVSmprcAM77KSmCuSIaC3Q99EGAZ3sFks8bMRouGW8BA48EuP7LLMzyylR+jc9fFQSnXs/3KJls69L4KDQsAuS8dmc2MOLXmbgz9M78tbF0qCKfI0Iy2CSkTe1cYyUT6aRFpx1wWuh8TEeGmCi16oyaHT53YNCvg8iIQC+wyKTQ==

Invalid signature.
```

#### Scenario 3. Eve Intercepts the Ciphertext from Alice

In this scenario, Alice uses Bob's public key to encrypt the message. Then, Alice signs the ciphertext with her signing key. However, during transmission, Eve intercepts the ciphertext and signature from Alice. She uses Alice's verification key to verify the signature. Then, Eve tries to decrypt the message with Bob's old private key. The decryption fails and she cannot obtain the original message.

```python
simulate_message_transmission(
    message,
    bad_private_key,   # Bob's OLD private key (used by Eve)
    public_key,        # Bob's public key
    signing_key,       # Alice's signing key
    verification_key   # Alice's verification key
)
```

Simulation Output:

```
Kyle@JPC512 MINGW64 ~/OneDrive/2023-2024/CMSC 134/mp2 (main)
$ python main.py

Select Scenario:
1 - Ciphertext Sent and Received Successfully
2 - Digital Signature protects against Spoofing
3 - Encryption protects against Eavesdropping
4 - Quit
Input: 3

Input Message: Hey Bob! I can't wait for tonight. Don't worry about Eve. She'll never find out. xoxo -Alice

Transmitting Ciphertext and Signature over channel...
Ciphertext (base-64):
vQDaxjkt83zpD7wpnn+Zo6KasIPkzGsSj+fMAGRrPW43u1oBZVabG78WqdZ2XzEWJeL/czhR1+V0wd3PkXfMXsWdIJr6s1yGs0xBzddQKcWY3rKMMc9JNiPgFubHh+UfobOHbC2pAvYouQMIkHUI2OkvCHB2gKpFf/ypHiEj7YD/62DwX4bGsGZDOUrhHx/Yxbrt+SgOsxN7KHD6/uBrT7EUQmjHD+7w04E1jG2ghIrCQtNJSjMg56sGPje4EP6+uwDjRk7ZpMInH7QfnOePSE0lHfdYVhwGjIBbzrpJIrmUCD/2Pi7CFlFnZEn2/f0xe29Gr8OxJ3t5uy124phiLQ==

Signature (base-64):
UhmTB6kHYc6ef2mU1m1rhH5WlRPl48XFNC3B2kPqF0ekb0C0ZusDuYozqqFSZTMDC+YvEQitHje37DcIN1naLI/XMTtL4JLKPZ5AhWU6BM2/6OAMVes6stkiFxLSLelVW8IcbPflujceytlQGwaFrfMQA60UsHZnIHcQHLkylP0wxknKORDk1PB2hfe7lsWBA4B1QrNZUbIH1h8N7z8FyyZX//L6fZJR7qulyDrDGNV7eFUlYW/RVai3zSls4tlr1pIbtfaICPxyuWdSiqQSX3xdCQ9jey03X+UAmGILlt6x6j3wLKEHWDVqnnWAzP8avv57y+co5C0ArQY8DwKydQ==

The message Is: HA! Your Private Key is Invalid! You cannot read this message.
```

In the `cryptography` library's implementation of the [`decrypt()`](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#decryption) function, if the `private_key` is incorrect, the function throws a `ValueError` stating that the `Decryption failed`. We found this interesting because we thought that the function would just output a random array of bytes. However, we learned that this was a design choice in order to protect the user from possible attacks.

### Creating a chat app with end-to-end encryption

We didn't.

It turns out that using low-level cryptographic primitives for 

### Conclusion
