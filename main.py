from my_rsa import *


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
