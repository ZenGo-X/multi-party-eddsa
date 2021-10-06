from nacl.encoding import HexEncoder
from nacl.signing import SigningKey



def main():
    # Generate a new random signing key
    signing_key = SigningKey('48ab347b2846f96b7bcd00bf985c52b83b92415c5c914bc1f3b09e186cf2b14f', encoder=HexEncoder)

    # Sign a message with the signing key
    signed_hex = signing_key.sign(b"Attack at Dawn", encoder=HexEncoder)

    # Obtain the verify key for a given signing key
    verify_key = signing_key.verify_key

    # Serialize the verify key to send it to a third party
    verify_key_hex = verify_key.encode(encoder=HexEncoder)
    print(verify_key_hex)


if __name__ == '__main__':
    main()
