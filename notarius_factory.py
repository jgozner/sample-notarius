import base64
import binascii
import hashlib
import json
import logging
import os

import jwt
import requests

from dotenv import load_dotenv
load_dotenv()
class NotariusFactory:
    """
    Factory class for interacting with the Notarius API.

    This class provides methods for generating tokens, signing data, retrieving certificate chains,
    and other operations related to the Notarius API.

    Attributes:
        JWT_ALGORITHM (str): The algorithm used for encoding JWT tokens. Defaults to "HS256".
        NOTARIUS_SECRET_KEY (str): The secret key used by Notarius. Defaults to an empty string.
        VERSION (str): The version of the Notarius API. Defaults to "1".
        OID_SHA256 (str): The OID for SHA-256. Defaults to an empty string.

    Args:
        None

    """

    JWT_ALGORITHM = os.environ.get("NOTARIUS_JWT_ALGORITHM", "HS256")
    NOTARIUS_SECRET_KEY = os.environ.get("NOTARIUS_SECRET_KEY", "")
    VERSION = os.environ.get("NOTARIUS_VERSION", "1")
    OID_SHA256 = os.environ.get("NOTARIUS_OID_SHA256", "")

    def __init__(self):
        """
        Initializes a new instance of the NotariusFactory class.

        Args:
            None

        Returns:
            None

        """
        # Root Certificate Authority (Root Certificate): Self-signed, top of the chain, inherently trusted.
        # Issuing Certificate Authority (Intermediate Certificate): Issued by the Root CA, used to sign End Entity Certificates.
        # End Entity Certificate: Issued by the Intermediate CA, used by end users or devices for secure communication.
        self.nonce = os.urandom(16).hex()
        self.endpoint = os.environ.get("NOTARIUS_API_URL", "")
        self.certs = self.get_certificate_chain()
        self.end_entity_cert = base64.b64decode(self.certs[0]) if self.certs else None
        self.issuing_cert_authority = (
            base64.b64decode(self.certs[1]) if self.certs else None
        )
        self.root_cert_authority = (
            base64.b64decode(self.certs[2]) if self.certs else None
        )
        self.signer_cert = self.end_entity_cert
        self.chain_certs = [self.issuing_cert_authority, self.root_cert_authority]

    def build_digest_info(self, info_to_be_signed="this is a digestinfo asn.1 object"):
        """
        Builds a DigestInfo ASN.1 object.

        Args:
            info_to_be_signed (str): The information to be signed. Defaults to "this is a digestinfo asn.1 object".

        Returns:
            str: The Base64-encoded DigestInfo ASN.1 object.

        """
        # 1. Return SHA-256 hash of the data (info_to_be_signed)
        h = hashlib.sha256()
        # Convert info_to_be_signed to a string before encoding
        h.update(str(info_to_be_signed).encode())

        # 2. Concatenate the OID for SHA-256 with the hash
        digest_info = self.OID_SHA256 + h.hexdigest()

        # 3. Convert the result from hexadecimal to binary
        binary_digest_info = binascii.unhexlify(digest_info)

        # 4. Convert the result from binary to Base64
        base64_digest_info = base64.b64encode(binary_digest_info)

        # 5. Return the Base64-encoded DigestInfo ASN.1 object
        return base64_digest_info.decode()

    def generate_token(self, digest_info):
        """
        Generates a token for the given digest information.

        Args:
            digest_info (bytearray): The digest information to be included in the token.

        Returns:
            str: The generated token.

        """
        payload = {
            "digestInfo": digest_info,
            "nonce": self.nonce,
            "version": self.VERSION,
        }

        return self.encode(payload)

    def sign_data(self, data):
        """
        Signs the provided data using the sign URL obtained from `get_sign_url()`.

        Args:
            data: The data to be signed.

        Returns:
            The signature obtained from the response, or None if an error occurred during the request or JSON decoding.

        """
        request_url = self.get_sign_url()

        try:
            response = requests.post(request_url, data=data)
            response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
        except requests.RequestException as e:
            logging.error(f"Request to {request_url} failed: {e}")
            return None

        try:
            resp = response.json()

            return resp.get("nonce"), resp.get("sig")
        except json.JSONDecodeError:
            logging.error("Failed to decode JSON response")
            return None

    def get_certificate_chain(self):
        """
        Calls the actual certificate chain function.

        Returns:
            list: A list of Base64-encoded X.509 certificates (DER format) representing the certificate chain.
                    The chain has the following order:
                    1. End Entity Certificate
                    2. Issuing Certificate Authority
                    3. Root Certificate Authority

                    Returns None if there was an error in making the request or decoding the JSON response.

        """
        request_url = self.get_cert_url()

        try:
            response = requests.get(request_url)
            response.raise_for_status()  # Raises a HTTPError if the status is 4xx, 5xx
        except requests.RequestException as e:
            logging.error(f"Request to {request_url} failed: {e}")
            return None

        try:
            resp = response.json()
            return resp.get("certs")
        except json.JSONDecodeError:
            logging.error("Failed to decode JSON response")
            return None

    def get_secret(self):
        """
        Returns the secret key used by Notarius.

        Returns:
            str: The secret key used by Notarius.

        """
        return self.NOTARIUS_SECRET_KEY

    def encode(self, payload):
        """
        Encodes the given payload into a JWT token using the secret key.

        Args:
            payload (dict): The payload to be encoded.

        Returns:
            str: The encoded JWT token.

        """
        secret = self.get_secret()
        token = jwt.encode(payload, secret, algorithm=self.JWT_ALGORITHM)
        return token

    def get_sign_url(self):
        """
        Returns the URL for signing documents.

        Returns:
            str: The URL for signing documents.

        """
        return f"{self.endpoint}/signatures"

    def get_cert_url(self):
        """
        Returns the URL for retrieving certificates.

        Returns:
            str: The URL for retrieving certificates.

        """
        return f"{self.endpoint}/certs"

    def get_signer_cert(self):
        return self.signer_cert

    def get_chain_certs(self):
        return self.chain_certs

    def get_rsa_sign_result(self, data):

        digest_info = self.build_digest_info(data)
        jws = self.generate_token(digest_info)
        nonce, sig = self.sign_data(jws)

        if nonce != self.nonce:
            print(f"sig_result: {nonce}\nself.none: {self.nonce}")
            raise Exception("Nonce mismatch")

        return base64.b64decode(sig) if sig else None
