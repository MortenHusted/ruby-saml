import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from lxml import etree # Using lxml for easier namespace handling

# --- Configuration ---
PRIVATE_KEY_FILE = 'test/certificates/ruby-saml.key'
ENCRYPTED_XML_FILE = 'test/responses/generated_unsigned_message_aes256gcm_sha256_rsa_oaep_encrypted_signed_assertion.xml'
# This password might be None if your key isn't password protected
PRIVATE_KEY_PASSWORD = None # Or b'your_password' if it is

# XML Namespaces used in the SAML file
NS = {
    'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
    'xenc': 'http://www.w3.org/2001/04/xmlenc#',
    'ds': 'http://www.w3.org/2000/09/xmldsig#'
}
# XPath to find the CipherValue within the EncryptedKey
ENCRYPTED_KEY_CIPHERVALUE_XPATH = ".//saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue"
# --- End Configuration ---

def main():
    # Load the private key
    try:
        with open(PRIVATE_KEY_FILE, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=PRIVATE_KEY_PASSWORD,
                backend=default_backend()
            )
        print(f"Successfully loaded private key from: {PRIVATE_KEY_FILE}")
    except Exception as e:
        print(f"Error loading private key: {e}")
        return

    # Parse the XML and find the encrypted key's CipherValue
    try:
        tree = etree.parse(ENCRYPTED_XML_FILE)
        # Use the namespaces argument in findall or xpath
        results = tree.xpath(ENCRYPTED_KEY_CIPHERVALUE_XPATH, namespaces=NS)
        if not results:
             print(f"Error: Could not find EncryptedKey CipherValue using XPath in {ENCRYPTED_XML_FILE}")
             print(f"XPath used: {ENCRYPTED_KEY_CIPHERVALUE_XPATH}")
             return

        encrypted_key_b64 = results[0].text.strip()
        encrypted_key_bytes = base64.b64decode(encrypted_key_b64)
        print(f"Successfully extracted encrypted key CipherValue (len: {len(encrypted_key_bytes)})")

    except Exception as e:
        print(f"Error parsing XML or extracting CipherValue: {e}")
        return

    # Define the OAEP padding
    oaep_padding = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()), # MGF1 with SHA256
        algorithm=hashes.SHA256(),                  # OAEP hash SHA256
        label=None                                  # XML Encryption typically uses no label
    )

    # Attempt decryption
    try:
        decrypted_key = private_key.decrypt(
            encrypted_key_bytes,
            oaep_padding
        )
        print("\n--- Decryption Result ---")
        print(f"Decryption successful!")
        print(f"Decrypted key length: {len(decrypted_key)} bytes")
        if len(decrypted_key) == 32:
            print("SUCCESS: Decrypted key is 32 bytes (correct for AES-256).")
        else:
            print(f"WARNING: Decrypted key is NOT 32 bytes. Expected 32, got {len(decrypted_key)}.")
        # print(f"Decrypted key (hex): {decrypted_key.hex()}") # Uncomment to see the key bytes

    except Exception as e:
        print("\n--- Decryption Failed ---")
        print(f"Error during decryption: {e}")
        print("This likely indicates the encryption in generate_fixture.rb was incorrect or incompatible.")

if __name__ == "__main__":
    main()
