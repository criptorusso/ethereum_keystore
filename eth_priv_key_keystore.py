# Get Ethereum private key from keystore and comparing with a test vector data
# created by: Antonio Russoniello

import json
import pyaes
import scrypt
import sha3
from eth_keys import keys

def keystore_file_to_json(file_name):
    # get json file from keystore with the key data    
    input_data = open(file_name, 'r')
    json_data = input_data.read()
    key_data = json.loads(json_data)
    return key_data

def test_vector_file_json(file_name):
    # get json file with the data to execute and verify the test   
    input_data = open(file_name, 'r')
    json_data = input_data.read()
    test_vector_data = json.loads(json_data)
    return test_vector_data    

def get_kdf_params():
    kdf_params = keystore_params["crypto"]["kdfparams"]    
    print("**************************************")
    print("KDF data from the Keystore")    
    for key in kdf_params:
        print(key, ": ", kdf_params[key])
    return kdf_params

def list_aes_params(aes_params):
    print("**************************************")    
    print("AES data from Keystore")
    print("cipher: ", aes_params["cipher"])
    print("iv: ", aes_params["cipherparams"]["iv"])
    print("ciphertext: ", aes_params["ciphertext"])


def get_kdf_key():
    password = test_data["passphrase"]    
    salt = bytes.fromhex(kdf_params["salt"])
    length=kdf_params["dklen"]
    n=kdf_params["n"]
    r=kdf_params["r"]
    p=kdf_params["p"]    
    secretKey = scrypt.hash(password, salt, n, r, p, length) # 256 bit key
    print("derived key KDF: ", secretKey.hex())
    if (secretKey.hex() == test_data["derivedKey"]):
        print("derived key OK")
    else:
        print("error in derived key")
    return secretKey

def aes_decrypt(kdf_key_hex):
    list_aes_params(aes_params)    
    iv = aes_params["cipherparams"]["iv"]
    ciphertext = aes_params["ciphertext"]
    iv_int = int(iv,16)
    kdf_key = kdf_key_hex[0:32] # the 16 most significant bytes are taken
    print("16 most significant bytes of kdf derived key: ", kdf_key)
    kdf_key_bytes = bytes.fromhex(kdf_key)
    aes = pyaes.AESModeOfOperationCTR(kdf_key_bytes, pyaes.Counter(iv_int)) # kdf_key must be in bytes
    decrypted_priv_key = aes.decrypt(bytes.fromhex(ciphertext))
    decrypted_priv_key_hex = decrypted_priv_key.hex()
    if (decrypted_priv_key_hex == test_data["secret"]):
        print("key decrypted OK")
    else:
        print("error in key decrypted")
    print("**************************************")
    return decrypted_priv_key_hex

def compare_MAC(kdf_k_hex):
    mac_hex = keystore_params["crypto"]["mac"]
    ciphertext_hex = aes_params["ciphertext"]    
    print("**************************************")
    print("Comparing MAC")
    print("MAC: ", mac_hex)
    left_bytes = kdf_k_hex[32:64] # extract the least significant 16 bytes
    concatenation = bytes.fromhex(left_bytes + ciphertext_hex) # the second least significant 16 bytes of the kdf_key
    print("16 least significant bytes of the kdf: ", left_bytes)
    print("Encrypted private key (ciphertext): ", ciphertext_hex)       
    print("kdf + ciphertext concatenation:", concatenation.hex())
    get_mac = sha3.keccak_256(concatenation).hexdigest()
    print("MAC result: ", get_mac)
    if (mac_hex == get_mac):
        print("Comparing MAC keccak256 OK")
    else:
        print("error in MAC")

def get_pubKey(privKey):
    print("**************************************")
    print("Getting Public Key")
    pk = keys.PrivateKey(bytes.fromhex(privKey))
    pubAddr= pk.public_key.to_address()[2:]
    print("Public key: ",pubAddr)
    if (pubAddr == test_data["address"]):
        print("public key OK")
    else:
        print("error in public key")
    return


##########################################################################
##################   GET PRIVATE KEY FROM KEYSTORE   #####################
##########################################################################

# FIRST STEP: get kdf derived key to decrypt private key in aes
keystore_params = keystore_file_to_json("keystore_file.json") # get json files formatted data in keystore
test_data = test_vector_file_json("Test Vectors.json")   # get json files data from test vector
kdf_params = get_kdf_params()
kdf_key = get_kdf_key()           # get derived key
kdf_key_hex = kdf_key.hex()       # derived key in hexadecimal

# SECOND STEP: verify consistency using the MAC
aes_params = keystore_params["crypto"]
compare_MAC(kdf_key_hex)

# THIRD STEP: decrypt the AES private key
priv_key = aes_decrypt(kdf_key_hex)
print("Private key: ", priv_key)
get_pubKey(priv_key)
