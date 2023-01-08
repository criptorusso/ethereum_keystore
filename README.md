<H1>PRIVATE KEY RECOVERY FROM ETHEREUM KEYSTORE</H1>

script to retrieve private key from files contained in keystore knowing the associated passphrase.

According to what has been investigated so far, the process followed for the storage of the key pair in both Ethereum and Quorum follows the following encryption scheme:

![alt text "blocks-kdf-aes"](keystore.drawio.png)

Both Ethereum and Quorum store the keys in the <b>Keystore</b> directory and all the required parameters are contained in the json files, which are stored inside this directory. The keystore contains the data necessary to rebuild the private key associated with the public address contained in the json files.

Each json file in the directory has the information associated with each public address. The file contains the parameters to generate a kdf derived key which in turn is used to generate the private key at the output of the aes-128-ctr encryption module. In order to regenerate the key, it is necessary to have the <b>passphrase</b> that the client (or the application internally) has used to build the address.

It should be noted that the ciphertext required as input parameter to the AES module corresponds to the encrypted Ethereum private key.

<li>Required parameters for the KDF module: {klen,r,n,p,salt} and the passphrase.
<li>Required parameters for the AES-128-CTR module: {iv, ciphertext, kdf_key}.

<H2>MAC Verification</H2>
Once the derived key (kdf) has been determined, the MAC is verified taking into account that a concatenation of the 16 least significant bytes of the kdf in hexadecimal must be carried out with the ciphertext in hexadecimal (concatenation_hex = kdf_hex[32:64] + ciphertext_hex ). The result of the concatenation is fingerprinted using the standard keccak_256 (keccak_256(concatenacion_bytes)).


<H2>Private Key Decryption</H2>
the following parameters are passed to the AES-128-CTR module:
  <li>initialization vector to integer (iv_int = int(iv,16))
  <li>16 most significant bytes of the kdf in bytes (kdf_key_bytes)
  <li>ciphertext in bytes (ciphertext_bytes)
    
 the result obtained is converted to hexadecimal (decrypted_priv_key_hex).
