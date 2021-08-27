# Crypto Wallet )

###### tags: crypto wallet

> How to write good specs?
> 

## :memo: Where do I start?

NOTE:
Public-key cryptography, or asymmetric cryptography, is any cryptographic system that uses pairs of keys: public keys which may be disseminated widely, and private keys which are known only to the owner. This accomplishes two functions: authentication, where the public key verifies that a holder of the paired private key sent the message, and encryption, where only the paired private key holder can decrypt the message encrypted with the public key.

### The requirments:

- [x] Generating keys
- [ ] Signing messages
- [ ] Verifying signatures
- [ ] Encrypting messages
- [ ] Decrypting messages

:rocket: 

firt choose a libary such as crypto js. 
npm install crypto-js

## Generating keys: 

### Private Keys:
Message encryption and signing is done by a private key. The private keys are always kept secret by their owner, just like passwords. In the server infrastructure, private key usually stay in an encrypted and protected keystore. In the blockchain systems the private keys usually stay in specific software or hardware apps or devices called "crypto wallets", which store securely a set of private keys.

### Public Keys

Message decryption and signature verification is done by the public key. Public keys are by design public information (not a secret). It is mathematically infeasible to calculate the private key from its corresponding public key.
In many systems the public key is encapsulated in a digital certificate, which binds certain identity (e.g. person or Internet domain name) to certain public key. In blockchain systems public keys are usually published as parts of the blockchain transactions to help identify who has signed each transaction. In systems like PGP and SSH the public key is downloaded from the server once (after manual user verification) and is remembered for further use.







hash with : var hash = CryptoJS.SHA256("hash:");

how to generate keys 

- [x] 
- [ ] 
- [ ] 
- [ ] 
- [ ]
- [x] 

### Signing a message 
SHA-3 Cryptographic Hash Algorithms


“Digital Signatures provide a digital fingerprint that allows a recipient to authenticate the message sender and its integrity.”



### Veryfinging signatures 


Authenticated Encryption: Encrypt / Decrypt Messages
using MAC
Another scenario to use MAC codes is for authenticated encryption: when we encrypt a message and we want to
be sure the decryption password is correct and the decrypted message is the same like the original message
before encryption.
First, we derive a key from the password. We can use this key for the MAC calculation algorithm (directly or
hashed for better security).
Next, we encrypt the message using the derived key and store the ciphertext in the output.
Finally, we calculate the MAC code using the derived key and the original message and we append it to the
output.
When we decrypt the encrypted message (ciphertext + MAC), we proceed as follows:
First, we derive a key from the password, entered by the user. It might be the correct password or wrong. We
shall find out later.
Next, we decrypt the message using the derived key. It might be the original message or incorrect message
(depends on the password entered).
Finally, we calculate a MAC code using the derived key + the decrypted message.
If the calculated MAC code matches the MAC code in the encrypted message, the password is correct.
Otherwise, it will be proven that the decrypted message is not the original message and this means that the
password is incorrect
Some authenticated encryption algorithms (such as AES-GCM and ChaCha20-Poly1305) integrate the MAC
calculation into the encryption algorithm and the MAC verification into the decryption algorithm. We shall learn more
about these algorithms later.
The MAC is stored along with the ciphertext and it does not reveal the password or the original message. Storing the
MAC code, visible to anyone is safe, and after decryption, we know whether the message is the original one or not
(wrong password).

### Encrypting messages


### Decrypting messages

