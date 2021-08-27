// - Generating keys
// - Signing messages
// - Verifying signatures
// - Encrypting messages
// - Decrypting messages
// - Compatible with Bitcoin (optional)
// - Compatible with Ethereum (optional)
// - HD wallet (optional)
// export {};
console.log('hello');
// with keypair we can generate RSA keys.
var keypair = require('keypair');
var pair = keypair();
console.log(pair);
// libaries 
const CryptoJS = require('crypto-js');
const EthCrypto = require('eth-crypto');
//var hash = CryptoJS.MD5("Message");
var hash = CryptoJS.MD5("Message");
var hash = CryptoJS.SHA1("Message");
console.log('create a eth wallet');
var cw = require('crypto-wallets');
var ethWallet = cw.generateWallet('ETH');
console.log("Address: " + ethWallet.address);
console.log("Address:" + ethWallet.publicKey);
console.log("Private Key: " + ethWallet.privateKey);
let elliptic = require('elliptic');
let sha3 = require('js-sha3');
let ec = new elliptic.ec('secp256k1');
// let keyPair = ec.genKeyPair(); // Generate random keys
let keyPair = ec.keyFromPrivate("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a");
let privKey = keyPair.getPrivate("hex");
let pubKey = keyPair.getPublic();
console.log(`Private key: ${privKey}`);
console.log("Public key :", pubKey.encode("hex").substr(2));
console.log("Public key (compressed):", pubKey.encodeCompressed("hex"));
let msg = 'Message for signing';
let msgHash = sha3.keccak256(msg);
let signature = ec.sign(msgHash, privKey, "hex", { canonical: true });
console.log(`Msg: ${msg}`);
console.log(`Msg hash: ${msgHash}`);
console.log("Signature:", signature);
let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex")
    .getPrivate().toString(10);
let pubKeyRecovered = ec.recoverPubKey(hexToDecimal(msgHash), signature, signature.recoveryParam, "hex");
console.log("Recovered pubKey:", pubKeyRecovered.encodeCompressed("hex"));
let validSig = ec.verify(msgHash, signature, pubKeyRecovered);
console.log("Signature valid?", validSig);
//let's create an identity for two people - Shanna & Rose
//Shanna
const Shanna = EthCrypto.createIdentity();
//Rose 
const Rose = EthCrypto.createIdentity();
const secretMessage = 'He Rose i would like to sent you a message';
signature = EthCrypto.sign(Shanna.privateKey, EthCrypto.hash.keccak256(secretMessage));
const payload = {
    message: secretMessage,
    signature
};
const encrypted = EthCrypto.encryptWithPublicKey(Rose.pubKeyRecovered, // by encryping with Rose publicKey, only Rose can decrypt the payload with her privateKey
JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
);
//const encryptedObject = EthCrypto.cipher.parse(encryptedString);
// const decrypted =  EthCrypto.decryptWithPrivateKey(
//     Rose.privateKey,
//     encryptedObject
// );
console.log(secretMessage);
