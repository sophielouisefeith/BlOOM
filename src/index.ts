// - Generating keys
// - Signing messages
// - Verifying signatures
// - Encrypting messages
// - Decrypting messages
// - Compatible with Bitcoin (optional)
// - Compatible with Ethereum (optional)
// - HD wallet (optional)



//******************** ****************************************/
//             Libaries                                       //
//*********************************************** ************/

import sha3 from "js-sha3";
import elliptic from "elliptic";
let ec = new elliptic.ec('secp256k1');
import cw from "crypto-wallets";
import crypto from "crypto";
import eccrypto from "eccrypto";


console.log('create an (ETH) wallet');



//******************** ****************************************/
//             GENERATE KEYS       with elliptic              //
//*********************************************** ************/
//Generate random keys
let keyPair = ec.genKeyPair(); 
let privKey = keyPair.getPrivate("hex");
let pubKey = keyPair.getPublic();


console.log(`Private key: ${privKey}`);
console.log("Public key :", pubKey.encode("hex", true).substr(2));
console.log("Public key (compressed):",pubKey.encodeCompressed("hex"));


//******************** ****************************************/
//             SIGN A MESSAGE                                  //
//*********************************************** ************/
//Message encryption and signing is done by a private key
const msg = 'He this message comes from Rose, needs to be signed, verified and encrypted';
// hash your message before signing 
var hash = sha3.keccak256(msg);
// we sign with a private key
const privKeyb = Buffer.from(privKey, "utf-8");
let signature = ec.sign(hash, privKeyb, "hex", {canonical: true});
console.log(`Msg: ${msg}`);
console.log(`Msg hash: ${hash}`);
console.log("Signature:", signature);

let hexToDecimal = (x) => ec.keyFromPrivate(x, "hex").getPrivate().toString(10);
let pubKeyRecovered = ec.recoverPubKey(hexToDecimal(hash), signature,signature.recoveryParam, "hex");
console.log("Recovered pubKey:",pubKeyRecovered.encodeCompressed("hex"));

//******************** ****************************************/
//             Verify signing                                  //
//*********************************************** ************/
let validSig = ec.verify(hash, signature, pubKeyRecovered);
console.log("Signature valid?", validSig);



//******************** ****************************************/
//             encrypt and decryp a message                   //
//*********************************************** ************/
//let encryptdata = msg;
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    // The standard secure default length for RSA keys is 2048 bits 
    modulusLength: 2048,
  }); 
const encryptMessage = crypto.publicEncrypt({key: publicKey,},Buffer.from(msg));
console.log("encypted data: ", encryptMessage.toString("base64"));
const decryptedMessage = crypto.privateDecrypt({key: privateKey,},encryptMessage);
console.log("decrypted data: ", decryptedMessage.toString());













//******************** ****************************************/
//              USING IES encrypting and decrypting a message //
//*********************************************** ************/
// var privateKeyA = eccrypto.generatePrivate();
// var publicKeyA = eccrypto.getPublic(privateKeyA);
// var privateKeyB = eccrypto.generatePrivate();
// var publicKeyB = eccrypto.getPublic(privateKeyB);

// // Encrypting the message for B.
// eccrypto.encrypt(publicKeyB, Buffer.from("msg to b")).then(function(encrypted) {
//     // B decrypting the message.
//     eccrypto.decrypt(privateKeyB, encrypted).then(function(plaintext) {
//       console.log("Message to part B:", plaintext.toString());
//     });
//   });
  
//   // Encrypting the message for A.
//   eccrypto.encrypt(publicKeyA, Buffer.from("msg to a")).then(function(encrypted) {
//     // A decrypting the message.
//     eccrypto.decrypt(privateKeyA, encrypted).then(function(plaintext) {
//       console.log("Message to part A:", plaintext.toString());
//     });
//   });



//******************** ****************************************/
//              USING AES //
//*********************************************** ************/





//let's create an identity for two people - Shanna & Rose
//Shanna
//const Shanna = EthCrypto.createIdentity();
//Rose 
// const Rose = EthCrypto.createIdentity();
// const secretMessage = 'He Rose i would like to sent you a message';

// signature = EthCrypto.sign(
//     Shanna.privateKey,
//     EthCrypto.hash.keccak256(secretMessage)
// );
// const payload = {
//     message: secretMessage,
//     signature
// };
// const encrypted =  EthCrypto.encryptWithPublicKey(

//     Rose.publicKey, // by encryping with Rose publicKey, only Rose can decrypt the payload with her privateKey
//     JSON.stringify(payload) // we have to stringify the payload before we can encrypt it
// );



//const encryptedObject = EthCrypto.cipher.parse(encryptedString);

// const decrypted =  EthCrypto.decryptWithPrivateKey(
//     Rose.privateKey,
//     encryptedObject
// );



// console.log(secretMessage);




//******************** ****************************************/
//              TWEETNACL //
//*********************************************** ************/





// with keypair we can generate RSA keys.
//var keypair = require('keypair');
//var pair = keypair();
//console.log(pair, "he public and private key");

// libaries 

// import CryptoJS from 'crypto-js';
//import EthCrypto = require('eth-crypto');
// import crypto from "crypto";
// var eccrypto = require("eccrypto");
//let elliptic = require('elliptic');
//let sha3 = require('js-sha3');

//var eccrypto = require("eccrypto");



// var hash = CryptoJS.MD5("Message");
// var hash = CryptoJS.SHA1("Message");
//var cw = require('crypto-wallets');






//import chalk from 'chalk';

//console.log(chalk.blue('Hello world!'));
//console.log("First we generate a wallet from the ethwallet libary");

// var ethWallet = cw.generateWallet('ETH');

// console.log('create an address');
// console.log("Address: " + ethWallet.address);
// console.log('create an private key');
// console.log("Private Key: " + ethWallet.privateKey);


//SHA-256 is one of the four variants in the SHA-2 set. 
//It isn't as widely used as SHA-1, though it appears 
//to provide much better security.

// var hash = CryptoJS.SHA256("hash:");
// console.log("hash", hash);
