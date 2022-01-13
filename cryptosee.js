// Module imports
const forge = require('node-forge');

// Local imports
const Poly1305 = require('./chacha20-poly1305/poly1305-original');
const util = require('./util');

// Constants
const SYM_KEY_SIZE = 32; // bytes
const RSA_KEY_SIZE = 2048; // bits

/**
 * Returns an RSA Key Object of RSA_KEY_SIZE bits.
 *
 * @returns { KeyObject } - an RSA key object with public, private key and other.
 */
const generateRSAKeyPair = () => {
    const keys = forge.pki.rsa.generateKeyPair(RSA_KEY_SIZE);
    return {
        secretKey: keys.privateKey,
        pemSecretKey: forge.pki.privateKeyToPem(keys.privateKey),
        publicKey: keys.publicKey,
        pemPublicKey: forge.pki.publicKeyToPem(keys.publicKey),
    };
};

/**
 * Encapsulates or encrypts a symetric key asymetrically with a public key.
 *
 * @param bobPublicKey {PublicKey} - the receipient's public key to be used to encrypt the key.
 * @returns {Object} - an object that contains an encapsulation of a key and a SYM-KEY-SIZE symmetric key.
 */
const encapsulateSymKey = bobPublicKey => {
    let kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
    var kem = forge.kem.rsa.create(kdf1);
    let result = kem.encrypt(bobPublicKey, SYM_KEY_SIZE);

    return {
        key: result.key,
        encapsulation: result.encapsulation,
        keyHex: forge.util.bytesToHex(result.key),
        encapsulationHex: forge.util.bytesToHex(result.encapsulation),
    };
};

/**
 * Encapsulates or encrypts a symetric key asymetrically with a public key.
 *
 * @param secretKey {PrivateKey} - the receipient's secret key to be used to decrypt and retrieve the symetric key from encapsulation.
 * @param encapsulation {Bytes} - the encapsulated/encrypted symmetric key to be decapsulated/decrypted/
 * @returns {BinaryString} - a 32 byte symmetric key.
 */
const decapsulateSymKey = (secretKey, encapsulation) => {
    // decrypt encapsulated 16-byte secret key
    var kdf1 = new forge.kem.kdf1(forge.md.sha1.create());
    var kem = forge.kem.rsa.create(kdf1);
    var key = kem.decrypt(secretKey, encapsulation, SYM_KEY_SIZE);

    return key;
};

/**
 * Authenticated Decryption Function. Makes use of Chacha20-Poly1305 to encrypt a given plaintext.
 *
 * @param key {NumberArray} - 256-bit key represented as an array of integers with the decimal representation of each byte.
 * @param nonce {NumberArray} - 12 byte nonce, each cell is a decimal representation of a byte of the nonce.
 * @param plaintext {Uint8Array} - arbitrary length plaintext, each cell is the decimal representation of a byte of the plaintext.
 * @param authenticatedData {NumberArray} - arbitrary number of bytes of non-secret authenticated data, each cell is a decimal representation of a byte in the additionalData.
 * @returns {Object} { ciphertext, nonce }  - ciphertext is an array made up of the encrypted data (size of plaintext) and a mac/tag (16 bytes).
 */
const aeadEncrypt = (key, nonce, plaintext, authenticatedData) => {
    const ciphertext = Poly1305.aead_encrypt(key, nonce, plaintext, authenticatedData);
    return ciphertext;
};

/**
 * Authenticated Decryption Function. Makes use of Chacha20-Poly1305 to decrypt a given ciphertext.
 *
 * @param {Uint8Array||binaryString} key - 256-bit key represented as an array of integers with the decimal representation of each byte.
 * @param {Uint8Array} nonce - 12 byte nonce, each cell is a decimal representation of a byte of the nonce.
 * @param {Uint8Array} ciphertext - encrypted data and mac/tag.
 * @param {Uint8Array} authenticatedData - optional non-secret authenticated data.
 * @returns {NumberArray} plaintext - original message.
 */
const aeadDecrypt = (key, nonce, ciphertext, authenticatedData, mac) => {

    // https://stackoverflow.com/questions/15251879/how-to-check-if-a-variable-is-a-typed-array-in-javascript
    if (
        (key.constructor === Uint8Array || typeof(key) === 'string') &&
        nonce.constructor === Uint8Array &&
        ciphertext.constructor === Uint8Array &&
        authenticatedData.constructor === Uint8Array &&
        mac.constructor === Uint8Array
    ) {

        const plaintext = Poly1305.aead_decrypt(key, nonce, ciphertext, authenticatedData, mac);
        return plaintext;
    } else {
        console.log('Incorrect format inputs.');
        return null;
    }
};

/**
 * Function that creates a symmetric key, encapsulates it and uses it to encrypt a ciphertext
 *
 * @param inPK {pemHexString} - PEM Hexadecimal representation of the receipient's public key
 * @param inPlaintext {String} - String of the data we want to safeguard
 * @param inAuthenticatedData {String}
 *
 */
const encrypt = (inPK, inPlaintext, inAuthenticatedData) => {
    // Manipulate variables so that they are in correct format for crypto operations.
    // Convert pem key string to a forge rsa key.
    const rsaBobPK = forge.pki.publicKeyFromPem(inPK);
    // Convert plaintext encoded in UTF8 to bytes.
    const plaintext = new Uint8Array(util.decodeUTF8(inPlaintext));
    // Convert authenticated data to bytes.
    const aad = new Uint8Array(util.decodeUTF8(inAuthenticatedData));
    const keyCiphertext = encapsulateSymKey(rsaBobPK);
    const nonce = util.generateAeadNonce();
    const ciphertext = aeadEncrypt(keyCiphertext.key, nonce, plaintext, aad);
    const ret = {
        encapsulation: keyCiphertext.encapsulationHex,
        nonce: forge.util.bytesToHex(nonce),
        authenticatedData: forge.util.bytesToHex(inAuthenticatedData),
        ciphertext: forge.util.bytesToHex(ciphertext[0]),
        mac: forge.util.bytesToHex(ciphertext[1]),
    };

    // TODO: merge nonce, ciphertext and encapsulation into one hex string to further confuse attacker.
    // TODO: base64encoding may help with storage size.
    return ret;
};

/**
 *
 * @param aliceSK {pemString}
 * @param encapsulation {hexString}
 * @param ciphertext {hexString}
 * @param nonce {hexString}
 * @param authenticatedData {hexString}
 * @param mac {hexString}
 * @returns {NumberArray}
 */
const decrypt = (inSK, inEncapsulation, inCiphertext, inNonce, inAuthenticatedData, inMac) => {

    if ( typeof(inSK) === 'string' && typeof(inEncapsulation) === 'string' && typeof(inCiphertext) === 'string' && typeof(inNonce) === 'string' && typeof(inAuthenticatedData) === 'string' && typeof(inMac) === 'string') {
        // Convert SK coming in pem string format to Forge RSA Key.
        const rsaSK = forge.pki.privateKeyFromPem(inSK);

        // Convert encapsulation hex string to bytes.
        const encapsulation = util.binaryEncodingToUint8Array(forge.util.hexToBytes(inEncapsulation));

        // Convert ciphertext hex string to bytes.
        const ciphertext = util.binaryEncodingToUint8Array(forge.util.hexToBytes(inCiphertext));

        // Convert nonce hex string to bytes.
        const nonce = util.binaryEncodingToUint8Array(forge.util.hexToBytes(inNonce));

        // Convert authenticated data hex string to bytes.
        const aad = util.binaryEncodingToUint8Array(forge.util.hexToBytes(inAuthenticatedData));

        // Convert mac hex string to bytes.
        const mac = util.binaryEncodingToUint8Array(forge.util.hexToBytes(inMac));

        // Decapsulate key
        const key = decapsulateSymKey(rsaSK, encapsulation);

        const plaintext = aeadDecrypt(key, nonce, ciphertext, aad, mac);

        return plaintext;
    } else {
        console.log('Incorrect format inputs.');
        return undefined;
    }
};

module.exports = {
    generateRSAKeyPair,
    encapsulateSymKey,
    decapsulateSymKey,
    aeadEncrypt,
    aeadDecrypt,
    encrypt,
    decrypt,
};
