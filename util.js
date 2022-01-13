// Module imports
/* eslint-disable */
const forge = require('node-forge');
// const UTIL = forge.util;
const PKI = forge.pki;

const NONCE_SIZE = 12; // bytes

/**
 * Generates a Uint8Array (TypedArray) of NONCE_LENGTH bytes in length (each cell is 8 bits) from the BrowserAPI.
 * @param {Int} len number of bytes of random data needed
 * @returns {Uint8Array} l random bytes
 */
const randUint8ArrayBytes = len => {
    // TODO: Be able to understand in which environment you are and get random bytes.
    try {
        // if (typeof window === 'undefined' && || window === null) {
        return binaryEncodingToUint8Array(forge.random.getBytesSync(len));
        // } else {
        //   return window.crypto.getRandomValues(new Uint8Array(len));
        // }
    } catch (e) {
        throw new Error(e.message);
    }
};

/**
 * Generates a random bytes for the AEAD nonce.
 * @returns {Uint8Array} - random Uint8Array of size NONCE_SIZE bytes.
 */
const generateAeadNonce = () => randUint8ArrayBytes(NONCE_SIZE);

/**
 * Converts a Uint8Array into its hexadecimal form.
 * @param uint8array {Uint8Array} - Bytes to be transformed.
 * @returns {string} - Hexadecimal representation of the bytes inputted.
 */
const uint8ArrayToHex = uint8array => {
    return Buffer.from(uint8array).toString('hex');
};

/**
 * Converts a binary encoded string to a typed array.
 *
 * @param binaryString - a binary encoded string.
 */
const binaryEncodingToUint8Array = bStr => {
    var len = bStr.length,
        u8_array = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        u8_array[i] = bStr.charCodeAt(i);
    }
    return u8_array;
};

/**
 * Function that converts a hexadecimal string into an array of bytes, treating every string character as a nibble.
 * @param {String} h - hexadecimal string.
 * @returns {[Number]} byteIntArray - An array of integers containing the decimal representation of every hexadecimal byte per cell..
 */
// Use for key, nonce, plaintext,
const fromHex = h => {
    // Replace with '' everything which isn't a a-z and 0-9 (case sensitive)
    h = h.replace(/([^0-9a-f])/g, '');

    const byteIntArray = [];
    const len = h.length;
    let byteString = '';

    // Construct our byteString from our hexadecimal string.
    for (let i = 0; i < len; i += 2) {
        byteString = h[i];

        // If we are done and don't have a hex string to fill in with, pad with zeros.
        if (i + 1 >= len || typeof h[i + 1] === 'undefined') {
            byteString += '0';

            // Append our nibble string to form our byte.
        } else {
            byteString += h[i + 1];
        }

        // Convert our byteString into an integer taking into account it's in base 16 (hex) and push it to the output variable.
        byteIntArray.push(parseInt(byteString, 16));
    }

    return byteIntArray;
};

/**
 * Compares two parameters to see if their bytes are equal.
 * @param a - first object to be checked.
 * @param b - second object to be checked.
 * @returns {number} - returns 1 if they are the same, else 0.
 */
const bytesEqual = (a, b) => {
    var dif = 0;
    if (a.length !== b.length) return 0;
    for (var i = 0; i < a.length; i++) {
        dif |= a[i] ^ b[i];
    }
    dif = (dif - 1) >>> 31;
    return dif & 1;
};

/**
 * Converts a UTF8 encoded String into its Uin8Array representation (used for plaintext and aad).
 * @param {String} s - to be converted.
 * @returns {Uint8Array} output - TypedArray representation of string.
 */
const decodeUTF8 = s => {
    let i;
    let d = unescape(encodeURIComponent(s));
    let b = new Uint8Array(d.length);
    for (i = 0; i < d.length; i++) b[i] = d.charCodeAt(i);
    return b;
};

// TODO: Add tests for these util functions.

/**
 * Converts a pem string into an RSA forge public key.
 * @param pemPublicKey {String} - PEM format public key.
 * @returns rsaPublicKey {Object} - forge RSA public key.
 */
const publicKeyFromPem = pemPublicKey => PKI.publicKeyFromPem(pemPublicKey);

/**
 * Converts an RSA forge public key to a pem string.
 * @param publicKey
 * @returns {String}
 */
const publicKeyToPem = publicKey => PKI.publicKeyToPem(publicKey);

/**
 * Converts a pem string into an RSA forge secret key.
 * @param publicKey
 * @returns {String}
 */
const secretKeyFromPem = pemSecretKey => PKI.privateKeyFromPem(pemSecretKey);

/**
 * Converts an RSA forge private key to a pem string.
 * @param publicKey
 * @returns {String}
 */
const secretKeyToPem = secretKey => PKI.privateKeyToPem(secretKey);

module.exports = {
    randUint8ArrayBytes,
    generateAeadNonce,
    uint8ArrayToHex,
    binaryEncodingToUint8Array,
    fromHex,
    bytesEqual,
    decodeUTF8,
    publicKeyFromPem,
    publicKeyToPem,
    secretKeyFromPem,
    secretKeyToPem,
};
