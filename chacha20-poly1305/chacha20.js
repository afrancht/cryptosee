/* chacha20 - 256 bits */

// Written in 2014 by Devi Mandiri. Public domain.
//
// Implementation derived from chacha-ref.c version 20080118
// See for details: http://cr.yp.to/chacha/chacha-20080128.pdf

// Modified by Alex Franch Tapia 28/11/2019
// Mitigating risks:
// Reusing a nonce:
//  Nonce must be changed after every change in the plaintext. Ie after every new encryption. As if the old plaintext with the same nonce were to be revealed, breaking the stream is easier.

/**
* Unsigned 8 bit to 32 bit little endian.
* @param x
* @param i
* @returns {number}
* @constructor
*/
const U8TO32_LE = (x, i) => {
  return x[i] | (x[i + 1] << 8) | (x[i + 2] << 16) | (x[i + 3] << 24);
};

/**
* Usingned 32 to 8 bit little endian.
* @param x
* @param i
* @param u
* @constructor
*/
const U32TO8_LE = (x, i, u) => {
  x[i] = u;
  u >>>= 8;
  x[i + 1] = u;
  u >>>= 8;
  x[i + 2] = u;
  u >>>= 8;
  x[i + 3] = u;
};

/**
 *
 * @param v
 * @param {number} c - number of bits to rotate.
 */
const ROTATE = (v, c)  => {
  return (v << c) | (v >>> (32 - c));
};

// export default Chacha20;
/**
*
* @param key - a 256-bit key, treated as a concatenation of 8 32-bit little-endian integers.
* @param nonce - a 96-bit nonce treated as a concatenation of 3 32-bit little-endian integers.
*  @param counter - a 32-bit clock count parameter, treated as a 32-bit little-endian integer.
 * @TODO add tests for the initialisation matrix.
 * @TODO: add conditional validation before the values are used.
 */
const setupVector = (key, nonce, counter) => {
 /*
  * This will be our 4 x 4 512-bit matrix. Each cell is 32-bits made up of 8 nibbles (4-bits).
  *   [ 0,  1,  2,  3,
  *     4,  5,  6,  7,
  *     8,  9, 10, 11,
  *    12, 13, 14, 15 ]
  *
  *   [ cccccccc,  cccccccc,  cccccccc,  cccccccc,
  *     kkkkkkkk,  kkkkkkkk,  kkkkkkkk,  kkkkkkkk,
  *     kkkkkkkk,  kkkkkkkk,  kkkkkkkk,  kkkkkkkk,
  *     bbbbbbbb,  nnnnnnnn,  nnnnnnnn,  nnnnnnnn ]
  *  Where c = constant (4x16 bits), k = key (8x16 bits) taken from the 256-bit key, b = blockcount (1x16 bits), n = nonce (3x16 bits)
  */
  const initialMatrix = new Uint32Array(16);

  // https://tools.ietf.org/html/draft-irtf-cfrg-chacha20-poly1305-01#section-2.3
  initialMatrix[0] = 1634760805;
  initialMatrix[1] = 857760878;
  initialMatrix[2] = 2036477234;
  initialMatrix[3] = 1797285236;
  initialMatrix[4] = U8TO32_LE(key, 0);
  initialMatrix[5] = U8TO32_LE(key, 4);
  initialMatrix[6] = U8TO32_LE(key, 8);
  initialMatrix[7] = U8TO32_LE(key, 12);
  initialMatrix[8] = U8TO32_LE(key, 16);
  initialMatrix[9] = U8TO32_LE(key, 20);
  initialMatrix[10] = U8TO32_LE(key, 24);
  initialMatrix[11] = U8TO32_LE(key, 28);
  initialMatrix[12] = counter;
  initialMatrix[13] = U8TO32_LE(nonce, 0);
  initialMatrix[14] = U8TO32_LE(nonce, 4);
  initialMatrix[15] = U8TO32_LE(nonce, 8);

  return initialMatrix;
};

/**
 * Performs a ChaCha round over four 32-bit words.
 *
 * @param {bytes} x - the ChaCha20 Matrix containing the 32-bit words (DWORDS)
 * @param {int} a - index of "a" in a ChaCha20 round.
 * @param {int} b - index of "b" in a ChaCha20 round.
 * @param {int} c - index of "c" in a ChaCha20 round.
 * @param {int} d - index of "d" in a ChaCha20 round.
 */
const quarterRound = (x, a, b, c, d) => {
  x[a] += x[b];
  x[d] = ROTATE(x[d] ^ x[a], 16);
  x[c] += x[d];
  x[b] = ROTATE(x[b] ^ x[c], 12);
  x[a] += x[b];
  x[d] = ROTATE(x[d] ^ x[a], 8);
  x[c] += x[d];
  x[b] = ROTATE(x[b] ^ x[c], 7);
};

const encrypt = (initialMatrix, dst, src, len) => {
  var x = new Uint32Array(16);
  var output = new Uint8Array(64);
  var i, dpos = 0, spos = 0;

  while (len > 0) {
    // Copy initialMatrix
    for (i = 16; i--;) x[i] = initialMatrix[i];
    for (i = 20; i > 0; i -= 2) {
      quarterRound(x, 0, 4, 8, 12);
      quarterRound(x, 1, 5, 9, 13);
      quarterRound(x, 2, 6, 10, 14);
      quarterRound(x, 3, 7, 11, 15);
      quarterRound(x, 0, 5, 10, 15);
      quarterRound(x, 1, 6, 11, 12);
      quarterRound(x, 2, 7, 8, 13);
      quarterRound(x, 3, 4, 9, 14);
    }
    for (i = 16; i--;) x[i] += initialMatrix[i];
    for (i = 16; i--;) U32TO8_LE(output, 4 * i, x[i]);

    initialMatrix[12] += 1;
    if (!initialMatrix[12]) {
      initialMatrix[13] += 1;
    }
    if (len <= 64) {
      for (i = len; i--;) {
        dst[i + dpos] = src[i + spos] ^ output[i];
      }
      return;
    }
    for (i = 64; i--;) {
      dst[i + dpos] = src[i + spos] ^ output[i];
    }
    len -= 64;
    spos += 64;
    dpos += 64;
  }
};

const keystream = (dst, len) => {
  for (var i = 0; i < len; ++i) dst[i] = 0;
  encrypt(dst, dst, len);
};

module.exports = {
  setupVector,
  quarterRound,
  encrypt,
  keystream,
};
