const forge = require('node-forge');

// Local Imports
const util = require('../util');
const Poly1305 = require('../chacha20-poly1305/poly1305-original');
const Chacha20 = require('../chacha20-poly1305/chacha20-original');

// Constants
const bytesEqual = util.bytesEqual;
const decodeUTF8 = util.decodeUTF8;
const fromHex = util.fromHex;

describe('Chacha20',() => {
  test("Block Test", () => {
    let testVectors = [
      {
        key: '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
        nonce: '00:00:00:09:00:00:00:4a:00:00:00:00',
        counter: 1,
        expected: '10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4' +
          'c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e' +
          'd2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2' +
          'b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e'
      },
      {
        key: '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
        nonce: '00 00 00 00 00 00 00 00 00 00 00 00',
        counter: 1,
        expected: '9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d' +
          'cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed' +
          '29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5' +
          '31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f'
      },
      {
        key: '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01',
        nonce: '00 00 00 00 00 00 00 00 00 00 00 00',
        counter: 1,
        expected: '3a eb 52 24 ec f8 49 92 9b 9d 82 8d b1 ce d4 dd' +
          '83 20 25 e8 01 8b 81 60 b8 22 84 f3 c9 49 aa 5a' +
          '8e ca 00 bb b4 a7 3b da d1 92 b5 c4 2f 73 f2 fd' +
          '4e 27 36 44 c8 b3 61 25 a6 4a dd eb 00 6c 13 a0'
      },
      {
        key: '00 ff 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
        nonce: '00 00 00 00 00 00 00 00 00 00 00 00',
        counter: 2,
        expected: '72 d5 4d fb f1 2e c4 4b 36 26 92 df 94 13 7f 32' +
          '8f ea 8d a7 39 90 26 5e c1 bb be a1 ae 9a f0 ca' +
          '13 b2 5a a2 6c b4 a6 48 cb 9b 9d 1b e6 5b 2c 09' +
          '24 a6 6c 54 d5 45 ec 1b 73 74 f4 87 2e 99 f0 96'
      },
      {
        key: '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
        nonce: '00 00 00 00 00 00 00 00 00 00 00 02',
        counter: 0,
        expected: 'c2 c6 4d 37 8c d5 36 37 4a e2 04 b9 ef 93 3f cd' +
          '1a 8b 22 88 b3 df a4 96 72 ab 76 5b 54 ee 27 c7' +
          '8a 97 0e 0e 95 5c 14 f3 a8 8e 74 1b 97 c2 86 f7' +
          '5f 8f c2 99 e8 14 83 62 fa 19 8a 39 53 1b ed 6d'
      }
    ];

    for (let i = 0; i < testVectors.length; i++) {
      let key = util.fromHex(testVectors[i].key),
        nonce = util.fromHex(testVectors[i].nonce),
        counter = testVectors[i].counter,
        expected = util.fromHex(testVectors[i].expected),
        len = expected.length,
        output = new Uint8Array(len);

      let ctx = new Chacha20.Chacha20(key, nonce, counter);

      ctx.keystream(output, len);

      expect(util.bytesEqual(output, expected)).toStrictEqual(1);
    }

  });

  test("Encryption Test", () => {
    let testVectors = [
      {
        key: '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
        nonce: '00 00 00 00 00 00 00 00 00 00 00 00',
        counter: 0,
        plaintext: '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' +
          '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00',
        expected: '76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28' +
          'bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7' +
          'da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37' +
          '6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86'
      },
      {
        key: '00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f',
        nonce: '00:00:00:00:00:00:00:4a:00:00:00:00',
        counter: 1,
        plaintext: '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c' +
          '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73' +
          '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63' +
          '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f' +
          '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20' +
          '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73' +
          '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69' +
          '74 2e',
        expected: '6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81' +
          'e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b' +
          'f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57' +
          '16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8' +
          '07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e' +
          '52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36' +
          '5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42' +
          '87 4d'
      },
      {
        key: '1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0' +
          '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
        nonce: '00 00 00 00 00 00 00 00 00 00 00 02',
        counter: 42,
        plaintext: '27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61' +
          '6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f' +
          '76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64' +
          '20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77' +
          '61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77' +
          '65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65' +
          '73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20' +
          '72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e',
        expected: '62 e6 34 7f 95 ed 87 a4 5f fa e7 42 6f 27 a1 df' +
          '5f b6 91 10 04 4c 0d 73 11 8e ff a9 5b 01 e5 cf' +
          '16 6d 3d f2 d7 21 ca f9 b2 1e 5f b1 4c 61 68 71' +
          'fd 84 c5 4f 9d 65 b2 83 19 6c 7f e4 f6 05 53 eb' +
          'f3 9c 64 02 c4 22 34 e3 2a 35 6b 3e 76 43 12 a6' +
          '1a 55 32 05 57 16 ea d6 96 25 68 f8 7d 3f 3f 77' +
          '04 c6 a8 d1 bc d1 bf 4d 50 d6 15 4b 6d a7 31 b1' +
          '87 b5 8d fd 72 8a fa 36 75 7a 79 7a c1 88 d1'
      },
    ];

    for (let i = 0; i < testVectors.length; i++) {
      let key = util.fromHex(testVectors[i].key),
        nonce = util.fromHex(testVectors[i].nonce),
        counter = testVectors[i].counter,
        plaintext = util.fromHex(testVectors[i].plaintext),
        expected = util.fromHex(testVectors[i].expected),
        len = plaintext.length,
        buf = new Uint8Array(len),
        output = new Uint8Array(len);

      let ctx = new Chacha20.Chacha20(key, nonce, counter);

      ctx.keystream(buf, len);

      for (let j = 0; j < len; j++) {
        output[j] = buf[j] ^ plaintext[j];
      }
      expect(util.bytesEqual(output, expected)).toStrictEqual(1);
    }
  });

})

describe('Poly1305 Tests', () => {
    test('Poly Test', () => {
      let testVectors = [
        {
          input: '27 54 77 61 73 20 62 72 69 6c 6c 69 67 2c 20 61' +
            '6e 64 20 74 68 65 20 73 6c 69 74 68 79 20 74 6f' +
            '76 65 73 0a 44 69 64 20 67 79 72 65 20 61 6e 64' +
            '20 67 69 6d 62 6c 65 20 69 6e 20 74 68 65 20 77' +
            '61 62 65 3a 0a 41 6c 6c 20 6d 69 6d 73 79 20 77' +
            '65 72 65 20 74 68 65 20 62 6f 72 6f 67 6f 76 65' +
            '73 2c 0a 41 6e 64 20 74 68 65 20 6d 6f 6d 65 20' +
            '72 61 74 68 73 20 6f 75 74 67 72 61 62 65 2e',
          key: '1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0' +
            '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
          tag: '45 41 66 9a 7e aa ee 61 e7 08 dc 7c bc c5 eb 62'
        },
        {
          input: '48656c6c6f20776f726c6421',
          key: '746869732069732033322d62797465206b657920666f7220506f6c7931333035',
          tag: 'a6f745008f81c916a20dcc74eef2b2f0'
        }
      ];

      for (let i = 0; i < testVectors.length; i++) {
        let input = util.fromHex(testVectors[i].input);
        let key = util.fromHex(testVectors[i].key);
      let expected = util.fromHex(testVectors[i].tag);

        let out = Poly1305.poly1305_auth(input, input.length, key);

        expect(Poly1305.poly1305_verify(expected,out)).toStrictEqual(1);
      }
    })
  });

describe('Aead Tests', () => {
    test('Test 1', () => {
  let testVectors = [
    {
      key:        '80 81 82 83 84 85 86 87 88 89 8a 8b 8c 8d 8e 8f'+
                  '90 91 92 93 94 95 96 97 98 99 9a 9b 9c 9d 9e 9f',
      nonce:      '07 00 00 00 40 41 42 43 44 45 46 47',
      plaintext:  '4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c'+
                  '65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73'+
                  '73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63'+
                  '6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f'+
                  '6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20'+
                  '74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73'+
                  '63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69'+
                  '74 2e',
      aad:        '50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7',
      ciphertext: 'd3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2'+
                  'a4 ad ed 51 29 6e 08 fe a9 e2 b5 a7 36 ee 62 d6'+
                  '3d be a4 5e 8c a9 67 12 82 fa fb 69 da 92 72 8b'+
                  '1a 71 de 0a 9e 06 0b 29 05 d6 a5 b6 7e cd 3b 36'+
                  '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58'+
                  'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc'+
                  '3f f4 de f0 8e 4b 7a 9d e5 76 d2 65 86 ce c6 4b'+
                  '61 16',
      tag:        '1a:e1:0b:59:4f:09:e2:6a:7e:90:2e:cb:d0:60:06:91'
    }
  ];

  for (let i = 0; i < testVectors.length; i++) {
    let key = util.fromHex(testVectors[i].key),
        nonce = util.fromHex(testVectors[i].nonce),
        plaintext = util.fromHex(testVectors[i].plaintext),
        aad = util.fromHex(testVectors[i].aad),
        ciphertext = util.fromHex(testVectors[i].ciphertext),
        tag = util.fromHex(testVectors[i].tag);

    let ret = Poly1305.aead_encrypt(key, nonce, plaintext, aad);

    expect((util.bytesEqual(ret[0], ciphertext) !== 1) || (util.bytesEqual(ret[1], tag) !== 1)).toBeFalsy();

    ret = Poly1305.aead_decrypt(key, nonce, ret[0], aad, ret[1]);

    expect(ret).toBeTruthy();

    expect(util.bytesEqual(ret,plaintext)).toStrictEqual(1);
  }


    })

    test("Test 2", () => {
      let testVectors = [
    {
      key:        '1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0'+
        '47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0',
      nonce:      '00 00 00 00 01 02 03 04 05 06 07 08',
      plaintext:  'Internet-Drafts are draft documents valid for a maximum of six months and may be updated, replaced, or obsoleted by other documents at any time. It is inappropriate to use Internet-Drafts as reference material or to cite them other than as /“work in progress./”',
      aad:        'f3 33 88 86 00 00 00 00 00 00 4e 91',
      ciphertext: '64 a0 86 15 75 86 1a f4 60 f0 62 c7 9b e6 43 bd'+
        '5e 80 5c fd 34 5c f3 89 f1 08 67 0a c7 6c 8c b2'+
        '4c 6c fc 18 75 5d 43 ee a0 9e e9 4e 38 2d 26 b0'+
        'bd b7 b7 3c 32 1b 01 00 d4 f0 3b 7f 35 58 94 cf'+
        '33 2f 83 0e 71 0b 97 ce 98 c8 a8 4a bd 0b 94 81'+
        '14 ad 17 6e 00 8d 33 bd 60 f9 82 b1 ff 37 c8 55'+
        '97 97 a0 6e f4 f0 ef 61 c1 86 32 4e 2b 35 06 38'+
        '36 06 90 7b 6a 7c 02 b0 f9 f6 15 7b 53 c8 67 e4'+
        'b9 16 6c 76 7b 80 4d 46 a5 9b 52 16 cd e7 a4 e9'+
        '90 40 c5 a4 04 33 22 5e e2 82 a1 b0 a0 6c 52 3e'+
        'af 45 34 d7 f8 3f a1 15 5b 00 47 71 8c bc 54 6a'+
        '0d 07 2b 04 b3 56 4e ea 1b 42 22 73 f5 48 27 1a'+
        '0b b2 31 60 53 fa 76 99 19 55 eb d6 31 59 43 4e'+
        'ce bb 4e 46 6d ae 5a 10 73 a6 72 76 27 09 7a 10'+
        '49 e6 17 d9 1d 36 10 94 fa 68 f0 ff 77 98 71 30'+
        '30 5b ea ba 2e da 04 df 99 7b 71 4d 6c 6f 2c 29'+
        'a6 ad 5c b4 02 2b 02 70 9b',
      tag:        'ee ad 9d 67 89 0c bb 22 39 23 36 fe a1 85 1f 38'
    }
  ];

      for (let i = 0; i < testVectors.length; i++) {
        let key = util.fromHex(testVectors[i].key),
          nonce = util.fromHex(testVectors[i].nonce),
          plaintext = util.decodeUTF8(testVectors[i].plaintext),
          aad = util.fromHex(testVectors[i].aad),
          ciphertext = util.fromHex(testVectors[i].ciphertext),
          tag = util.fromHex(testVectors[i].tag);
        let ret = Poly1305.aead_encrypt(key, nonce, plaintext, aad);

        expect((util.bytesEqual(ret[0], ciphertext) !== 1) || (util.bytesEqual(ret[1], tag) !== 1)).toBeFalsy();

        ret = Poly1305.aead_decrypt(key, nonce, ret[0], aad, ret[1]);

        expect(ret).toBeTruthy();

        expect(util.bytesEqual(ret,plaintext)).toStrictEqual(1);
      }
    })
  });