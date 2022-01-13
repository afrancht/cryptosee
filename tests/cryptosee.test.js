// Module imports
const forge = require('node-forge');

// Local Imports
const cryptosee = require('../cryptosee');
const util = require('../util');

const encapsulateSymKey = cryptosee.encapsulateSymKey;
const decapsulateSymKey = cryptosee.decapsulateSymKey;
const encrypt = cryptosee.encrypt;
const decrypt = cryptosee.decrypt;

// Tests
describe('RSA Tests', () => {
  test('Generate 2048bit RSA Key', () => {
  // TODO: Check that the output is 2048bits.
  // TODO: Check that the Pem and non pem output is equivalent.
  const keyPair = cryptosee.generateRSAKeyPair();
  expect(keyPair).toHaveProperty('secretKey');

  expect(keyPair.secretKey).toHaveProperty('n');
  expect(keyPair.secretKey).toHaveProperty('e');
  expect(keyPair.secretKey).toHaveProperty('d');
  expect(keyPair.secretKey).toHaveProperty('p');
  expect(keyPair.secretKey).toHaveProperty('q');
  expect(keyPair.secretKey).toHaveProperty('dP');
  expect(keyPair.secretKey).toHaveProperty('dQ');
  expect(keyPair.secretKey).toHaveProperty('qInv');
  expect(keyPair.secretKey).toHaveProperty('decrypt');
  expect(keyPair.secretKey).toHaveProperty('sign');

  expect(keyPair).toHaveProperty('publicKey');

  expect(keyPair.publicKey).toHaveProperty('n');
  expect(keyPair.publicKey).toHaveProperty('e');
  expect(keyPair.publicKey).toHaveProperty('encrypt');
  expect(keyPair.publicKey).toHaveProperty('verify');

  expect(keyPair).toHaveProperty('pemSecretKey');
  expect(keyPair).toHaveProperty('pemPublicKey');

});

  test('Encapsualtes a Key', () => {
    const testVector = {
    alice: {
        publicKey: '-----BEGIN PUBLIC KEY-----\n' +
          'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwJj/0qn+Bh/2dkPLiSPt\n' +
          'MlgRZTWlXCA+7j1/I20bN7wL2q2PIWVG7/c6TxjjlUM9JePeFPlWUZHIig98Pypy\n' +
          'c2paCDH4KHAxdJ03UFVsdskQEqjudrztCwFhorXdXIr6RDI99vOLd9Zw/Vpt9OkE\n' +
          'sorJ0uQILIsfm0Hd6Bp4tC9LJAuRRDuO/o4zxZV/ybeXpICm7y71R+yx1UrBZc8m\n' +
          'M1cF/pFNofzGvDTjpZKFsR+/7X1OlyfiPIK894Uww0JdEnYLEIPW+/pvil4/2Lt7\n' +
          'pMJGVcYWliIowTUtdd0M8+YpOJkpriKGuPvmQl+W4HNZXxe4pdtV7x3Q48CB7rfQ\n' +
          'XwIDAQAB\n' +
          '-----END PUBLIC KEY-----',
        privateKey: '-----BEGIN RSA PRIVATE KEY-----\n' +
          'MIIEowIBAAKCAQEAwJj/0qn+Bh/2dkPLiSPtMlgRZTWlXCA+7j1/I20bN7wL2q2P\n' +
          'IWVG7/c6TxjjlUM9JePeFPlWUZHIig98Pypyc2paCDH4KHAxdJ03UFVsdskQEqju\n' +
          'drztCwFhorXdXIr6RDI99vOLd9Zw/Vpt9OkEsorJ0uQILIsfm0Hd6Bp4tC9LJAuR\n' +
          'RDuO/o4zxZV/ybeXpICm7y71R+yx1UrBZc8mM1cF/pFNofzGvDTjpZKFsR+/7X1O\n' +
          'lyfiPIK894Uww0JdEnYLEIPW+/pvil4/2Lt7pMJGVcYWliIowTUtdd0M8+YpOJkp\n' +
          'riKGuPvmQl+W4HNZXxe4pdtV7x3Q48CB7rfQXwIDAQABAoIBAQCZhVvmgLqMB05e\n' +
          'VwwW9RxN1QWIt4poNQv0u/BsPLxFYQ/R8Cb3Z9Nz1I4WHrDKeh5z5X9RGK9Ftf80\n' +
          'jcNsVlmExnGdtrcpBMVnPyqoTm93AC5fsWjkHRSWgTNij7Uz31Q+qA3cm6XAkJ7g\n' +
          'VQTxBA1KhHb8M+iQGRXInGhWa0Nr3CTYPh7WIujQbo/V5UANMswZThot8y2OUnqg\n' +
          'Q9pjJlIkoWSmixSVGnjWS0yG+J1hJeoUGb4ItqIWAK2SWNg4OC3LkN2euwmQb2Df\n' +
          'gwxbRmRfarMkw8N4QRdYIu5ixp4VImbGTNcXTz1ShnlTrQfOJbPbWFxraFWhdHtH\n' +
          'UUW0PPwBAoGBAOQ2SWvne0MF9YruVyyNViQ5zBQfqTgp5GA8Km8ZzrEQg1PkhTEI\n' +
          '3GjA5DsPHXsSfpqijUo9OzaJ1rs8BCnEHfhVaCwqiy/23qrgGyRkHgI3rrU90/ol\n' +
          'qhoymtnqVqrD1M4pc7wzHqR0xIKWwVskj2KcyrZJXr/ImkuQIllctkB/AoGBANgM\n' +
          'jtU1ifcyRJsE7hXUtlIIzZF/PwmOoBJPWjZZfABpiHUj7Y6F69gi+AterzLLdlvQ\n' +
          'rolRbwJaw4Lu1FKTfKaVEq/bG9ERiArYWLCEIFaBn6sMivcO/H0lBCTxbhK0GniT\n' +
          'eueKWhv3M6Vnh4Rw8f0u6d1BkdRvsliTnXeoBoAhAoGAVKfKrqts7xzrzADD97Pq\n' +
          'S3/hM2nXRQ1NOWG4QARrxwUgImO4AMuPr5A2Wa4uunPO4SABl5OFPqL9M/F8fd3R\n' +
          'XEiaXx/dCArk6LA/gU1eUGZFedgYpUeJhTRWexXR1oDUlTGNTDgOWuUx7FtuGJhE\n' +
          'VEljbSFkc3I/wl4ST+HzfZMCgYBMdu1ago9o4O6tGuqU6Wr5z8nJ1ApgfI0kzdb0\n' +
          '42ji0HcOVn/ucHGPVpkJlSJWzPH//vS2/w5V+/+0aIjXDQISBzLM8LSAoz7N79I7\n' +
          '7xdu5oO3S0InvLMaK66y0IwPrJSt1iyqpCnOOgiaYvDwq/TJkgANYfaWBE5P0Tbr\n' +
          'MZnTYQKBgBkWG5pfcx51HPMDJWmIlU8+hDukmbp8wovSBp2ex5jijRN6MylEG9xc\n' +
          'pG/Y7UITSPnR/hjS6mBPefDv/kDqfxySBXSQt1SbUwge1hA37s2NBmQpiyQ7Dx4r\n' +
          'Fq4wVkldX97Azb904FHX/TwXRZ3QQJWeRIJEb85OQOR3ik7yWw90\n' +
          '-----END RSA PRIVATE KEY-----'
      },
      bob: {
      publicKey: '-----BEGIN PUBLIC KEY-----\n' +
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzS2psHIBiriJA+CLwGKe\n' +
        'rTxaaUXYt4XguFbVsJ4U2Mrf/MQHnpIC5TuLPVyKC94jcNJRWlsl4BAAB6dR8ceH\n' +
        'fYoPR/Ye1f397faBsKychWxVxn0vJRScY4k60mwAhv4bv2GXpUy1rGb9OOesAf/l\n' +
        'a+fktVoBeZTcdDOSD+LL9gtymEvXzxfWprxWjF2HLaSZgc5S+WPf7PPtJENHGQGZ\n' +
        'tUqwMY7g5jZGvIR9LjJ0OWWeXZVrnInfDdA11yNDgp7AUZV4EFkyiWM7IJBcYlNN\n' +
        'Y98voOQloSAf8IJcewl5ToDYMPWaShbUFoqmb5SXkBZ+3QB4f5zZzXFgFVmw/qZg\n' +
        'hwIDAQAB\n' +
        '-----END PUBLIC KEY-----',
      privateKey:'-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIEpAIBAAKCAQEAzS2psHIBiriJA+CLwGKerTxaaUXYt4XguFbVsJ4U2Mrf/MQH\n' +
        'npIC5TuLPVyKC94jcNJRWlsl4BAAB6dR8ceHfYoPR/Ye1f397faBsKychWxVxn0v\n' +
        'JRScY4k60mwAhv4bv2GXpUy1rGb9OOesAf/la+fktVoBeZTcdDOSD+LL9gtymEvX\n' +
        'zxfWprxWjF2HLaSZgc5S+WPf7PPtJENHGQGZtUqwMY7g5jZGvIR9LjJ0OWWeXZVr\n' +
        'nInfDdA11yNDgp7AUZV4EFkyiWM7IJBcYlNNY98voOQloSAf8IJcewl5ToDYMPWa\n' +
        'ShbUFoqmb5SXkBZ+3QB4f5zZzXFgFVmw/qZghwIDAQABAoIBAQDEz1hF+BWiiwBi\n' +
        'x7FGCVNLuOjAsk7/O1wjdqfjkr9MdM4GF8N3R3efi040vd9tIte8EQIYOfZKxw5A\n' +
        'SS9BTLOaqCOgU2WgvtIkwKAGaIx7Lz/X9ZyTZQHeOHREA3U+B+F14pcj6EEb7m5X\n' +
        'd2J3SI84wmePzZY8mZ4dmJoywsoCZ6CkSpSvq1fvTchZH+PcF7Vr3N8J3VugTcpj\n' +
        'sQlTehZ3sGrdwPrAU9nivMdcXzGtM2Vvpr0Q8RyGzfAcmHpdyqUq0tGXL2sg7uEj\n' +
        'hCeEVq3FsEoD8KmWGMz8l3/ronv3nFBrkXcFtm+ng5k+IINyctk+DfAxfaDKfHDb\n' +
        '0RmKHeeBAoGBAO7yKOrv+EHJrttKysGtgjJYfMDaCHRCvO4jURga8FqpSQ8cNkU1\n' +
        'SkrSbd+FvO9N0nLBPZlxTWVIaNKobCzse0APmfRHwIfdDnqFyzkrrBhUgSHdmMIp\n' +
        'Tjj0c3YUmtlsQVQM4lE30mpzLUgWHCmiZ9kBnXq1Ez+J9rdG/IaP0oyTAoGBANvS\n' +
        'hwjIMCpat2Dnn69Mawvc0Mbv32fD2SCNozna7yEApB6EY8fL96uuDVKPejfrfTOt\n' +
        'fqrp05V+3KQZw9SfXti30XAyJVSI6QpJbuP6IU1QJBDO2U8984KvzoogLwA1jLGn\n' +
        'Ok27v+11SSq9DhZpQi4Hy1BpdpFN2a00AAkG8Ai9AoGBAILaltHiTMAqZNmu4c6i\n' +
        '6HQNxXQPcyXIDpMTQCvFRO9BWcMungHUpzTGfGk2YjtjEObLMKLBS7M1rkH+/g60\n' +
        'CuMQKC2Axc0hn/Y1Iw/R/NLuJDGZmzhpSm8iX8DAk/SRtk0DKUV1HoQxQxEBGrcq\n' +
        'O1i567XxR/M56KSB+XTvekyFAoGAZ/IfZGm1TPHksPAWNICARfW+y7N2As07iQcw\n' +
        '3hTG6uYwtTWJMVsj3IzLQ/UQqAy1AZDSyuMS6Cg7EWYVkh9ibDxPzywHNvgeqnya\n' +
        '8TbANJzm0QPfAnebBHs5wVsCnqizxPX8vfFACnthg9IuLS7M2pNY8sdMB922Rw7F\n' +
        'zX74VkkCgYBl83F/WDXs9rvYIyLEnxUQXywPNx4JYMzJEzFYSjF6H8bY1tzCXEft\n' +
        'MpT8sUxxoRpeO2T3efB0e48V2/WC6/YGFzyu6XsabwVuQD9Kx7SLk1DbcL9vqPRh\n' +
        'CVzhHuwmFUaWi+xI9WJUiNB6TFgRhPXv1Sp4btiIcejL5DQlT9gSJQ==\n' +
        '-----END RSA PRIVATE KEY-----'

      }
    };

    const bobPK = forge.pki.publicKeyFromPem(testVector.bob.publicKey);

    const keyCiphertext = encapsulateSymKey(bobPK);
    // TODO: Check for hex lengths and non-undefinied property values.
    expect(keyCiphertext).toHaveProperty('encapsulation');
    expect(keyCiphertext).toHaveProperty('key');
    expect(keyCiphertext).toHaveProperty('encapsulationHex');
    expect(keyCiphertext).toHaveProperty('keyHex');
    expect(keyCiphertext.key.length).toBe(32);
    expect(keyCiphertext.encapsulation.length).toBe(256);
  });

  test('Decapsulates a Key', () => {
  const testVector = {
   privateKey:'-----BEGIN RSA PRIVATE KEY-----\n' +
        'MIIEpAIBAAKCAQEAzS2psHIBiriJA+CLwGKerTxaaUXYt4XguFbVsJ4U2Mrf/MQH\n' +
        'npIC5TuLPVyKC94jcNJRWlsl4BAAB6dR8ceHfYoPR/Ye1f397faBsKychWxVxn0v\n' +
        'JRScY4k60mwAhv4bv2GXpUy1rGb9OOesAf/la+fktVoBeZTcdDOSD+LL9gtymEvX\n' +
        'zxfWprxWjF2HLaSZgc5S+WPf7PPtJENHGQGZtUqwMY7g5jZGvIR9LjJ0OWWeXZVr\n' +
        'nInfDdA11yNDgp7AUZV4EFkyiWM7IJBcYlNNY98voOQloSAf8IJcewl5ToDYMPWa\n' +
        'ShbUFoqmb5SXkBZ+3QB4f5zZzXFgFVmw/qZghwIDAQABAoIBAQDEz1hF+BWiiwBi\n' +
        'x7FGCVNLuOjAsk7/O1wjdqfjkr9MdM4GF8N3R3efi040vd9tIte8EQIYOfZKxw5A\n' +
        'SS9BTLOaqCOgU2WgvtIkwKAGaIx7Lz/X9ZyTZQHeOHREA3U+B+F14pcj6EEb7m5X\n' +
        'd2J3SI84wmePzZY8mZ4dmJoywsoCZ6CkSpSvq1fvTchZH+PcF7Vr3N8J3VugTcpj\n' +
        'sQlTehZ3sGrdwPrAU9nivMdcXzGtM2Vvpr0Q8RyGzfAcmHpdyqUq0tGXL2sg7uEj\n' +
        'hCeEVq3FsEoD8KmWGMz8l3/ronv3nFBrkXcFtm+ng5k+IINyctk+DfAxfaDKfHDb\n' +
        '0RmKHeeBAoGBAO7yKOrv+EHJrttKysGtgjJYfMDaCHRCvO4jURga8FqpSQ8cNkU1\n' +
        'SkrSbd+FvO9N0nLBPZlxTWVIaNKobCzse0APmfRHwIfdDnqFyzkrrBhUgSHdmMIp\n' +
        'Tjj0c3YUmtlsQVQM4lE30mpzLUgWHCmiZ9kBnXq1Ez+J9rdG/IaP0oyTAoGBANvS\n' +
        'hwjIMCpat2Dnn69Mawvc0Mbv32fD2SCNozna7yEApB6EY8fL96uuDVKPejfrfTOt\n' +
        'fqrp05V+3KQZw9SfXti30XAyJVSI6QpJbuP6IU1QJBDO2U8984KvzoogLwA1jLGn\n' +
        'Ok27v+11SSq9DhZpQi4Hy1BpdpFN2a00AAkG8Ai9AoGBAILaltHiTMAqZNmu4c6i\n' +
        '6HQNxXQPcyXIDpMTQCvFRO9BWcMungHUpzTGfGk2YjtjEObLMKLBS7M1rkH+/g60\n' +
        'CuMQKC2Axc0hn/Y1Iw/R/NLuJDGZmzhpSm8iX8DAk/SRtk0DKUV1HoQxQxEBGrcq\n' +
        'O1i567XxR/M56KSB+XTvekyFAoGAZ/IfZGm1TPHksPAWNICARfW+y7N2As07iQcw\n' +
        '3hTG6uYwtTWJMVsj3IzLQ/UQqAy1AZDSyuMS6Cg7EWYVkh9ibDxPzywHNvgeqnya\n' +
        '8TbANJzm0QPfAnebBHs5wVsCnqizxPX8vfFACnthg9IuLS7M2pNY8sdMB922Rw7F\n' +
        'zX74VkkCgYBl83F/WDXs9rvYIyLEnxUQXywPNx4JYMzJEzFYSjF6H8bY1tzCXEft\n' +
        'MpT8sUxxoRpeO2T3efB0e48V2/WC6/YGFzyu6XsabwVuQD9Kx7SLk1DbcL9vqPRh\n' +
        'CVzhHuwmFUaWi+xI9WJUiNB6TFgRhPXv1Sp4btiIcejL5DQlT9gSJQ==\n' +
        '-----END RSA PRIVATE KEY-----',
        keyHex:'4deaefd46d8af4ced6fbc31249cfee854f4fc650f8c24590137fe46464a93577',
        encapsulationHex:'b36c44c9fcbe9579fd16c69749156dc9b8d85988fd9390114f15f29dcef90ea6ed87aae155e87f9f1d18cef9c13c59ec4654ac0b4cbb84e853d64de1bebdc67318c20bafb63ca8114ad741821a279a2c14d0a1fe3a357eb3e1febe4c5190084c038472e95b1713cd0454c7346d03baa914f87d41a2dfdf89a32ad3ef5a02dcc4ba67784b0a2ea82207f0953a4a811d45c33b4df8e8d78d6a81f30c87fcb6e139d186ffb37191fb25c63c1c455fffb969ace1174df5834de3dcf92e83aee032a31596b07097571b35bcfaed3c9a033a8cab10f500cc1407c1e3c34a08143d2bb620b0f859c1098291bbf6e14f591c059b5d6679ef7d34fe8b3cbbc2d5b2f1cd3b'
   }

    const bobSK = forge.pki.privateKeyFromPem(testVector.privateKey);

    const decapkey = decapsulateSymKey(bobSK, forge.util.hexToBytes(testVector.encapsulationHex));


    expect((forge.util.bytesToHex(decapkey))).toEqual(testVector.keyHex)

    // Test vector of encapsulated key
  // Decapsualte key
  // Check output
  })

});

describe('Full KEM/DEM Mechanism', () => {
  test('Encrypt function uses inputs correctly, returns a ciphertext and mac', () => {
    const testVector = {
    rsa: {
      bob: {
        pk: '-----BEGIN PUBLIC KEY-----\n' +
          'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzS2psHIBiriJA+CLwGKe\n' +
          'rTxaaUXYt4XguFbVsJ4U2Mrf/MQHnpIC5TuLPVyKC94jcNJRWlsl4BAAB6dR8ceH\n' +
          'fYoPR/Ye1f397faBsKychWxVxn0vJRScY4k60mwAhv4bv2GXpUy1rGb9OOesAf/l\n' +
          'a+fktVoBeZTcdDOSD+LL9gtymEvXzxfWprxWjF2HLaSZgc5S+WPf7PPtJENHGQGZ\n' +
          'tUqwMY7g5jZGvIR9LjJ0OWWeXZVrnInfDdA11yNDgp7AUZV4EFkyiWM7IJBcYlNN\n' +
          'Y98voOQloSAf8IJcewl5ToDYMPWaShbUFoqmb5SXkBZ+3QB4f5zZzXFgFVmw/qZg\n' +
          'hwIDAQAB\n' +
          '-----END PUBLIC KEY-----',

    }},
    aead: {
      key: '808182838485868788898a8b8c8d8e8f' +
        '909192939495969798999a9b9c9d9e9f',
      plaintext: 'hifriend',
      aad: 'onethwothree',
      ciphertext: 'd31a8d34648e60db7b86afbc53ef7ec2' +
        'a4aded51296e08fea9e2b5a736ee62d6' +
        '3dbea45e8ca9671282fafb69da92728b' +
        '1a71de0a9e 06 0b 29 05 d6 a5 b6 7e cd 3b36' +
        '92 dd bd 7f 2d 77 8b 8c 98 03 ae e3 28 09 1b 58' +
        'fa b3 24 e4 fa d6 75 94 55 85 80 8b 48 31 d7 bc' +
        '3ff4def08e4b7a9de576d26586cec64b' +
        '6116',
      tag: '1ae10b594f09e26a7e902ecbd0600691'
    }
  };
    // let called = false;
    // const dummyFunc = () => {
    //   called = true;
    // }

    const ciphertext = encrypt(testVector.rsa.bob.pk, testVector.aead.plaintext, testVector.aead.aad);
    expect(ciphertext).toHaveProperty('ciphertext');
    expect(ciphertext).toHaveProperty('encapsulation');
    expect(ciphertext).toHaveProperty('mac');
    expect(ciphertext).toHaveProperty('authenticatedData');
    expect(ciphertext).toHaveProperty('nonce');

    //TODO: Add checking for mac, nonce and other lengths.
  });

  test('Decrypt function uses inputs correctly, returns correct plaintext.', () => {
    const testVector = {
    rsa: {
      bob: {
       sk: '-----BEGIN RSA PRIVATE KEY-----\n' +
          'MIIEpAIBAAKCAQEAzS2psHIBiriJA+CLwGKerTxaaUXYt4XguFbVsJ4U2Mrf/MQH\n' +
          'npIC5TuLPVyKC94jcNJRWlsl4BAAB6dR8ceHfYoPR/Ye1f397faBsKychWxVxn0v\n' +
          'JRScY4k60mwAhv4bv2GXpUy1rGb9OOesAf/la+fktVoBeZTcdDOSD+LL9gtymEvX\n' +
          'zxfWprxWjF2HLaSZgc5S+WPf7PPtJENHGQGZtUqwMY7g5jZGvIR9LjJ0OWWeXZVr\n' +
          'nInfDdA11yNDgp7AUZV4EFkyiWM7IJBcYlNNY98voOQloSAf8IJcewl5ToDYMPWa\n' +
          'ShbUFoqmb5SXkBZ+3QB4f5zZzXFgFVmw/qZghwIDAQABAoIBAQDEz1hF+BWiiwBi\n' +
          'x7FGCVNLuOjAsk7/O1wjdqfjkr9MdM4GF8N3R3efi040vd9tIte8EQIYOfZKxw5A\n' +
          'SS9BTLOaqCOgU2WgvtIkwKAGaIx7Lz/X9ZyTZQHeOHREA3U+B+F14pcj6EEb7m5X\n' +
          'd2J3SI84wmePzZY8mZ4dmJoywsoCZ6CkSpSvq1fvTchZH+PcF7Vr3N8J3VugTcpj\n' +
          'sQlTehZ3sGrdwPrAU9nivMdcXzGtM2Vvpr0Q8RyGzfAcmHpdyqUq0tGXL2sg7uEj\n' +
          'hCeEVq3FsEoD8KmWGMz8l3/ronv3nFBrkXcFtm+ng5k+IINyctk+DfAxfaDKfHDb\n' +
          '0RmKHeeBAoGBAO7yKOrv+EHJrttKysGtgjJYfMDaCHRCvO4jURga8FqpSQ8cNkU1\n' +
          'SkrSbd+FvO9N0nLBPZlxTWVIaNKobCzse0APmfRHwIfdDnqFyzkrrBhUgSHdmMIp\n' +
          'Tjj0c3YUmtlsQVQM4lE30mpzLUgWHCmiZ9kBnXq1Ez+J9rdG/IaP0oyTAoGBANvS\n' +
          'hwjIMCpat2Dnn69Mawvc0Mbv32fD2SCNozna7yEApB6EY8fL96uuDVKPejfrfTOt\n' +
          'fqrp05V+3KQZw9SfXti30XAyJVSI6QpJbuP6IU1QJBDO2U8984KvzoogLwA1jLGn\n' +
          'Ok27v+11SSq9DhZpQi4Hy1BpdpFN2a00AAkG8Ai9AoGBAILaltHiTMAqZNmu4c6i\n' +
          '6HQNxXQPcyXIDpMTQCvFRO9BWcMungHUpzTGfGk2YjtjEObLMKLBS7M1rkH+/g60\n' +
          'CuMQKC2Axc0hn/Y1Iw/R/NLuJDGZmzhpSm8iX8DAk/SRtk0DKUV1HoQxQxEBGrcq\n' +
          'O1i567XxR/M56KSB+XTvekyFAoGAZ/IfZGm1TPHksPAWNICARfW+y7N2As07iQcw\n' +
          '3hTG6uYwtTWJMVsj3IzLQ/UQqAy1AZDSyuMS6Cg7EWYVkh9ibDxPzywHNvgeqnya\n' +
          '8TbANJzm0QPfAnebBHs5wVsCnqizxPX8vfFACnthg9IuLS7M2pNY8sdMB922Rw7F\n' +
          'zX74VkkCgYBl83F/WDXs9rvYIyLEnxUQXywPNx4JYMzJEzFYSjF6H8bY1tzCXEft\n' +
          'MpT8sUxxoRpeO2T3efB0e48V2/WC6/YGFzyu6XsabwVuQD9Kx7SLk1DbcL9vqPRh\n' +
          'CVzhHuwmFUaWi+xI9WJUiNB6TFgRhPXv1Sp4btiIcejL5DQlT9gSJQ==\n' +
          '-----END RSA PRIVATE KEY-----'

    }},
    aead: {
      key: '808182838485868788898a8b8c8d8e8f' +
        '909192939495969798999a9b9c9d9e9f',
      plaintext: 'hifriend',
      aad: 'onethwothree',
      aadHex: '6f6e6574776f7468726565',
      nonce:'000000000000000000000000',
      encapsulation: '90e2eb884b80cb39e04253a1902ba47109fbecb1d6fb25662c3466f65e853be9b156c6530f76276974d0d3dc13c09b7415422f174fd4c0740c62fe596ca04604694ffba3a59aa2a310fc9092facf7183a23950607c3b364ad7b7992ee5241ef1ceb997abdfa9198e78ce426603e3a881722ea6eeac4aa87971eb723427b2e8e9cbb9fbea5fd17d072a197c90718f50444e8e75c247ab559d62c70a9dc14bc5c78327027744c0568d21a7242d99f8e69e02a8e50739b96c7e2cdac259e7a197f609100c5c6180f7482907e1ae5e288135e4a56b16f960adfabd6b5217feddcaa26f39213d8de613c98db2819fbfd5a3a9aadb7493221153199d440ec1b7717677',
      mac: '27e94293b3b0138ef4a1c2aef8daca93',
      ciphertext: '121344bd4e3e668f'
    }
  };

    const plaintext = decrypt(testVector.rsa.bob.sk, testVector.aead.encapsulation, testVector.aead.ciphertext, testVector.aead.nonce, testVector.aead.aadHex, testVector.aead.mac);

    expect(util.bytesEqual(plaintext,new Uint8Array([ 104, 105, 102, 114, 105, 101, 110, 100 ]))).toBe(1);
  })

});
