// Module imports
const forge = require('node-forge');

// Local Imports
const util = require('../util')

// 48656c6c6f20576f726c64 -> 'Hello World' -> Uint8Array []
describe('Auxilary Functions', () => {
  test('fromHex hex string with spaces', () => {
    var hexTestVector = {
      hexStringNoSpaces: '48656c6c6f20576f726c64',
      hexStringSpaces: '48 65 6c 6c 6f 20 57 6f 72 6c 64',
      decimalArrayRepresentation: [ 72,101,108,108,111,32,87,111, 114, 108,100 ],
      uint8ArrayRepresentation: new Uint8Array([ 72,101,108,108,111,32,87,111, 114, 108,100 ]),
    }
    const out = util.fromHex(hexTestVector.hexStringSpaces)
    expect(out).toEqual(expect.arrayContaining(hexTestVector.decimalArrayRepresentation));

  });

   test('fromHex hex string without spaces', () => {
      var hexTestVector = {
      hexStringNoSpaces: '48656c6c6f20576f726c64',
      hexStringSpaces: '48 65 6c 6c 6f 20 57 6f 72 6c 64',
      decimalArrayRepresentation: [ 72,101,108,108,111,32,87,111, 114, 108,100 ],
      uint8ArrayRepresentation: new Uint8Array([ 72,101,108,108,111,32,87,111, 114, 108,100 ]),
    }
    const out = util.fromHex(hexTestVector.hexStringNoSpaces)
    expect(out).toEqual(expect.arrayContaining(hexTestVector.decimalArrayRepresentation))

  });

   test('hexToBytes hex string without spaces', () => {
     var hexTestVector = {
      hexStringNoSpaces: '48656c6c6f20576f726c64',
      hexStringSpaces: '48 65 6c 6c 6f 20 57 6f 72 6c 64',
      decimalArrayRepresentation: [ 72,101,108,108, 111, 32, 87,111, 114, 108, 100 ],
      uint8ArrayRepresentation: new Uint8Array([ 72,101,108,108,111,32,87,111, 114, 108,100 ]),
    }
    const out = util.binaryEncodingToUint8Array(forge.util.hexToBytes(hexTestVector.hexStringNoSpaces))

    expect(util.bytesEqual(hexTestVector.uint8ArrayRepresentation,out)).toBe(1);

  });

  //TODO: Add corner cases
  test('bytesEqual should return true', () => {
      const a = new Uint8Array([0,1,88,56,45,214,158]);
      const b = new Uint8Array([0,1,88,56,45,214,158]);
      expect(util.bytesEqual(a,b)).toBeTruthy();
  });

  // TODO: Add corner cases
  test('bytesEqual should return false', () => {
      const a = new Uint8Array([0,1,88,56,45,214,158]);
      const b = new Uint8Array([]);
      expect(util.bytesEqual(a,b)).toBeFalsy();
  });

  test('decodeUTF8', () => {
      // 'Hello World' created with TextEncoder()
      const testVector = new Uint8Array([ 72, 101, 108, 108, 111, 87, 111, 114, 108, 100 ]);
      expect(util.decodeUTF8('HelloWorld')).toStrictEqual(testVector);

  });

  test('Uint8ArrayToHex', () => {
    const testVector = new Uint8Array([10, 100, 240, 50, 16 ]);
    const hex = '0a64f03210';
    expect(util.uint8ArrayToHex(testVector)).toEqual(hex);
  });

  test('Hex to Uint8Array to Hex', () => {
    const testVector = {
      hex: '0a64f03210',
      plaintext: 'HelloWorld',
      uint8ArrayValues: [10, 100, 240, 50, 16],
    }

    expect(util.uint8ArrayToHex(util.fromHex(testVector.hex))).toEqual(testVector.hex);
  });

  test('Uint8Array to Hex to Uint8Array', () => {
    const testVector = {
      hex: '0a64f03210',
      plaintext: 'HelloWorld',
      uint8ArrayValues: [10, 100, 240, 50, 16],
    }

    expect(util.fromHex(util.uint8ArrayToHex(new Uint8Array(testVector.uint8ArrayValues)))).toEqual(expect.arrayContaining([10, 100, 240, 50, 16]));
  });

  test('Binary string to Uint8Array to Hex', () => {
    expect(util.uint8ArrayToHex(util.binaryEncodingToUint8Array('binarystring'))).toEqual('62696e617279737472696e67');
  });

});