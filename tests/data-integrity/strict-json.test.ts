import { describe, expect, it } from 'vitest';
import { parseStrictJsonObject } from '../../src';

const bytesOf = (text: string): Uint8Array => new TextEncoder().encode(text);

describe('parseStrictJsonObject', () => {
  it('returns a valid object', () => {
    expect(parseStrictJsonObject(bytesOf(' {"a":{"b":[1,"c",true,null]},"d":-2.5e1} '))).toEqual({
      a: { b: [1, 'c', true, null] },
      d: -25
    });
  });

  it('refuses a byte order mark', () => {
    expect(() =>
      parseStrictJsonObject(new Uint8Array([0xef, 0xbb, 0xbf, ...bytesOf('{}')]))
    ).toThrow(/unexpected character/);
  });

  it('refuses invalid UTF-8', () => {
    expect(() =>
      parseStrictJsonObject(new Uint8Array([...bytesOf('{"a":"'), 0xff, ...bytesOf('"}')]))
    ).toThrow(/not valid UTF-8/);
  });

  it('refuses a repeated member name at depth 2 and deeper', () => {
    for (const text of ['{"a":{"b":1,"b":2}}', '{"a":[{"b":{"c":1,"c":2}}]}']) {
      expect(() => parseStrictJsonObject(bytesOf(text))).toThrow(/repeats/);
    }
  });

  it('refuses a top level that is not an object', () => {
    for (const text of ['[]', '1', '"a"', 'true', 'null']) {
      expect(() => parseStrictJsonObject(bytesOf(text))).toThrow(/not an object/);
    }
  });
});
