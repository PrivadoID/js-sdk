const MAX_DEPTH = 8;
const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;
const REPLACEMENT_CHARACTER = '�';
const SIMPLE_ESCAPES: Readonly<Record<string, string>> = {
  '"': '"',
  '\\': '\\',
  '/': '/',
  b: '\b',
  f: '\f',
  n: '\n',
  r: '\r',
  t: '\t'
};

type JsonValue = null | boolean | number | string | JsonValue[] | JsonObject;
type JsonObject = { [key: string]: JsonValue };

class StrictJsonError extends Error {
  constructor(message: string) {
    super(`invalid JSON: ${message}`);
    this.name = 'StrictJsonError';
  }
}

const isHighSurrogate = (unit: number): boolean => unit >= 0xd800 && unit < 0xdc00;
const isLowSurrogate = (unit: number): boolean => unit >= 0xdc00 && unit < 0xe000;

const isJsonObject = (value: JsonValue): value is JsonObject =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

const setMember = (object: JsonObject, key: string, value: JsonValue): void => {
  Object.defineProperty(object, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true
  });
};

class StrictJsonParser {
  private pos = 0;

  constructor(private readonly text: string) {}

  parseDocument(): JsonValue {
    this.skipWhitespace();
    const value = this.parseValue(0);
    this.skipWhitespace();
    if (this.pos !== this.text.length) {
      this.fail('data after the JSON value');
    }
    return value;
  }

  private fail(message: string): never {
    throw new StrictJsonError(`${message} at offset ${this.pos}`);
  }

  private skipWhitespace(): void {
    while (this.pos < this.text.length && ' \t\n\r'.includes(this.text[this.pos])) {
      this.pos++;
    }
  }

  private parseValue(depth: number): JsonValue {
    const c = this.text[this.pos];
    switch (c) {
      case '{':
        return this.parseObject(depth + 1);
      case '[':
        return this.parseArray(depth + 1);
      case '"':
        return this.parseString();
      case 't':
        return this.parseLiteral('true', true);
      case 'f':
        return this.parseLiteral('false', false);
      case 'n':
        return this.parseLiteral('null', null);
    }
    if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
      return this.parseNumber();
    }
    this.fail(
      c === undefined ? 'unexpected end of input' : `unexpected character ${JSON.stringify(c)}`
    );
  }

  private parseLiteral<T extends JsonValue>(word: string, value: T): T {
    if (!this.text.startsWith(word, this.pos)) {
      this.fail('invalid literal');
    }
    this.pos += word.length;
    return value;
  }

  private parseNumber(): number {
    NUMBER.lastIndex = this.pos;
    const match = NUMBER.exec(this.text);
    if (!match) {
      this.fail('invalid number');
    }
    this.pos += match[0].length;
    return Number(match[0]);
  }

  private parseString(): string {
    this.pos++;
    let out = '';
    let start = this.pos;
    for (;;) {
      if (this.pos >= this.text.length) {
        this.fail('unterminated string');
      }
      const unit = this.text.charCodeAt(this.pos);
      if (unit === 0x22) {
        out += this.text.slice(start, this.pos);
        this.pos++;
        return out;
      }
      if (unit < 0x20) {
        this.fail('control character in string');
      }
      if (unit !== 0x5c) {
        this.pos++;
        continue;
      }
      out += this.text.slice(start, this.pos);
      this.pos++;
      out += this.parseEscape();
      start = this.pos;
    }
  }

  private parseEscape(): string {
    const e = this.text[this.pos];
    this.pos++;
    if (e !== 'u') {
      if (e === undefined || !Object.hasOwn(SIMPLE_ESCAPES, e)) {
        this.fail('invalid escape');
      }
      return SIMPLE_ESCAPES[e];
    }
    const unit = this.parseHex4();
    if (isLowSurrogate(unit)) {
      return REPLACEMENT_CHARACTER;
    }
    if (!isHighSurrogate(unit)) {
      return String.fromCharCode(unit);
    }
    if (this.text.startsWith('\\u', this.pos)) {
      const save = this.pos;
      this.pos += 2;
      const low = this.parseHex4();
      if (isLowSurrogate(low)) {
        return String.fromCharCode(unit, low);
      }
      this.pos = save;
    }
    return REPLACEMENT_CHARACTER;
  }

  private parseHex4(): number {
    const hex = this.text.slice(this.pos, this.pos + 4);
    if (!HEX4.test(hex)) {
      this.fail('invalid \\u escape');
    }
    this.pos += 4;
    return parseInt(hex, 16);
  }

  private parseObject(depth: number): JsonObject {
    if (depth > MAX_DEPTH) {
      this.fail(`nesting deeper than ${MAX_DEPTH}`);
    }
    this.pos++;
    const object: JsonObject = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.text[this.pos] === '}') {
      this.pos++;
      return object;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.text[this.pos] !== '"') {
        this.fail('member name is not a string');
      }
      const key = this.parseString();
      if (seen.has(key)) {
        this.fail(`member name ${JSON.stringify(key)} repeats`);
      }
      seen.add(key);
      this.skipWhitespace();
      if (this.text[this.pos] !== ':') {
        this.fail('expected :');
      }
      this.pos++;
      this.skipWhitespace();
      setMember(object, key, this.parseValue(depth));
      this.skipWhitespace();
      const c = this.text[this.pos];
      this.pos++;
      if (c === '}') {
        return object;
      }
      if (c !== ',') {
        this.fail('expected , or }');
      }
    }
  }

  private parseArray(depth: number): JsonValue[] {
    if (depth > MAX_DEPTH) {
      this.fail(`nesting deeper than ${MAX_DEPTH}`);
    }
    this.pos++;
    const array: JsonValue[] = [];
    this.skipWhitespace();
    if (this.text[this.pos] === ']') {
      this.pos++;
      return array;
    }
    for (;;) {
      this.skipWhitespace();
      array.push(this.parseValue(depth));
      this.skipWhitespace();
      const c = this.text[this.pos];
      this.pos++;
      if (c === ']') {
        return array;
      }
      if (c !== ',') {
        this.fail('expected , or ]');
      }
    }
  }
}

const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export const parseStrictJsonObject = (bytes: Uint8Array): Record<string, unknown> => {
  let text: string;
  try {
    text = strictUtf8.decode(bytes);
  } catch {
    throw new StrictJsonError('not valid UTF-8');
  }
  const value = new StrictJsonParser(text).parseDocument();
  if (!isJsonObject(value)) {
    throw new StrictJsonError('top-level value is not an object');
  }
  return value;
};
