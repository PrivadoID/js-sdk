const textEncoder = new TextEncoder();

const V4_SEGMENT = '(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])';
const V4_ADDRESS = `(?:${V4_SEGMENT}\\.){3}${V4_SEGMENT}`;
const V6_SEGMENT = '(?:[0-9a-fA-F]{1,4})';
const IPV6_ADDRESS = new RegExp(
  '^(?:' +
    `(?:${V6_SEGMENT}:){7}(?:${V6_SEGMENT}|:)|` +
    `(?:${V6_SEGMENT}:){6}(?:${V4_ADDRESS}|:${V6_SEGMENT}|:)|` +
    `(?:${V6_SEGMENT}:){5}(?::${V4_ADDRESS}|(?::${V6_SEGMENT}){1,2}|:)|` +
    `(?:${V6_SEGMENT}:){4}(?:(?::${V6_SEGMENT}){0,1}:${V4_ADDRESS}|(?::${V6_SEGMENT}){1,3}|:)|` +
    `(?:${V6_SEGMENT}:){3}(?:(?::${V6_SEGMENT}){0,2}:${V4_ADDRESS}|(?::${V6_SEGMENT}){1,4}|:)|` +
    `(?:${V6_SEGMENT}:){2}(?:(?::${V6_SEGMENT}){0,3}:${V4_ADDRESS}|(?::${V6_SEGMENT}){1,5}|:)|` +
    `(?:${V6_SEGMENT}:){1}(?:(?::${V6_SEGMENT}){0,4}:${V4_ADDRESS}|(?::${V6_SEGMENT}){1,6}|:)|` +
    `(?::(?:(?::${V6_SEGMENT}){0,5}:${V4_ADDRESS}|(?::${V6_SEGMENT}){1,7}|:))` +
    ')$'
);

interface GoURL {
  scheme: string;
  host: string;
  path: string;
}

const isHex = (c: string | undefined) => c !== undefined && /^[0-9a-fA-F]$/.test(c);
const isAlphanumeric = (c: string) => /^[a-zA-Z0-9]$/.test(c);

type Mode = 'host' | 'zone' | 'path' | 'fragment' | 'user';

function shouldEscape(c: string, mode: Mode): boolean {
  if (isAlphanumeric(c)) return false;
  if ((mode === 'host' || mode === 'zone') && '!$&\'()*+,;=:[]<>"'.includes(c)) return false;
  if ('-_.~'.includes(c)) return false;
  if ('$&+,/:;=?@'.includes(c)) {
    switch (mode) {
      case 'user':
        return c === '@' || c === '/' || c === '?' || c === ':';
      case 'path':
        return c === '?';
      case 'fragment':
        return false;
      default:
        break;
    }
  }
  if (mode === 'fragment' && '!()*'.includes(c)) return false;
  return true;
}

function unescapeOK(s: string, mode: Mode): boolean {
  const b = Array.from(textEncoder.encode(s), (byte) => String.fromCharCode(byte)).join('');
  for (let i = 0; i < b.length; ) {
    const c = b.charAt(i);
    if (c === '%') {
      if (i + 2 >= b.length || !isHex(b.charAt(i + 1)) || !isHex(b.charAt(i + 2))) return false;
      if (mode === 'host' && parseInt(b.charAt(i + 1), 16) < 8 && b.slice(i, i + 3) !== '%25')
        return false;
      if (mode === 'zone') {
        const v = parseInt(b.slice(i + 1, i + 3), 16);
        if (
          b.slice(i, i + 3) !== '%25' &&
          v !== 0x20 &&
          shouldEscape(String.fromCharCode(v), 'host')
        )
          return false;
      }
      i += 3;
      continue;
    }
    if (
      (mode === 'host' || mode === 'zone') &&
      c.charCodeAt(0) < 0x80 &&
      c !== '+' &&
      shouldEscape(c, mode)
    )
      return false;
    i++;
  }
  return true;
}

function validOptionalPort(port: string): boolean {
  if (port === '') return true;
  if (port[0] !== ':') return false;
  return /^[0-9]*$/.test(port.slice(1));
}

function validUserinfo(s: string): boolean {
  for (const c of s) {
    if (isAlphanumeric(c)) continue;
    if ("-._:~!$&'()*+,;=%@".includes(c)) continue;
    return false;
  }
  return true;
}

function isIPv6Literal(text: string): boolean {
  const pct = text.indexOf('%');
  const addr = pct >= 0 ? text.slice(0, pct) : text;
  if (pct >= 0 && pct === text.length - 1) return false;
  return IPV6_ADDRESS.test(addr);
}

function parseHost(scheme: string, host: string): string | null {
  const open = host.lastIndexOf('[');
  if (open > 0) return null;
  if (open === 0) {
    const close = host.lastIndexOf(']');
    if (close < 0) return null;
    const colonPort = host.slice(close + 1);
    if (!validOptionalPort(colonPort) || !unescapeOK(colonPort, 'host')) return null;
    const hostname = host.slice(1, close);
    const zone = hostname.indexOf('%25');
    let unescaped: string;
    if (zone >= 0) {
      if (!unescapeOK(hostname.slice(0, zone), 'host') || !unescapeOK(hostname.slice(zone), 'zone'))
        return null;
      unescaped = decodeURIComponentSafe(hostname);
    } else {
      if (!unescapeOK(hostname, 'host')) return null;
      unescaped = decodeURIComponentSafe(hostname);
    }
    if (!isIPv6Literal(unescaped)) return null;
    return host;
  }
  const first = host.indexOf(':');
  if (first !== -1) {
    let i = first;
    const last = host.lastIndexOf(':');
    if (last !== first && scheme !== 'http' && scheme !== 'https') i = last;
    if (!validOptionalPort(host.slice(i))) return null;
  }
  if (!unescapeOK(host, 'host')) return null;
  return host;
}

function decodeURIComponentSafe(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function getScheme(raw: string): { scheme: string; rest: string } | null {
  for (let i = 0; i < raw.length; i++) {
    const c = raw.charAt(i);
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) continue;
    if ((c >= '0' && c <= '9') || c === '+' || c === '-' || c === '.') {
      if (i === 0) return { scheme: '', rest: raw };
      continue;
    }
    if (c === ':') {
      if (i === 0) return null;
      return { scheme: raw.slice(0, i), rest: raw.slice(i + 1) };
    }
    return { scheme: '', rest: raw };
  }
  return { scheme: '', rest: raw };
}

export function goParseURL(rawURL: string): GoURL | null {
  const hash = rawURL.indexOf('#');
  const u = hash >= 0 ? rawURL.slice(0, hash) : rawURL;
  const frag = hash >= 0 ? rawURL.slice(hash + 1) : '';
  for (let i = 0; i < u.length; i++) {
    const c = u.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return null;
  }
  const out: GoURL = { scheme: '', host: '', path: '' };
  if (u !== '*') {
    const s = getScheme(u);
    if (!s) return null;
    out.scheme = s.scheme.toLowerCase();
    let rest = s.rest;
    if (rest.endsWith('?') && rest.split('?').length === 2) {
      rest = rest.slice(0, -1);
    } else {
      const q = rest.indexOf('?');
      if (q >= 0) rest = rest.slice(0, q);
    }
    let opaque = false;
    if (!rest.startsWith('/')) {
      if (out.scheme !== '') {
        opaque = true;
      } else {
        const slash = rest.indexOf('/');
        const segment = slash >= 0 ? rest.slice(0, slash) : rest;
        if (segment.includes(':')) return null;
      }
    }
    if (!opaque) {
      if ((out.scheme !== '' || !rest.startsWith('///')) && rest.startsWith('//')) {
        let authority = rest.slice(2);
        rest = '';
        const slash = authority.indexOf('/');
        if (slash >= 0) {
          rest = authority.slice(slash);
          authority = authority.slice(0, slash);
        }
        const at = authority.lastIndexOf('@');
        const host = parseHost(out.scheme, at < 0 ? authority : authority.slice(at + 1));
        if (host === null) return null;
        if (at >= 0) {
          const userinfo = authority.slice(0, at);
          if (!validUserinfo(userinfo)) return null;
          const colon = userinfo.indexOf(':');
          if (colon < 0) {
            if (!unescapeOK(userinfo, 'user')) return null;
          } else if (
            !unescapeOK(userinfo.slice(0, colon), 'user') ||
            !unescapeOK(userinfo.slice(colon + 1), 'user')
          ) {
            return null;
          }
        }
        out.host = decodeURIComponentSafe(host);
      }
      if (!unescapeOK(rest, 'path')) return null;
      out.path = decodeURIComponentSafe(rest);
    }
  }
  if (frag !== '' && !unescapeOK(frag, 'fragment')) return null;
  return out;
}

const JSONLD_KEYWORDS = new Set([
  '@always',
  '@base',
  '@container',
  '@context',
  '@default',
  '@direction',
  '@embed',
  '@explicit',
  '@first',
  '@json',
  '@id',
  '@included',
  '@index',
  '@graph',
  '@import',
  '@language',
  '@last',
  '@list',
  '@nest',
  '@never',
  '@none',
  '@null',
  '@omitDefault',
  '@once',
  '@prefix',
  '@preserve',
  '@propagate',
  '@protected',
  '@requireAll',
  '@reverse',
  '@set',
  '@type',
  '@value',
  '@version',
  '@vocab'
]);

export function isKeyword(key: unknown): boolean {
  return typeof key === 'string' && JSONLD_KEYWORDS.has(key);
}

export function isAbsoluteIri(value: string): boolean {
  if (value.startsWith('_:')) return true;
  const u = goParseURL(value);
  return u !== null && u.scheme !== '';
}

export function isRelativeIri(value: string): boolean {
  return !(isKeyword(value) || isAbsoluteIri(value));
}

const SCHEMA = /^(?:ftp|tcp|udp|wss?|https?):\/\//;
const URL_IP =
  /^([1-9]\d?|1\d\d|2[01]\d|22[0-3])(\.(1?\d{1,2}|2[0-4]\d|25[0-5])){2}(?:\.([0-9]\d?|1\d\d|2[0-4]\d|25[0-4]))$/;
const IP6 =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
const LABEL = /^[a-zA-Z0-9¡-￿]+(?:-{1,2}[a-zA-Z0-9¡-￿]+)*$/u;
const TLD = /^[a-zA-Z¡-￿]+$/u;
const A0_HEAD = /^[a-zA-Z0-9][a-zA-Z0-9_-]*[a-zA-Z0-9]$/;
const A0_TAIL = /^(?:[.-][a-zA-Z0-9]+)*$/;
const SUB_PRE = /^[a-zA-Z0-9](?:[-_.]?[a-zA-Z0-9])*$/;
const ALPHANUMERIC = /^[a-zA-Z0-9]+$/;
const ALPHANUMERIC_CHAR = /^[a-zA-Z0-9]$/;

function matchA(s: string): boolean {
  const dot = s.indexOf('.');
  if (dot < 0) return A0_HEAD.test(s);
  return A0_HEAD.test(s.slice(0, dot)) && A0_TAIL.test(s.slice(dot));
}

function matchSub(s: string): boolean {
  if (s === 'www.') return true;
  const dot = s.lastIndexOf('.');
  if (dot < 0 || !ALPHANUMERIC.test(s.slice(dot + 1))) return false;
  const pre = s.slice(0, dot);
  if (pre.length < 2 || !ALPHANUMERIC_CHAR.test(pre.slice(-1))) return false;
  return SUB_PRE.test(pre.slice(0, -1));
}

function matchLabelTld(s: string): boolean {
  const dot = s.indexOf('.');
  if (dot < 0) return LABEL.test(s);
  if (s.indexOf('.', dot + 1) >= 0) return false;
  return LABEL.test(s.slice(0, dot)) && TLD.test(s.slice(dot + 1));
}

function matchHostName(s: string): boolean {
  if (URL_IP.test(s)) return true;
  const last = s.lastIndexOf('.');
  const secondLast = last > 0 ? s.lastIndexOf('.', last - 1) : -1;
  for (let i = Math.max(0, secondLast + 1); i <= s.length; i++) {
    if (!matchLabelTld(s.slice(i))) continue;
    const prefix = s.slice(0, i);
    if (prefix === '' || matchA(prefix) || matchSub(prefix)) return true;
  }
  return false;
}

function matchAfterUserinfo(r: string): boolean {
  let after: string;
  if (r.startsWith('[')) {
    const close = r.indexOf(']');
    if (close < 0 || !IP6.test(r.slice(1, close))) return false;
    after = r.slice(close + 1);
  } else {
    const m = /[:/?#]/.exec(r);
    const end = m ? m.index : r.length;
    let host = r.slice(0, end);
    const ok =
      matchHostName(host) || (host.endsWith('.') && matchHostName((host = host.slice(0, -1))));
    if (!ok) return false;
    after = r.slice(end);
  }
  if (r.startsWith('[') && after.startsWith('.')) after = after.slice(1);
  const port = /^:\d{1,5}/.exec(after);
  if (port) after = after.slice(port[0].length);
  return after === '' || '/?#'.includes(after.charAt(0));
}

function matchURLRegex(str: string): boolean {
  if (/[\t\n\f\r ]/.test(str)) return false;
  const m = SCHEMA.exec(str);
  const rest = m ? str.slice(m[0].length) : str;
  if (matchAfterUserinfo(rest)) return true;
  for (let i = rest.indexOf('@'); i >= 0; i = rest.indexOf('@', i + 1)) {
    if ((m !== null || i >= 1) && matchAfterUserinfo(rest.slice(i + 1))) return true;
  }
  return false;
}

export function isURL(str: string): boolean {
  if (
    str === '' ||
    [...str].length >= 2083 ||
    textEncoder.encode(str).length <= 3 ||
    str.startsWith('.')
  )
    return false;
  let strTemp = str;
  if (str.includes(':') && !str.includes('://')) strTemp = 'http://' + str;
  const u = goParseURL(strTemp);
  if (u === null) return false;
  if (u.host.startsWith('.')) return false;
  if (u.host === '' && u.path !== '' && !u.path.includes('.')) return false;
  return matchURLRegex(str);
}
