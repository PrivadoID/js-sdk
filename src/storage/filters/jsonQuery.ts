/* eslint-disable @typescript-eslint/no-explicit-any */
import { W3CCredential, ProofQuery } from '../../verifiable';

/**
 * search errors
 *
 * @enum {number}
 */
export enum SearchError {
  NotDefinedQueryKey = 'not defined query key',
  NotDefinedComparator = 'not defined comparator'
}
/**
 * supported data formats
 *
 * @enum {number}
 */
export enum SupportedDataFormat {
  BigInt,
  Boolean,
  Double,
  DateTime,
  String
}
/** allowed operators to search */
export type FilterOperatorMethod =
  | '$noop'
  | '$eq'
  | '$in'
  | '$nin'
  | '$gt'
  | '$lt'
  | '$ne'
  | '$gte'
  | '$lte'
  | '$sd'
  | '$exists'
  | '$between'
  | '$nonbetween';

/** filter function type */
export type FilterOperatorFunction = (a: any, b: any) => boolean;

/**
 * query filter interface that allows to query Verifiable Credential
 *
 * @public
 * @interface   IFilterQuery
 */
export interface IFilterQuery {
  /**
   * applies filter to verifiable credential
   *
   * @param {W3CCredential} credential - credential to query
   * @returns boolean
   */
  execute(credential: W3CCredential): boolean;
}

const truthyValues = [true, 1, 'true'];
const falsyValues = [false, 0, 'false'];
type ComparableType = number | string | boolean;
const equalsComparator = (
  a: ComparableType | Array<ComparableType>,
  b: ComparableType | Array<ComparableType>
) => {
  if (Array.isArray(a) && Array.isArray(b)) {
    return (
      a.length === b.length && a.every((val, index) => val === (b as Array<ComparableType>)[index])
    );
  }

  if (!Array.isArray(a) && Array.isArray(b)) {
    return b.includes(a);
  }

  if (Array.isArray(a) && !Array.isArray(b)) {
    return a.includes(b);
  }

  a = a as ComparableType;
  b = b as ComparableType;
  if (truthyValues.includes(a) && truthyValues.includes(b)) {
    return true;
  }

  if (falsyValues.includes(a) && falsyValues.includes(b)) {
    return true;
  }

  return a === b;
};

const greaterThan = (
  a: ComparableType | ComparableType[],
  b: ComparableType | ComparableType[]
) => {
  const predicate = (a: ComparableType, b: ComparableType) => {
    const dataFormat = detectDataFormat(a.toString());

    switch (dataFormat) {
      case SupportedDataFormat.BigInt:
      case SupportedDataFormat.Boolean:
        return BigInt(a) > BigInt(b);
      case SupportedDataFormat.DateTime:
        return Date.parse(a.toString()) > Date.parse(b.toString()); /// nanoseconds won't be compared.
      case SupportedDataFormat.Double:
      case SupportedDataFormat.String:
      default:
        return a > b;
    }
  };

  return operatorIndependentCheck(a, b, predicate);
};

const greaterThanOrEqual = (
  a: ComparableType | ComparableType[],
  b: ComparableType | ComparableType[]
) => {
  const predicate = (a: ComparableType, b: ComparableType) => {
    const dataFormat = detectDataFormat(a.toString());

    switch (dataFormat) {
      case SupportedDataFormat.BigInt:
      case SupportedDataFormat.Boolean:
        return BigInt(a) >= BigInt(b);
      case SupportedDataFormat.DateTime:
        return Date.parse(a.toString()) >= Date.parse(b.toString()); /// nanoseconds won't be compared.
      case SupportedDataFormat.Double:
      case SupportedDataFormat.String:
      default:
        return a >= b;
    }
  };

  return operatorIndependentCheck(a, b, predicate);
};

// a - field value
// b - true / false (exists operator values)
const existsComparator = (a: ComparableType | ComparableType[] | undefined, b: ComparableType) => {
  if (truthyValues.includes(b) && typeof a !== 'undefined') {
    // if exists val is true , a field val exists
    return true;
  }
  // if exists val is false , a field val doesn't exist
  if (falsyValues.includes(b) && (a === undefined || (Array.isArray(a) && !a.length))) {
    return true;
  }
  return false;
};

const inOperator = (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) => {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.every((val) => b.includes(val));
  }
  if (!Array.isArray(a) && Array.isArray(b)) {
    return b.includes(a);
  }
  if (Array.isArray(a) && !Array.isArray(b)) {
    return a.includes(b);
  }
  return false;
};

const betweenOperator = (
  a: ComparableType | ComparableType[],
  b: ComparableType | ComparableType[]
) => {
  if (!Array.isArray(b) || b.length !== 2) {
    throw new Error('$between/$nonbetween operator value should be 2 elements array');
  }
  
  // TODO: between operator is valid for RFC3339 dates and for YYYY-MM-DD dates, but b.map / or BigInt(a) fails for such strings. It must work
  const [min, max] = b.map(BigInt);
  const predicate = (val: bigint) => val >= min && val <= max;

  if (Array.isArray(a)) {
    return a.map(BigInt).every(predicate);
  }

  return predicate(BigInt(a));
};

export const comparatorOptions: { [v in FilterOperatorMethod]: FilterOperatorFunction } = {
  $noop: () => true,
  $sd: () => true,
  $exists: (a, b) => existsComparator(a, b),
  $eq: (a, b) => equalsComparator(a, b),
  $in: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    inOperator(a, b),
  $nin: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    !inOperator(a, b),
  $gt: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    greaterThan(a, b),
  $lt: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    !greaterThanOrEqual(a, b),
  $ne: (a, b) => !equalsComparator(a, b),
  $gte: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    greaterThanOrEqual(a, b),
  $lte: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    !greaterThan(a, b),
  $between: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    betweenOperator(a, b),
  $nonbetween: (a: ComparableType | ComparableType[], b: ComparableType | ComparableType[]) =>
    !betweenOperator(a, b)
};

/**
 * credential search path resolver
 *
 * @param {object} object - object to query
 * @param {string} path - given path
 * @param {*} [defaultValue=null]
 */
export const resolvePath = (object: object, path: string, defaultValue = null) => {
  const pathParts = path.split('.');
  let o = object;
  for (const part of pathParts) {
    if (o === null || o === undefined) {
      return defaultValue;
    }
    o = o[part as keyof typeof o];
  }
  return o;
};

/**
 * Filter for queries of credentialSubject with a json path e.g  birthday.date
 *
 *
 * @public
 * @class FilterQuery
 * @implements implements IFilterQuery interface
 */
export class FilterQuery implements IFilterQuery {
  /**
   * Creates an instance of FilterQuery.
   * @param {string} path
   * @param {FilterOperatorFunction} operatorFunc
   * @param {*} value
   * @param {boolean} [isReverseParams=false]
   */
  constructor(
    public path: string,
    public operatorFunc: FilterOperatorFunction,
    public value: any,
    public isReverseParams = false
  ) {}
  /** {@inheritdoc IFilterQuery} */
  execute(credential: W3CCredential): boolean {
    if (!this.operatorFunc) {
      throw new Error(SearchError.NotDefinedComparator);
    }
    const credentialPathValue = resolvePath(credential, this.path);
    if (
      (credentialPathValue === null || credentialPathValue === undefined) &&
      this.operatorFunc !== comparatorOptions.$exists
    ) {
      return false;
    }
    if (this.isReverseParams) {
      return this.operatorFunc(this.value, credentialPathValue);
    }
    return this.operatorFunc(credentialPathValue, this.value);
  }
}

/**
 * creates filters based on proof query
 * @param {ProofQuery} query - proof query
 * @returns {*}  {FilterQuery[]} - array of filters to apply
 */
export const StandardJSONCredentialsQueryFilter = (query: ProofQuery): FilterQuery[] => {
  return Object.keys(query).reduce((acc: FilterQuery[], queryKey) => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const queryValue: any = query[queryKey as keyof typeof query];
    switch (queryKey) {
      case 'claimId':
        return acc.concat(new FilterQuery('id', comparatorOptions.$eq, queryValue));
      case 'allowedIssuers': {
        const queryValueParam = queryValue || ['*'];
        if (queryValueParam.includes('*')) {
          return acc;
        }
        return acc.concat(new FilterQuery('issuer', comparatorOptions.$in, queryValue));
      }
      case 'type':
        return acc.concat(new FilterQuery('type', comparatorOptions.$in, queryValue, true));
      case 'context':
        return acc.concat(new FilterQuery('@context', comparatorOptions.$in, queryValue, true));
      case 'credentialSubjectId':
        return acc.concat(
          new FilterQuery('credentialSubject.id', comparatorOptions.$eq, queryValue)
        );
      case 'schema':
        return acc.concat(
          new FilterQuery('credentialSchema.id', comparatorOptions.$eq, queryValue)
        );
      case 'credentialSubject':
      case 'credentialStatus': {
        const reqFilters = Object.keys(queryValue).reduce((acc: FilterQuery[], fieldKey) => {
          const fieldParams = queryValue[fieldKey];
          if (typeof fieldParams === 'object' && Object.keys(fieldParams).length === 0) {
            return acc.concat([
              new FilterQuery(`${queryKey}.${fieldKey}`, comparatorOptions.$noop, null)
            ]);
          }
          const res = Object.keys(fieldParams).map((comparator) => {
            const value = fieldParams[comparator];
            const path = `${queryKey}.${fieldKey}`;
            return new FilterQuery(
              path,
              comparatorOptions[comparator as keyof typeof comparatorOptions],
              value
            );
          });
          return acc.concat(res);
        }, []);

        return acc.concat(reqFilters);
      }
      case 'expirationDate':
      case 'issuanceDate': {
        if (Object.keys(queryValue).length === 0) {
          return acc.concat([new FilterQuery(queryKey, comparatorOptions.$noop, null)]);
        }
        const res = Object.keys(queryValue).map((comparator) => {
          const rawValue = queryValue[comparator];
          // Credentials store these fields as ISO strings; convert Unix-second timestamps so
          // the date comparator (Date.parse) can handle both formats correctly.
          const value =
            typeof rawValue === 'number' || (typeof rawValue === 'string' && /^\d+$/.test(rawValue))
              ? new Date(Number(rawValue) * 1000).toISOString()
              : rawValue;
          return new FilterQuery(
            queryKey,
            comparatorOptions[comparator as keyof typeof comparatorOptions],
            value
          );
        });
        return acc.concat(res);
      }
      case 'proofType':
      case 'groupId':
      case 'skipClaimRevocationCheck': {
        return acc;
      }
      default:
        throw new Error(`${queryKey} : ${SearchError.NotDefinedQueryKey}`);
    }
  }, []);
};

const operatorIndependentCheck = (
  a: ComparableType | ComparableType[],
  b: ComparableType | ComparableType[],
  predicate: (a: ComparableType, b: ComparableType) => boolean
) => {
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.every((val, index) => predicate(val, (b as ComparableType[])[index]));
  }
  if (!Array.isArray(a) && Array.isArray(b)) {
    return b.every((val) => predicate(a, val));
  }
  if (Array.isArray(a) && !Array.isArray(b)) {
    return a.every((val) => predicate(val, b));
  }
  // in this case a and b are not arrays
  return predicate(a as ComparableType, b as ComparableType);
};

const regExBigInt = /^[+-]?\d+$/;
const regExDouble = /^(-?)(0|([1-9][0-9]*))(\\.[0-9]+)?$/;
const regExDateTimeRFC3339Nano =
  /* eslint-disable-next-line */
  /^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([\+|\-]([01][0-9]|2[0-3]):[0-5][0-9]))$/;
const regExBoolean = /^(true)|(false)$/;
const regExDateTimeYYYYMMDD = /^\d{4}-\d{2}-\d{2}$/;

const detectDataFormat = (s: string): SupportedDataFormat =>
  regExBigInt.test(s)
    ? SupportedDataFormat.BigInt
    : regExDouble.test(s)
    ? SupportedDataFormat.Double
    : regExDateTimeRFC3339Nano.test(s) || regExDateTimeYYYYMMDD.test(s)
    ? SupportedDataFormat.DateTime
    : regExBoolean.test(s)
    ? SupportedDataFormat.Boolean
    : SupportedDataFormat.String;
