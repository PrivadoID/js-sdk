import { describe, expect, it } from 'vitest';
import {
  createVerifiablePresentation,
  parseDocumentToPropertyQueries,
  parseJsonDocumentObject,
  parseZKPQuery,
  QueryMetadata,
  W3CCredential
} from '../../src';
import { Operators, QueryOperators } from '../../src/circuits';
import { ZeroKnowledgeProofQuery } from '../../src/iden3comm';

describe('createVerifiablePresentation selective disclosure', () => {
  it('discloses sibling fields of the same nested object without dropping any', () => {
    const credential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      credentialSubject: {
        id: 'did:example:subject',
        type: 'BasicPerson',
        addresses: {
          primaryAddress: {
            addressLine1: 'line-1',
            addressLine2: 'line-2'
          }
        }
      },
      credentialStatus: {
        id: 'https://example.com/status',
        type: 'Iden3ReverseSparseMerkleTreeProof'
      }
    } as unknown as W3CCredential;

    const queries = [
      {
        fieldName: 'credentialSubject.addresses.primaryAddress.addressLine1',
        operator: Operators.SD
      },
      {
        fieldName: 'credentialSubject.addresses.primaryAddress.addressLine2',
        operator: Operators.SD
      }
    ] as unknown as QueryMetadata[];

    const vp = createVerifiablePresentation('', 'BasicPerson', credential, queries);

    const credentialSubject = vp.verifiableCredential.credentialSubject as unknown as {
      addresses: { primaryAddress: { addressLine1: string; addressLine2: string } };
    };
    const disclosed = credentialSubject.addresses.primaryAddress;

    expect(disclosed.addressLine1).to.eq('line-1');
    expect(disclosed.addressLine2).to.eq('line-2');
  });

  it('does not include credentialStatus in VP when no credentialStatus fields are queried', () => {
    const credential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      credentialSubject: { id: 'did:example:subject', type: 'BasicPerson', age: 30 },
      credentialStatus: {
        id: 'https://example.com/status',
        type: 'Iden3ReverseSparseMerkleTreeProof'
      }
    } as unknown as W3CCredential;

    const queries = [
      { fieldName: 'credentialSubject.age', operator: Operators.SD }
    ] as unknown as QueryMetadata[];

    const vp = createVerifiablePresentation('', 'BasicPerson', credential, queries);
    expect(vp.verifiableCredential.credentialStatus).to.be.undefined;
  });

  it('includes credentialStatus skeleton in VP when credentialStatus fields are queried', () => {
    const credential = {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      credentialSubject: { id: 'did:example:subject', type: 'BasicPerson' },
      credentialStatus: {
        id: 'https://example.com/status',
        type: 'Iden3ReverseSparseMerkleTreeProof',
        revocationNonce: 42
      }
    } as unknown as W3CCredential;

    const queries = [
      { fieldName: 'credentialStatus.revocationNonce', operator: Operators.SD }
    ] as unknown as QueryMetadata[];

    const vp = createVerifiablePresentation('', 'BasicPerson', credential, queries);
    expect(vp.verifiableCredential.credentialStatus?.id).to.eq('https://example.com/status');
    expect(vp.verifiableCredential.credentialStatus?.type).to.eq(
      'Iden3ReverseSparseMerkleTreeProof'
    );
  });
});

describe('parseJsonDocumentObject', () => {
  it('accepts the $noop operator (operator value 0)', () => {
    const queries = parseJsonDocumentObject({ documentType: { $noop: '' } });
    expect(queries).to.deep.equal([
      { operator: QueryOperators.$noop, fieldName: 'documentType', operatorValue: '' }
    ]);
  });
});

describe('parseZKPQuery', () => {
  it('credentialSubject: {} throws — same as pre-PR behavior', () => {
    const query = {
      allowedIssuers: ['*'],
      context: '',
      type: '',
      credentialSubject: {}
    } as unknown as ZeroKnowledgeProofQuery;

    expect(() => parseZKPQuery(query)).to.throw('query must have at least 1 predicate');
  });

  it('credentialStatus: {} is treated as noop (no queries added)', () => {
    const query = {
      allowedIssuers: ['*'],
      context: '',
      type: '',
      credentialStatus: {}
    } as unknown as ZeroKnowledgeProofQuery;

    const queries = parseZKPQuery(query);
    expect(queries).to.deep.equal([{ operator: QueryOperators.$noop, fieldName: '' }]);
  });

  it('credentialStatus.revocationNonce passes through', () => {
    const query = {
      allowedIssuers: ['*'],
      context: '',
      type: '',
      credentialStatus: { revocationNonce: { $eq: 123 } }
    } as unknown as ZeroKnowledgeProofQuery;

    const queries = parseZKPQuery(query);
    expect(queries).to.have.length(1);
    expect(queries[0].fieldName).to.equal('credentialStatus.revocationNonce');
  });

  it('credentialStatus.id passes through', () => {
    const query = {
      allowedIssuers: ['*'],
      context: '',
      type: '',
      credentialStatus: { id: {} }
    } as unknown as ZeroKnowledgeProofQuery;

    const queries = parseZKPQuery(query);
    expect(queries).to.have.length(1);
    expect(queries[0].fieldName).to.equal('credentialStatus.id');
  });

  it('credentialStatus with only disallowed fields throws', () => {
    const query = {
      allowedIssuers: ['*'],
      context: '',
      type: '',
      credentialStatus: { type: {} }
    } as unknown as ZeroKnowledgeProofQuery;

    expect(() => parseZKPQuery(query)).to.throw(
      'credentialStatus query contains no allowed fields'
    );
  });

  it('only revocationNonce and id survive when other credentialStatus fields are present', () => {
    const query = {
      allowedIssuers: ['*'],
      context: '',
      type: '',
      credentialStatus: { id: {}, revocationNonce: {}, type: {} }
    } as unknown as ZeroKnowledgeProofQuery;

    const queries = parseZKPQuery(query);
    expect(queries).to.have.length(2);
    const fieldNames = queries.map((q) => q.fieldName);
    expect(fieldNames).to.include('credentialStatus.revocationNonce');
    expect(fieldNames).to.include('credentialStatus.id');
    expect(fieldNames).not.to.include('credentialStatus.type');
  });
});

describe('parseDocumentToPropertyQueries', () => {
  it('credentialSubject: {} throws — callers must name specific fields', () => {
    expect(() => parseDocumentToPropertyQueries('credentialSubject', {})).to.throw(
      'query must have at least 1 predicate'
    );
  });

  it('credentialSubject: undefined returns noop', () => {
    const queries = parseDocumentToPropertyQueries('credentialSubject', undefined);
    expect(queries).to.deep.equal([{ operator: QueryOperators.$noop, fieldName: '' }]);
  });
});
