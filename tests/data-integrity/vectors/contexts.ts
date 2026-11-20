import { VerifiableConstants } from '../../../src';

const DID_V1_CONTEXT = `{
  "@context": {
    "@protected": true,
    "id": "@id",
    "type": "@type",

    "alsoKnownAs": {
      "@id": "https://www.w3.org/ns/activitystreams#alsoKnownAs",
      "@type": "@id"
    },
    "assertionMethod": {
      "@id": "https://w3id.org/security#assertionMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "authentication": {
      "@id": "https://w3id.org/security#authenticationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityDelegation": {
      "@id": "https://w3id.org/security#capabilityDelegationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "capabilityInvocation": {
      "@id": "https://w3id.org/security#capabilityInvocationMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "controller": {
      "@id": "https://w3id.org/security#controller",
      "@type": "@id"
    },
    "keyAgreement": {
      "@id": "https://w3id.org/security#keyAgreementMethod",
      "@type": "@id",
      "@container": "@set"
    },
    "service": {
      "@id": "https://www.w3.org/ns/did#service",
      "@type": "@id",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "serviceEndpoint": {
          "@id": "https://www.w3.org/ns/did#serviceEndpoint",
          "@type": "@id"
        }
      }
    },
    "verificationMethod": {
      "@id": "https://w3id.org/security#verificationMethod",
      "@type": "@id"
    }
  }
}
`;

const DATA_INTEGRITY_V2_CONTEXT = `{
  "@context": {
    "id": "@id",
    "type": "@type",
    "@protected": true,
    "proof": {
      "@id": "https://w3id.org/security#proof",
      "@type": "@id",
      "@container": "@graph"
    },
    "DataIntegrityProof": {
      "@id": "https://w3id.org/security#DataIntegrityProof",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "nonce": "https://w3id.org/security#nonce",
        "previousProof": {
          "@id": "https://w3id.org/security#previousProof",
          "@type": "@id"
        },
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "cryptosuite": {
          "@id": "https://w3id.org/security#cryptosuite",
          "@type": "https://w3id.org/security#cryptosuiteString"
        },
        "proofValue": {
          "@id": "https://w3id.org/security#proofValue",
          "@type": "https://w3id.org/security#multibase"
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}`;

const DID_CONFIGURATION_V1_CONTEXT = `{
  "@context": [
    {
      "@version": 1.1,
      "@protected": true,
      "LinkedDomains": "https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains",
      "DomainLinkageCredential": "https://identity.foundation/.well-known/resources/did-configuration/#DomainLinkageCredential",
      "origin": "https://identity.foundation/.well-known/resources/did-configuration/#origin",
      "linked_dids": "https://identity.foundation/.well-known/resources/did-configuration/#linked_dids"
    }
  ]
}
`;

const JWS_2020_V1_CONTEXT = `{
  "@context": {
    "privateKeyJwk": {
      "@id": "https://w3id.org/security#privateKeyJwk",
      "@type": "@json"
    },
    "JsonWebKey2020": {
      "@id": "https://w3id.org/security#JsonWebKey2020",
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "publicKeyJwk": {
          "@id": "https://w3id.org/security#publicKeyJwk",
          "@type": "@json"
        }
      }
    },
    "JsonWebSignature2020": {
      "@id": "https://w3id.org/security#JsonWebSignature2020",
      "@context": {
        "@protected": true,

        "id": "@id",
        "type": "@type",

        "challenge": "https://w3id.org/security#challenge",
        "created": {
          "@id": "http://purl.org/dc/terms/created",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "domain": "https://w3id.org/security#domain",
        "expires": {
          "@id": "https://w3id.org/security#expiration",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "jws": "https://w3id.org/security#jws",
        "nonce": "https://w3id.org/security#nonce",
        "proofPurpose": {
          "@id": "https://w3id.org/security#proofPurpose",
          "@type": "@vocab",
          "@context": {
            "@protected": true,

            "id": "@id",
            "type": "@type",

            "assertionMethod": {
              "@id": "https://w3id.org/security#assertionMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "authentication": {
              "@id": "https://w3id.org/security#authenticationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityInvocation": {
              "@id": "https://w3id.org/security#capabilityInvocationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "capabilityDelegation": {
              "@id": "https://w3id.org/security#capabilityDelegationMethod",
              "@type": "@id",
              "@container": "@set"
            },
            "keyAgreement": {
              "@id": "https://w3id.org/security#keyAgreementMethod",
              "@type": "@id",
              "@container": "@set"
            }
          }
        },
        "verificationMethod": {
          "@id": "https://w3id.org/security#verificationMethod",
          "@type": "@id"
        }
      }
    }
  }
}
`;

export const VECTOR_CONTEXTS: Record<string, string> = {
  'https://www.w3.org/ns/did/v1': DID_V1_CONTEXT,
  'https://w3id.org/security/data-integrity/v2': DATA_INTEGRITY_V2_CONTEXT,
  'https://identity.foundation/.well-known/did-configuration/v1': DID_CONFIGURATION_V1_CONTEXT,
  'https://w3id.org/security/suites/jws-2020/v1': JWS_2020_V1_CONTEXT,
  [VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD_URL]:
    VerifiableConstants.AUTH.AUTH_BJJ_CREDENTIAL_SCHEMA_JSONLD,
  [VerifiableConstants.JSONLD_SCHEMA.W3C_CREDENTIAL_2018]:
    VerifiableConstants.JSONLD_SCHEMA.W3C_VC_DOCUMENT_2018,
  [VerifiableConstants.JSONLD_SCHEMA.IDEN3_CREDENTIAL]:
    VerifiableConstants.JSONLD_SCHEMA.IDEN3_PROOFS_DEFINITION_DOCUMENT
};
