import path from 'node:path';
import { DID } from '@iden3/js-iden3-core';
import { Token, ProvingMethodAlg, proving } from '@iden3/js-jwz';

import {
  byteDecoder,
  byteEncoder,
  CircuitId,
  CredentialStatusResolverRegistry,
  CredentialStatusType,
  CredentialWallet,
  DefaultZKPPacker,
  FSCircuitStorage,
  IdentityWallet,
  ProofService,
  RHSResolver,
  ZKPPacker,
  ZKPPackerParams,
  PROTOCOL_CONSTANTS,
  AuthV2PubSignals
} from '../../src';
import { beforeAll, describe, expect, it, vi } from 'vitest';
import { initZKPPacker } from './mock/proving';
import {
  MOCK_STATE_STORAGE,
  SEED_USER,
  createIdentity,
  getInMemoryDataStorage,
  registerKeyProvidersInMemoryKMS
} from '../helpers';
describe('zkp packer tests', () => {
  it('test zkp packer pack', async () => {
    const p = await initZKPPacker();

    const msgBytes = byteEncoder.encode(
      `{"type":"https://iden3-communication.io/authorization/1.0/response","from":"did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29","body":{"scope":[{"type":"zeroknowledge","circuit_id":"auth","pub_signals":["1","18311560525383319719311394957064820091354976310599818797157189568621466950811","323416925264666217617288569742564703632850816035761084002720090377353297920"],"proof_data":{"pi_a":["11130843150540789299458990586020000719280246153797882843214290541980522375072","1300841912943781723022032355836893831132920783788455531838254465784605762713","1"],"pi_b":[["20615768536988438336537777909042352056392862251785722796637590212160561351656","10371144806107778890538857700855108667622042215096971747203105997454625814080"],["19598541350804478549141207835028671111063915635580679694907635914279928677812","15264553045517065669171584943964322117397645147006909167427809837929458012913"],["1","0"]],"pi_c":["16443309279825508893086251290003936935077348754097470818523558082502364822049","2984180227766048100510120407150752052334571876681304999595544138155611963273","1"],"protocol":""}}]}}`
    );

    const identifier = 'did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29';
    const senderDID = DID.parse(identifier);

    const b = await p.pack(msgBytes, {
      senderDID: senderDID,
      profileNonce: 0, // if it's genesis identity
      provingMethodAlg: new ProvingMethodAlg('groth16-mock', 'authV2')
    } as unknown as ZKPPackerParams);
    const t = await Token.parse(byteDecoder.decode(b));
    const outs = new AuthV2PubSignals().pubSignalsUnmarshal(
      byteEncoder.encode(JSON.stringify(t.zkProof.pub_signals))
    );

    const didFromToken = DID.parseFromId(outs.userID);
    expect(senderDID.string()).to.deep.equal(didFromToken.string());
  });

  it('test plain message packer', async () => {
    const p = await initZKPPacker({ alg: 'groth16' });

    const msgZKP = byteEncoder.encode(
      `eyJhbGciOiJncm90aDE2IiwiY2lyY3VpdElkIjoiYXV0aFYyIiwiY3JpdCI6WyJjaXJjdWl0SWQiXSwidHlwIjoiYXBwbGljYXRpb24vaWRlbjMtemtwLWpzb24ifQ.eyJpZCI6IjBmYmQ3NjZhLTM3YmItNGI3My05YzlmLTQ1NWQyNGE1YjI5OSIsInR5cCI6ImFwcGxpY2F0aW9uL2lkZW4zLXprcC1qc29uIiwidHlwZSI6Imh0dHBzOi8vaWRlbjMtY29tbXVuaWNhdGlvbi5pby9hdXRob3JpemF0aW9uLzEuMC9yZXNwb25zZSIsInRoaWQiOiJmZGU1MGRkMS0xOTEyLTQyOGQtODE0NS05MDYwNTEyY2M3YWEiLCJib2R5Ijp7Im1lc3NhZ2UiOiIiLCJzY29wZSI6W119LCJmcm9tIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4N1o5NVZrVXV5bzZtcXJhSncyVkd3Q2ZxVHpkcWhNMVJWalJIemNwSyIsInRvIjoiZGlkOmlkZW4zOnBvbHlnb246YW1veTp4Q1JwNzVEZ0FkUzYzVzY1Zm1YSHo2cDlEd2RvbnVSVTllNDZEaWZoWCJ9.eyJwcm9vZiI6eyJwaV9hIjpbIjEwMjc1MjUzOTg4NDU2OTIwMzYyODg3OTE5NzM5NTI2OTMxNzQ2NDcxNDcyMDEyMzY0MjY1MjEwMjgyMDIzMjM5NzA3NzQ2Nzk2MDU4IiwiMTkxNTE4OTA4MTY4MjE5NjExMjY4NDQzNTIyNjMyNDQ2NTc3MTgxMDc4OTc2MDkzODk2NTQyNjk3ODMzMzc5OTg0MTIxNjI3ODY3MTIiLCIxIl0sInBpX2IiOltbIjQ4NjQ1NDU3NDc2NDMxODI0ODY2MDgzNzYxNDM2MzkwNjgzNjE1ODk2MTM0NDA1MzAxNzk0MDI2NzQ4MTYxNjYwNjQzNjM4Njc3MjgiLCIxNDE0MDg3NjAxNzQxNTI5NzQ5NjYwMzAzODAyODQ0ODAxODgwNTEyMTY1NjI0ODMwMjUzMzU1NDk3MDI3ODM3MDk5NTUxMDA5OTU2MCJdLFsiODAxMTE0MDIyNjI3OTMwNzI3NjI5OTYxMjA2Mzc3NjE3NDUyODk1NzExMzI4NjA3Mzk3Nzk0NDU4NzkzNjM3MDIxNzg0NTY1NDQ1MyIsIjEwODg2MzE2MDcyNTAyNTEyMjM5NTI3NzI5NzI2MTI5ODgyNDM5NzY5NTI4NDcxNjgxODEyMDM0MjIyMzkwNjkwNjkzNTQ0MjU0MTE4Il0sWyIxIiwiMCJdXSwicGlfYyI6WyIyMDY5NzkwNTEwOTA0ODQxNzgzNDc4NzM1NTU4MTg3Mjc4NDU5NzMwNjYwNjE4MDk5NTU3MjA5MTM2MDU4MjA4MjE0MjYzMTk3NzI4MCIsIjE0MzcwOTQ1MzAyNjkzMTg2Mzg0NDMxMDM4Njc5MzcwMzY5MDExMjU4MDgyMDQ3MzkzNzI1Nzk4NjUyMTc0MjQ3NDczNDM3OTM5NTY4IiwiMSJdLCJwcm90b2NvbCI6Imdyb3RoMTYiLCJjdXJ2ZSI6ImJuMTI4In0sInB1Yl9zaWduYWxzIjpbIjIxNTc1MTI3MjE2MjM2MjQ4ODY5NzAyMjc2MjQ2MDM3NTU3MTE5MDA3NDY2MTgwMzAxOTU3NzYyMTk2NTkzNzg2NzMzMDA3NjE3IiwiMTI3MjEzMTA2MDgxMzMwNzg4ODExMTY2OTA5ODg0MTQ2OTkyMzU2NzY4MjM0NjgxNDg1MjI5NjY1MTU5NTUxMjU2MjQ5NTQ2MjAyMDQiLCIxNzg0OTk4MTcyMDYzNDIxMjgwMjY2NDE4OTkyOTY3MTE0MDc2MjU1NzQ4MzIzNjcwODA5NzcyMzg4NDE3MjY0MTEyNDY5MTIyMjI5OCJdfQ`
    );
    const iden3msg = await p.unpack(msgZKP);

    expect(
      PROTOCOL_CONSTANTS.PROTOCOL_MESSAGE_TYPE.AUTHORIZATION_RESPONSE_MESSAGE_TYPE
    ).to.deep.equal(iden3msg.type);
  });

  it('test getSupportedProfiles', async () => {
    const p = await initZKPPacker();
    const [accept] = p.getSupportedProfiles();
    expect(accept).to.be.eq(
      `iden3comm/v1;env=${PROTOCOL_CONSTANTS.MediaType.ZKPMessage};alg=groth16;circuitIds=authV2`
    );
  });

  describe('verifyToken', () => {
    const prepare = async () => {
      const kms = registerKeyProvidersInMemoryKMS();
      const dataStorage = getInMemoryDataStorage(MOCK_STATE_STORAGE);
      const circuitStorage = new FSCircuitStorage({
        dirname: path.join(__dirname, '../proofs/testdata')
      });
      const resolvers = new CredentialStatusResolverRegistry();
      resolvers.register(
        CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
        new RHSResolver(dataStorage.states)
      );
      const credWallet = new CredentialWallet(dataStorage, resolvers);
      const idWallet = new IdentityWallet(kms, dataStorage, credWallet);
      const proofService = new ProofService(
        idWallet,
        credWallet,
        circuitStorage,
        MOCK_STATE_STORAGE
      );
      const { did } = await createIdentity(idWallet, {
        seed: SEED_USER,
        revocationOpts: {
          type: CredentialStatusType.Iden3ReverseSparseMerkleTreeProof,
          id: 'https://rhs.example.com',
          genesisPublishingDisabled: true
        }
      });
      const verifyState = vi.spyOn(proofService, 'verifyState').mockResolvedValue(true);
      const packer = new DefaultZKPPacker(circuitStorage, proofService, {
        acceptedStateTransitionDelay: 1000
      });
      const packed = await packer.pack(byteEncoder.encode('payload that is not JSON'), {
        senderDID: did,
        profileNonce: 0,
        provingMethodAlg: proving.provingMethodGroth16AuthV3Instance.methodAlg
      } as ZKPPackerParams);
      const token = await Token.parse(byteDecoder.decode(packed));
      return { packer, token, did, verifyState };
    };

    let setup: () => ReturnType<typeof prepare>;

    beforeAll(async () => {
      const prepared = await prepare();
      setup = async () => prepared;
    }, 60000);

    it('accepts a token that the packer packed when the sender is right', async () => {
      const { packer, token, did, verifyState } = await setup();
      const referenceTime = new Date('2026-01-01T00:00:00Z');
      await expect(
        packer.verifyToken(token, did.string(), { referenceTime })
      ).resolves.toBeUndefined();
      expect(verifyState).toHaveBeenCalledWith(CircuitId.AuthV3, token.zkProof.pub_signals, {
        acceptedStateTransitionDelay: 1000,
        referenceTime
      });
    });

    it('throws when the sender is not the sender of the token', async () => {
      const { packer, token } = await setup();
      const other = 'did:iden3:polygon:mumbai:x4jcHP4XHTK3vX58AHZPyHE8kYjneyE6FZRfz7K29';
      await expect(packer.verifyToken(token, other)).rejects.toThrow(
        'sender of message is not used for jwz token creation'
      );
    });

    it('throws when the state verification function refuses the state', async () => {
      const { packer, token, did, verifyState } = await setup();
      verifyState.mockResolvedValueOnce(false);
      await expect(packer.verifyToken(token, did.string())).rejects.toThrow(
        'message state verification failed'
      );
    });

    it('throws when there are no verification parameters for the circuit', async () => {
      const { token, did } = await setup();
      const packer = new ZKPPacker(new Map(), new Map());
      await expect(packer.verifyToken(token, did.string())).rejects.toThrow(
        'message was packed with unsupported circuit'
      );
    });
  });
});
