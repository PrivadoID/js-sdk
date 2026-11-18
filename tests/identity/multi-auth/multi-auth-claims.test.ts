/**
 * Identity with multiple auth claims.
 *
 * An identity (BJJ- or Ethereum-based) holds several AuthBJJ claims in its claims tree. The first key belongs to the
 * owner; a delegate generates a key on their own device and the owner adds only its public key
 * to the identity. The delegate can then produce authV3 proofs / JWZ tokens whose sender is the
 * identity's DID (e.g. an officer acting as an organization). Revoking the delegate's auth claim
 * cuts off that ability without changing the DID.
 *
 * Runs offline against an in-memory State contract (see env.ts for circuits).
 */
import { describe, expect, it, beforeAll } from 'vitest';
import { DID } from '@iden3/js-iden3-core';
import { PublicKey, getRandomBytes } from '@iden3/js-crypto';
import { KmsKeyType, W3CCredential } from '../../../src';
import { Device, IdentityType, MultiAuthEnv, SMT_REVOCATION, createMultiAuthEnv } from './env';

describe.each<{ name: string; type: IdentityType }>([
  { name: 'BJJ-based', type: 'bjj' },
  { name: 'Ethereum-based', type: 'eth' }
])('$name identity with multiple auth claims', ({ type }) => {
  let env: MultiAuthEnv;

  let verifier: Device;
  let owner: Device; // created the identity, holds its first auth key
  let delegate: Device; // holds an extra auth key of the same identity on another device

  let verifierDID: DID;
  let did: DID;
  let delegateAuthCredential: W3CCredential;

  beforeAll(async () => {
    env = await createMultiAuthEnv();

    verifier = await env.newDevice();
    verifierDID = await env.createDID(verifier);

    owner = await env.newDevice({ sharedTrees: true });
    did = await env.createDID(owner, type);
    env.revocation.registerIssuer(did, owner.idWallet);

    // the delegate creates a key on their device; only the public key reaches the owner, which
    // adds it to the identity as an extra AuthBJJ claim (state transition on chain)
    delegate = await env.newDevice({ sharedTrees: true });
    const delegateKeyId = await delegate.kms.createKeyFromSeed(
      KmsKeyType.BabyJubJub,
      getRandomBytes(32)
    );
    const delegatePubKey = PublicKey.newFromHex(await delegate.kms.publicKey(delegateKeyId));

    delegateAuthCredential = await owner.idWallet.addBJJAuthCredential(
      did,
      await env.latestTreeState(owner, did),
      await env.isGenesis(owner, did),
      env.ethSigner,
      { publicKey: delegatePubKey, revocationOpts: SMT_REVOCATION },
      env.prover
    );
    await delegate.credWallet.save(delegateAuthCredential);
  }, 600_000);

  it('identity holds two independently revocable auth claims and its state is published', async () => {
    const authCreds = await owner.credWallet.getAllAuthBJJCredentials(did);
    expect(authCreds).toHaveLength(2);
    const nonces = authCreds.map((c) => c.credentialStatus.revocationNonce);
    expect(new Set(nonces).size).toBe(2);
    const latest = await env.chain.getLatestStateById(DID.idFromDID(did).bigInt());
    expect(latest.state).toBe((await env.latestTreeState(owner, did)).state.bigInt());
    // the owner wallet does not hold the delegate's private key
    await expect(owner.idWallet.signChallenge(1n, delegateAuthCredential)).rejects.toThrow();
  });

  it('delegate authenticates as the identity with their own key', async () => {
    const request = env.newRequest(verifierDID, 'Approve contract #42');
    const response = await env.verify(verifier, await env.respond(delegate, did, request), request);
    expect(response.from).toBe(did.string());
    expect(response.body.message).toBe('Approve contract #42');
  });

  it('a holder without an auth key of the identity cannot authenticate as it', async () => {
    const outsider = await env.newDevice({ sharedTrees: true });
    await outsider.credWallet.saveAll(await owner.credWallet.getAllAuthBJJCredentials(did));
    await expect(
      env.respond(outsider, did, env.newRequest(verifierDID, 'Pay 5M to Mallory'))
    ).rejects.toThrow(/no auth credentials found/i);
  });

  it('revoking the delegate auth claim stops the delegate; DID and owner key are unchanged', async () => {
    await env.revokeAndPublish(owner, did, delegateAuthCredential);
    await expect(
      env.respond(delegate, did, env.newRequest(verifierDID, 'Approve contract #43'))
    ).rejects.toThrow(/no auth credentials found/i);

    const request = env.newRequest(verifierDID, 'Rotate delegates');
    const response = await env.verify(verifier, await env.respond(owner, did, request), request);
    expect(response.from).toBe(did.string());
  });
});
