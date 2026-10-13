import { hkdfSync, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import {
  generateAuthenticationOptions, generateRegistrationOptions,
  verifyAuthenticationResponse, verifyRegistrationResponse,
} from '@simplewebauthn/server';
import config from '../aleph.config.json' with { type: 'json' };

const app = new URL(config.publicAppUrl);
const origin = app.origin;
const rpID = app.hostname;
const CHALLENGE_LIFETIME_MS = 5 * 60 * 1000;
const CREDENTIAL_ID = /^[A-Za-z0-9_-]{16,1024}$/u;

function respond(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(payload);
}

function grantKey() {
  const secret = process.env.SUPABASE_SECRET_KEY;
  if (!secret) throw new Error('missing_server_configuration');
  return new Uint8Array(hkdfSync('sha256', secret, 'aleph-device-approval',
    'device-grant-v1', 32));
}

function bodyObject(request) {
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf8');
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

async function saveChallenge(database, ownerId, flow, challenge) {
  const id = randomUUID();
  const { error } = await database.from('device_challenges').insert({
    id, owner_id: ownerId, flow, challenge,
    expires_at: new Date(Date.now() + CHALLENGE_LIFETIME_MS).toISOString(),
  });
  if (error) throw new Error('device_store_unavailable');
  return id;
}

async function takeChallenge(database, ownerId, flow, id) {
  if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/iu.test(id)) return null;
  const { data, error } = await database.from('device_challenges')
    .update({ used_at: new Date().toISOString() })
    .eq('id', id).eq('owner_id', ownerId).eq('flow', flow)
    .is('used_at', null).gt('expires_at', new Date().toISOString())
    .select('challenge').maybeSingle();
  if (error) throw new Error('device_store_unavailable');
  return data?.challenge ?? null;
}

export async function deviceApproved(database, identity, grant) {
  if (identity?.kind !== 'student' || typeof grant !== 'string'
      || grant.length > 4096) return false;
  try {
    const { payload } = await jwtVerify(grant, grantKey(), {
      issuer: origin, audience: 'aleph-protected-data', algorithms: ['HS256'],
      maxTokenAge: '5 minutes',
    });
    if (payload.sub !== identity.userId || !CREDENTIAL_ID.test(payload.cid ?? '')) return false;
    const { data, error } = await database.from('device_credentials')
      .select('credential_id').eq('credential_id', payload.cid)
      .eq('owner_id', identity.userId).eq('status', 'approved').maybeSingle();
    return !error && Boolean(data);
  } catch { return false; }
}

export async function handleDeviceRequest(request, response, suppliedContext) {
  let context;
  try { context = suppliedContext ?? (await import('./notes-api.mjs')).getServices(); } catch {
    return respond(response, 503, { error: 'DEVICE_SERVICE_UNAVAILABLE' });
  }
  let identity;
  try { identity = await context.verifyLogin(request.headers?.authorization); } catch {}
  if (!identity) return respond(response, 401, { error: 'UNAUTHORIZED' });
  if (identity.kind !== 'student') return respond(response, 403, { error: 'DEVICE_NOT_APPROVED' });
  const action = request.query?.action;
  if (request.method !== 'POST' || typeof action !== 'string') {
    return respond(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }
  const database = context.database;
  const body = bodyObject(request);
  try {
    if (action === 'status') {
      const { data, error } = await database.from('device_credentials')
        .select('status').eq('owner_id', identity.userId);
      if (error) throw new Error('device_store_unavailable');
      return respond(response, 200, {
        approvedDeviceAvailable: data.some(row => row.status === 'approved'),
        approvalPending: data.some(row => row.status === 'pending'),
      });
    }
    if (action === 'register-options') {
      const { data, error } = await database.from('device_credentials')
        .select('credential_id,transports').eq('owner_id', identity.userId);
      if (error) throw new Error('device_store_unavailable');
      const options = await generateRegistrationOptions({
        rpName: '가상 자료실', rpID, userName: identity.userId,
        attestationType: 'none', supportedAlgorithmIDs: [-7, -257],
        authenticatorSelection: { authenticatorAttachment: 'platform',
          residentKey: 'preferred', userVerification: 'required' },
        excludeCredentials: data.map(row => ({ id: row.credential_id,
          transports: row.transports ?? [] })),
      });
      const requestId = await saveChallenge(database, identity.userId, 'registration', options.challenge);
      return respond(response, 200, { requestId, options });
    }
    if (action === 'register-verify') {
      const challenge = await takeChallenge(database, identity.userId, 'registration', body?.requestId);
      if (!challenge || !body?.response) return respond(response, 400, { error: 'INVALID_DEVICE_CHALLENGE' });
      let result;
      try { result = await verifyRegistrationResponse({ response: body.response,
        expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID,
        requireUserVerification: true }); } catch {
        return respond(response, 400, { error: 'INVALID_DEVICE_PROOF' });
      }
      if (!result.verified || !result.registrationInfo?.credential) {
        return respond(response, 400, { error: 'INVALID_DEVICE_PROOF' });
      }
      if (result.registrationInfo.credentialDeviceType !== 'singleDevice'
          || result.registrationInfo.credentialBackedUp) {
        return respond(response, 400, { error: 'DEVICE_BOUND_CREDENTIAL_REQUIRED' });
      }
      const credential = result.registrationInfo.credential;
      if (!CREDENTIAL_ID.test(credential.id)) {
        return respond(response, 400, { error: 'INVALID_DEVICE_PROOF' });
      }
      const { error } = await database.from('device_credentials').insert({
        credential_id: credential.id, owner_id: identity.userId,
        public_key: Buffer.from(credential.publicKey).toString('base64url'),
        counter: credential.counter, transports: credential.transports ?? [],
        status: 'pending',
      });
      if (error) return respond(response, 409, { error: 'DEVICE_ALREADY_REGISTERED' });
      return respond(response, 202, { status: 'pending', message: '기기 등록 요청을 접수했습니다. 관리자 승인을 기다려 주세요.' });
    }
    if (action === 'authenticate-options') {
      const { data, error } = await database.from('device_credentials')
        .select('credential_id,transports').eq('owner_id', identity.userId).eq('status', 'approved');
      if (error) throw new Error('device_store_unavailable');
      if (!data.length) return respond(response, 403, { error: 'DEVICE_NOT_APPROVED' });
      const options = await generateAuthenticationOptions({ rpID, userVerification: 'required',
        allowCredentials: data.map(row => ({ id: row.credential_id,
          transports: row.transports ?? [] })) });
      const requestId = await saveChallenge(database, identity.userId, 'authentication', options.challenge);
      return respond(response, 200, { requestId, options });
    }
    if (action === 'authenticate-verify') {
      const challenge = await takeChallenge(database, identity.userId, 'authentication', body?.requestId);
      if (!challenge || !CREDENTIAL_ID.test(body?.response?.id ?? '')) {
        return respond(response, 400, { error: 'INVALID_DEVICE_CHALLENGE' });
      }
      const { data: row, error } = await database.from('device_credentials')
        .select('credential_id,public_key,counter,transports').eq('credential_id', body.response.id)
        .eq('owner_id', identity.userId).eq('status', 'approved').maybeSingle();
      if (error || !row) return respond(response, 403, { error: 'DEVICE_NOT_APPROVED' });
      let result;
      try { result = await verifyAuthenticationResponse({ response: body.response,
        expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpID,
        requireUserVerification: true,
        credential: { id: row.credential_id,
          publicKey: new Uint8Array(Buffer.from(row.public_key, 'base64url')),
          counter: Number(row.counter), transports: row.transports ?? [] } }); } catch {
        return respond(response, 403, { error: 'INVALID_DEVICE_PROOF' });
      }
      if (!result.verified) return respond(response, 403, { error: 'INVALID_DEVICE_PROOF' });
      if (result.authenticationInfo.credentialDeviceType !== 'singleDevice'
          || result.authenticationInfo.credentialBackedUp) {
        return respond(response, 403, { error: 'DEVICE_BOUND_CREDENTIAL_REQUIRED' });
      }
      const { data: updated, error: updateError } = await database.from('device_credentials')
        .update({ counter: result.authenticationInfo.newCounter })
        .eq('credential_id', row.credential_id).eq('owner_id', identity.userId)
        .eq('status', 'approved').eq('counter', row.counter)
        .select('credential_id').maybeSingle();
      if (updateError || !updated) return respond(response, 409, { error: 'DEVICE_PROOF_RETRY' });
      const grant = await new SignJWT({ cid: row.credential_id })
        .setProtectedHeader({ alg: 'HS256' }).setSubject(identity.userId)
        .setIssuer(origin).setAudience('aleph-protected-data')
        .setIssuedAt().setExpirationTime('5m').sign(grantKey());
      return respond(response, 200, { approved: true, grant, expiresInSeconds: 300 });
    }
    return respond(response, 404, { error: 'NOT_FOUND' });
  } catch {
    return respond(response, 503, { error: 'DEVICE_SERVICE_UNAVAILABLE' });
  }
}
