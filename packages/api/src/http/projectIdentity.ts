import { createRemoteJWKSet, jwtVerify } from 'jose';

/** Project API access tokens issued for this API, after the provider's own login. */
export function projectIdentity(env: NodeJS.ProcessEnv = process.env) {
  const issuer = env.SECSCAN_OIDC_ISSUER,
    audience = env.SECSCAN_OIDC_AUDIENCE,
    uri = env.SECSCAN_OIDC_JWKS;
  if (!issuer && !audience && !uri) return undefined;
  if (
    !issuer ||
    !audience ||
    !uri ||
    new URL(issuer).protocol !== 'https:' ||
    new URL(uri).protocol !== 'https:'
  ) {
    throw new Error('Set HTTPS OIDC issuer and JWKS URL plus a dedicated project API audience');
  }
  const keys = createRemoteJWKSet(new URL(uri), { timeoutDuration: 3500 });
  return async (header: string | undefined): Promise<string | null> => {
    const token = /^Bearer\s+(\S+)$/i.exec(header ?? '')?.[1];
    if (!token) return null;
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer,
        audience,
        algorithms: ['RS256', 'ES256'],
        requiredClaims: ['sub', 'exp', 'iat'],
      });
      if (!payload.sub) return null;
      return issuer + '#' + payload.sub;
    } catch {
      return null;
    }
  };
}
