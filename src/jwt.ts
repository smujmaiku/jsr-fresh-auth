import * as jose from '@panva/jose';
import uuidSmall from './uuid.ts';

export async function readJwt(
	token: string,
	jwtSecret: Uint8Array,
	jwtOptions?: jose.JWTVerifyOptions,
): Promise<
	jose.JWTPayload & { sub: string; iat: number; exp: number }
> {
	const { payload } = await jose.jwtVerify(token, jwtSecret, {
		currentDate: new Date(),
		...jwtOptions,
	});
	const { sub, iat, exp } = payload;

	if (!sub || !iat || !exp) {
		throw new Error('Invalid JWT');
	}

	return { ...payload, sub, iat, exp };
}

export async function signJwt(
	payload: jose.JWTPayload,
	jwtSecret: Uint8Array,
	maxAge: number,
): Promise<string> {
	const now = Math.floor(Date.now() / 1000);

	const token = await new jose.CompactSign(
		new TextEncoder().encode(JSON.stringify({
			iat: now,
			exp: now + maxAge * 1_000,
			jti: uuidSmall(),
			...payload,
		})),
	).setProtectedHeader({
		'alg': 'HS256',
		'typ': 'JWT',
	}).sign(jwtSecret);

	return token;
}
