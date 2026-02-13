import { Cookie, deleteCookie, getCookies, setCookie } from '@std/http/cookie';
import TTLStore from '@smujdev/ttl-store';
import { readJwt } from './jwt.ts';
import { createToken } from './uuid.ts';

/** Fresh-ish Context */
export interface Context<S> {
	req: Request;
	state: S;
	next: () => Promise<Response> | Response;
}

export interface AuthOptions {
	/** Cookie name */
	cookieName?: string;
	/** Cookie max age in seconds */
	cookieMaxAge?: number;
	/** Cookie options */
	cookieOpts?: Omit<Cookie, 'name' | 'value' | 'maxAge'>;
	/** Storage for session data */
	store?: Storage;
	/** Storage key */
	storeKey?: string;
	/** JWT Secret */
	jwtSecret?: Uint8Array;
	/** URL Search key */
	urlSearchName?: string;
	/** WebSocket protocol prefix */
	wsPrefix?: string;
}

export type Middleware<S> = (ctx: Context<S>) => Promise<Response>;

export type AuthType = 'cookie' | 'header' | 'urlSearch' | 'websocket';

export type AuthCallback<S> = (
	type: AuthType,
	data: unknown,
	ctx: Context<S>,
) => Promise<void> | void;

export type UpdateCallback<S> = (ctx: Context<S>) => Promise<unknown> | unknown;

/** Authentication middleware */
export function authMiddleware<S = never>(
	opts: AuthOptions,
	callback: AuthCallback<S>,
	updateCallback: UpdateCallback<S>,
): Middleware<S> {
	const {
		cookieName = 'auth',
		cookieMaxAge = 36_000,
		cookieOpts = {},
		store = localStorage,
		storeKey = 'auth',
		jwtSecret,
		urlSearchName,
		wsPrefix,
	} = opts;

	const ttlStore = new TTLStore(storeKey, store);

	const readHeaderBearer = (headers: Headers): string | undefined => {
		const authHeader = headers.get('authorization') || '';
		const [type, token] = authHeader?.split(' ');

		if (type !== 'bearer') return undefined;
		return token || undefined;
	};

	const readUrlSearch = (url: string): string | undefined => {
		if (!urlSearchName) return undefined;

		const { searchParams } = new URL(url);
		const token = searchParams.get(urlSearchName);

		return token || undefined;
	};

	const readWsProtocol = (headers: Headers): string | undefined => {
		if (!wsPrefix) return undefined;
		if (headers.get('Upgrade') !== 'websocket') return undefined;

		const allProto = headers.get('Sec-WebSocket-Protocol') || '';
		const proto = allProto.split(',').map((v) => v.trim()).find((v) =>
			v.startsWith(wsPrefix)
		);
		if (!proto) return undefined;

		const token = proto.slice(wsPrefix.length);
		return token || undefined;
	};

	return (async (ctx: Context<S>) => {
		const { req } = ctx;
		const { headers, url } = req;
		const { hostname } = new URL(url);

		// Process Cookie
		let currentCookie: string | undefined = getCookies(headers)[cookieName];
		const cookieState = ttlStore.getItem(currentCookie);
		if (cookieState) {
			await callback('cookie', cookieState, ctx);
		}

		let wsProtocolRes: string | undefined;

		if (jwtSecret) {
			// Process Authorization Header
			const headerToken = readHeaderBearer(headers);
			const headerState = await readJwt(headerToken || '', jwtSecret).catch(
				() => undefined,
			);
			if (headerState) {
				await callback('header', headerState, ctx);
			}

			// Process URL Search
			const searchToken = readUrlSearch(url);
			const searchState = await readJwt(searchToken || '', jwtSecret).catch(
				() => undefined,
			);
			if (searchState) {
				await callback('urlSearch', searchState, ctx);
			}

			// Process Sec-WebSocket-Protocol
			const wsToken = readWsProtocol(headers);
			const wsState = await readJwt(wsToken || '', jwtSecret).catch(
				() => undefined,
			);
			if (wsState) {
				await callback('websocket', wsState, ctx);
				wsProtocolRes = `${wsPrefix}${wsToken}`;
			}
		}

		// Do request
		const origRes = await ctx.next();

		// Protect against Resonse.redirect locking headers
		const origBody = origRes.body ? await origRes.arrayBuffer() : null;
		const res = new Response(origBody, origRes);

		// Accept Sec-WebSocket-Protocol
		const wsAccept = res.headers.get('Sec-Websocket-Accept');
		if (wsAccept && wsProtocolRes) {
			res.headers.set('Sec-WebSocket-Protocol', wsProtocolRes);
		}

		// Get state to store
		const state = await updateCallback(ctx);

		// Set browser cookie
		if (state && !currentCookie) {
			currentCookie = createToken();
			ttlStore.setItem(currentCookie, null, cookieMaxAge);
			setCookie(res.headers, {
				name: cookieName,
				value: currentCookie,
				maxAge: cookieMaxAge,
				httpOnly: true,
				sameSite: 'Lax',
				domain: hostname,
				path: '/',
				secure: true,
				...cookieOpts,
			});
		} else if (!state && currentCookie) {
			deleteCookie(res.headers, cookieName);
		}

		// Store or remove cookie state
		if (currentCookie) {
			if (state) {
				ttlStore.updateItem(currentCookie, state);
			} else {
				ttlStore.removeItem(currentCookie);
			}
		}

		return res;
	});
}

export default authMiddleware;
