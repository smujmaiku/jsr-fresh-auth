import { Cookie, getCookies, setCookie } from '@std/http/cookie';
import { createToken } from '@/uuid.ts';

/** Fresh-ish Context */
export interface Context<S = never> {
	req: Request;
	state: S;
	next: () => Promise<Response> | Response;
}

export interface AuthOptions {
	/** Cookie name */
	cookieName?: string;
	/** Cookie sessionStorage name */
	cookieSession?: string;
	/** Cookie max age in seconds */
	cookieMaxAge?: number;
	/** Cookie options */
	cookieOpts?: Cookie;
}

export type Middleware = (ctx: Context) => Promise<Response>;

export type AuthType = 'cookie' | 'header' | 'search';

export type AuthCallback<S> = (
	type: AuthType,
	data: unknown,
	ctx: Context<S>,
) => Promise<void>;

export type UpdateCallback<S> = (ctx: Context<S>) => Promise<unknown>;

/** Authentication middleware */
export function authMiddleware<S = never>(
	opts: AuthOptions,
	callback: AuthCallback<S>,
	updateCallback: UpdateCallback<S>,
): Middleware {
	const {
		cookieName = 'auth',
		cookieSession = 'auth:cookie',
		cookieMaxAge = 36_000,
		cookieOpts = {},
	} = opts;

	const getCookieKey = (token: string): string => {
		return `${cookieSession}:${token}`;
	};

	const getCookieStore = <S = never>(token: string): S | undefined => {
		try {
			return JSON.parse(
				sessionStorage.getItem(getCookieKey(token))!,
			) as S;
		} catch (_e) {}

		return undefined;
	};

	function createCookieStore(): string {
		const token = createToken();

		setTimeout(() => {
			sessionStorage.removeItem(getCookieKey(token));
		}, cookieMaxAge * 1_000);

		return token;
	}

	return (async (ctx: Context) => {
		const { req } = ctx;
		const { headers, url } = req;
		const { hostname } = new URL(url);

		// Process Cookie
		const currentCookie = getCookies(headers)[cookieName];
		const cookieState = getCookieStore(currentCookie);
		if (cookieState) {
			await callback('cookie', cookieState, ctx);
		}

		// TODO jwts
		// TODO search

		// Do request
		const res = await ctx.next();

		// Setup possible new cookie
		const newCookie = currentCookie ? undefined : createCookieStore();
		const cookie = currentCookie ?? newCookie;

		// Get state to store
		const state = !cookie ? undefined : await updateCallback(ctx);

		// Set browser cookie
		if (state && newCookie) {
			setCookie(res.headers, {
				name: cookieName,
				value: newCookie,
				maxAge: cookieMaxAge,
				sameSite: 'Lax',
				domain: hostname,
				path: '/',
				secure: true,
				...cookieOpts,
			});
			// delete cookie storage
		}

		// Store or remove cookie state
		if (cookie) {
			if (state) {
				sessionStorage.setItem(getCookieKey(cookie), JSON.stringify(state));
			} else {
				sessionStorage.removeItem(getCookieKey(cookie));
			}
		}

		return res;
	});
}

export default authMiddleware;
