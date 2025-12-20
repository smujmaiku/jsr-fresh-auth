import { Cookie, deleteCookie, getCookies, setCookie } from '@std/http/cookie';
import { createToken } from '@/uuid.ts';

/** Fresh-ish Context */
export interface Context<S> {
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
	cookieOpts?: Omit<Cookie, 'name' | 'value' | 'maxAge'>;
}

export type Middleware<S> = (ctx: Context<S>) => Promise<Response>;

export type AuthType = 'cookie' | 'header' | 'search';

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
		cookieSession = 'auth:cookie',
		cookieMaxAge = 36_000,
		cookieOpts = {},
	} = opts;

	const getCookieKey = (token: string): string => {
		return `${cookieSession}:${token}`;
	};

	const getCookieStore = (token: string): S | undefined => {
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

	return (async (ctx: Context<S>) => {
		const { req } = ctx;
		const { headers, url } = req;
		const { hostname } = new URL(url);

		// Process Cookie
		let currentCookie: string | undefined = getCookies(headers)[cookieName];
		const cookieState = getCookieStore(currentCookie);
		if (cookieState) {
			await callback('cookie', cookieState, ctx);
		} else if (currentCookie) {
			deleteCookie(headers, currentCookie);
			currentCookie = undefined;
		}

		// TODO jwts
		// TODO search

		// Do request
		const res = await ctx.next();

		// Get state to store
		const state = await updateCallback(ctx);

		// Set browser cookie
		if (state && !currentCookie) {
			currentCookie = createCookieStore();
			setCookie(res.headers, {
				name: cookieName,
				value: currentCookie,
				maxAge: cookieMaxAge,
				sameSite: 'Lax',
				domain: hostname,
				path: '/',
				secure: true,
				...cookieOpts,
			});
		}

		// Store or remove cookie state
		if (currentCookie) {
			if (state) {
				sessionStorage.setItem(
					getCookieKey(currentCookie),
					JSON.stringify(state),
				);
			} else {
				sessionStorage.removeItem(getCookieKey(currentCookie));
			}
		}

		return res;
	});
}

export default authMiddleware;
