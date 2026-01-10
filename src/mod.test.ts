import { describe, it } from '@std/testing/bdd';
import { FakeTime } from '@std/testing/time';
import { expect, fn } from '@std/expect';
import freshAuth, { Context } from './mod.ts';

const td = new TextDecoder();
const jwtSecret = new Uint8Array([1, 2, 3, 4]);

describe('mod', () => {
	it('should store state', async () => {
		using _time = new FakeTime();

		const res = new Response('<html />');
		const ctx: Context<{ sub: string }> = {
			req: new Request('http://test.smuj.dev', {}),
			state: { sub: 'mockSub' },
			next: fn(() => res),
		};

		const result = await freshAuth<{ sub: string }>(
			{ cookieName: 'mockName', jwtSecret },
			() => {},
			async () => ({
				sub: 'mockSub',
			}),
		)(ctx);

		expect(td.decode(await result.arrayBuffer())).toEqual('<html />');
		expect(result.headers.get('set-cookie')).toMatch(
			/mockName=[0-9a-zA-Z\-]+; Secure; HttpOnly; Max-Age=36000; Domain=test.smuj.dev; SameSite=Lax; Path=\//,
		);
	});

	it('should not crash on redirects', async () => {
		using _time = new FakeTime();

		const res = Response.redirect(
			'http://test.smuj.dev/redirect',
		);
		const ctx: Context<{ sub: string }> = {
			req: new Request('http://test.smuj.dev', {}),
			state: { sub: 'mockSub' },
			next: fn(() => res),
		};

		const result = await freshAuth<{ sub: string }>(
			{ cookieName: 'mockName', jwtSecret },
			() => {},
			async () => ({
				sub: 'mockSub',
			}),
		)(ctx);

		expect(result.headers.get('set-cookie')).toBeDefined();
		expect(result.headers.get('location')).toBe(
			'http://test.smuj.dev/redirect',
		);
	});
});
