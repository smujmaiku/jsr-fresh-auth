export const TIME_PAD = 7;
export const INDEX_PAD = 5;

const LASTTIME_KEY = 'authuuid:lastTime';
const LASTINDEX_KEY = 'authuuid:lastIndex';

/** Create the smaller uuid */
export function createUuid(time: number, index: number): string {
	return [
		time.toString(36).padStart(TIME_PAD, '0'),
		index.toString(36).padStart(INDEX_PAD, '0'),
	].join('');
}

/**
 * Create a smaller uuid that is sortable
 * Concept from firebase key generator
 */
export function uuidSmall(): string {
	const now = Math.floor(Date.now() / 1000);
	const lastTime = Number(localStorage.getItem(LASTTIME_KEY));
	let lastIndex = Number(localStorage.getItem(LASTINDEX_KEY));

	if (now !== lastTime || isNaN(lastIndex)) {
		localStorage.setItem(LASTTIME_KEY, `${now}`);
		lastIndex = Math.floor(Math.random() * 36 ** (INDEX_PAD - 1));
	} else {
		lastIndex += 1;
	}
	localStorage.setItem(LASTINDEX_KEY, `${lastIndex}`);

	return createUuid(now, lastIndex);
}

/** Create random unique token */
export function createToken(): string {
	return [
		uuidSmall(),
		Math.random().toString(36).slice(2),
		Math.random().toString(36).slice(2),
		Math.random().toString(36).slice(2),
	].join('-');
}

export default uuidSmall;
