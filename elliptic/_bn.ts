
export default class BN {
	private _value: bigint;

	get value() {
		return this._value;
	}

	constructor(num: bigint | number | string) {
		this._value = BigInt(num);
	}
}