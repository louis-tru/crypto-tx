/* ***** BEGIN LICENSE BLOCK *****
 * Distributed under the BSD license:
 *
 * Copyright (c) 2015, xuewen.chu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of xuewen.chu nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL xuewen.chu BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ***** END LICENSE BLOCK ***** */

import {isTypedArray} from 'somes/buffer';

const toString = Object.prototype.toString;

export default function assert(value: any, message: any) {
	if (!value) throw Error(message);
}

// TypeError
export function isArray(value: any, message: any) {
	if (!Array.isArray(value)) throw TypeError(message)
}

export function isBoolean(value: any, message: any) {
	if (toString.call(value) !== '[object Boolean]') throw TypeError(message)
}

export function isBuffer(value: any, message: any) {
	if (!isTypedArray(value)) throw TypeError(message)
}

export function isFunction(value: any, message: any) {
	if (toString.call(value) !== '[object Function]') throw TypeError(message)
}

export function isNumber(value: any, message: any) {
	if (toString.call(value) !== '[object Number]') throw TypeError(message)
}

export function isObject(value: any, message: any) {
	if (toString.call(value) !== '[object Object]') throw TypeError(message)
}

// RangeError
export function isBufferLength(buffer: any, length: number, message: any) {
	if (buffer.length !== length) throw RangeError(message)
}

export function isBufferLength2(buffer: any, length1: number, length2: number, message: any) {
	if (buffer.length !== length1 && buffer.length !== length2) throw RangeError(message)
}

export function isLengthGTZero(value: any, message: any) {
	if (value.length === 0) throw RangeError(message)
}

export function isNumberInInterval(number: number, x: number, y: number, message: any) {
	if (number <= x || number >= y) throw RangeError(message)
}

export function isString(s: any, message: any) {
	if (typeof s != 'string') throw TypeError(message)
}