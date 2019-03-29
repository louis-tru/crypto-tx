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

module.exports = {
	"genesisGasLimit": {
		"v": 5000,
		"d": "Gas limit of the Genesis block."
	},
	"genesisDifficulty": {
		"v": 17179869184,
		"d": "Difficulty of the Genesis block."
	},
	"genesisNonce": {
		"v": "0x0000000000000042",
		"d": "the geneis nonce"
	},
	"genesisExtraData": {
		"v": "0x11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa",
		"d": "extra data "
	},
	"genesisHash": {
		"v": "0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
		"d": "genesis hash"
	},
	"genesisStateRoot": {
		"v": "0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544",
		"d": "the genesis state root"
	},
	"minGasLimit": {
		"v": 5000,
		"d": "Minimum the gas limit may ever be."
	},
	"gasLimitBoundDivisor": {
		"v": 1024,
		"d": "The bound divisor of the gas limit, used in update calculations."
	},
	"minimumDifficulty": {
		"v": 131072,
		"d": "The minimum that the difficulty may ever be."
	},
	"difficultyBoundDivisor": {
		"v": 2048,
		"d": "The bound divisor of the difficulty, used in the update calculations."
	},
	"durationLimit": {
		"v": 13,
		"d": "The decision boundary on the blocktime duration used to determine whether difficulty should go up or not."
	},
	"maximumExtraDataSize": {
		"v": 32,
		"d": "Maximum size extra data may be after Genesis."
	},
	"epochDuration": {
		"v": 30000,
		"d": "Duration between proof-of-work epochs."
	},
	"stackLimit": {
		"v": 1024,
		"d": "Maximum size of VM stack allowed."
	},
	"callCreateDepth": {
		"v": 1024,
		"d": "Maximum depth of call/create stack."
	},

	"tierStepGas": {
		"v": [0, 2, 3, 5, 8, 10, 20],
		"d": "Once per operation, for a selection of them."
	},
	"expGas": {
		"v": 10,
		"d": "Once per EXP instuction."
	},
	"expByteGas": {
		"v": 10,
		"d": "Times ceil(log256(exponent)) for the EXP instruction."
	},

	"sha3Gas": {
		"v": 30,
		"d": "Once per SHA3 operation."
	},
	"sha3WordGas": {
		"v": 6,
		"d": "Once per word of the SHA3 operation's data."
	},
	"sloadGas": {
		"v": 50,
		"d": "Once per SLOAD operation."
	},
	"sstoreSetGas": {
		"v": 20000,
		"d": "Once per SSTORE operation if the zeroness changes from zero."
	},
	"sstoreResetGas": {
		"v": 5000,
		"d": "Once per SSTORE operation if the zeroness does not change from zero."
	},
	"sstoreRefundGas": {
		"v": 15000,
		"d": "Once per SSTORE operation if the zeroness changes to zero."
	},
	"jumpdestGas": {
		"v": 1,
		"d": "Refunded gas, once per SSTORE operation if the zeroness changes to zero."
	},

	"logGas": {
		"v": 375,
		"d": "Per LOG* operation."
	},
	"logDataGas": {
		"v": 8,
		"d": "Per byte in a LOG* operation's data."
	},
	"logTopicGas": {
		"v": 375,
		"d": "Multiplied by the * of the LOG*, per LOG transaction. e.g. LOG0 incurs 0 * c_txLogTopicGas, LOG4 incurs 4 * c_txLogTopicGas."
	},

	"createGas": {
		"v": 32000,
		"d": "Once per CREATE operation & contract-creation transaction."
	},

	"callGas": {
		"v": 40,
		"d": "Once per CALL operation & message call transaction."
	},
	"callStipend": {
		"v": 2300,
		"d": "Free gas given at beginning of call."
	},
	"callValueTransferGas": {
		"v": 9000,
		"d": "Paid for CALL when the value transfor is non-zero."
	},
	"callNewAccountGas": {
		"v": 25000,
		"d": "Paid for CALL when the destination address didn't exist prior."
	},

	"suicideRefundGas": {
		"v": 24000,
		"d": "Refunded following a suicide operation."
	},

	"memoryGas": {
		"v": 3,
		"d": "Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL."
	},
	"quadCoeffDiv": {
		"v": 512,
		"d": "Divisor for the quadratic particle of the memory cost equation."
	},

	"createDataGas": {
		"v": 200,
		"d": ""
	},
	"txGas": {
		"v": 21000,
		"d": "Per transaction. NOTE: Not payable on data of calls between transactions."
	},
	"txCreation": {
		"v": 32000,
		"d": "the cost of creating a contract via tx"
	},
	"txDataZeroGas": {
		"v": 4,
		"d": "Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions."
	},
	"txDataNonZeroGas": {
		"v": 68,
		"d": "Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions."
	},

	"copyGas": {
		"v": 3,
		"d": "Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added."
	},

	"ecrecoverGas": {
		"v": 3000,
		"d": ""
	},
	"sha256Gas": {
		"v": 60,
		"d": ""
	},
	"sha256WordGas": {
		"v": 12,
		"d": ""
	},
	"ripemd160Gas": {
		"v": 600,
		"d": ""
	},
	"ripemd160WordGas": {
		"v": 120,
		"d": ""
	},
	"identityGas": {
		"v": 15,
		"d": ""
	},
	"identityWordGas": {
		"v": 3,
		"d": ""
	},
	"minerReward": {
		"v": "5000000000000000000",
		"d": "the amount a miner get rewarded for mining a block"
	},
	"ommerReward": {
		"v": "625000000000000000",
		"d": "The amount of wei a miner of an uncle block gets for being inculded in the blockchain"
	},
	"niblingReward": {
		"v": "156250000000000000",
		"d": "the amount a miner gets for inculding a uncle"
	},
	"homeSteadForkNumber": {
		"v": 1150000,
		"d": "the block that the Homestead fork started at"
	},
	"homesteadRepriceForkNumber": {
		"v": 2463000,
		"d": "the block that the Homestead Reprice (EIP150) fork started at"
	},
	"timebombPeriod": {
		"v": 100000,
		"d": "Exponential difficulty timebomb period"
	},
	"freeBlockPeriod": {
		"v": 2
	}
}
