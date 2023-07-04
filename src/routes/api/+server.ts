import { json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

import * as bitcoinJsLib from 'bitcoinjs-lib';
import { ECPairFactory } from 'ecpair';
import * as tinysecp from 'tiny-secp256k1';
import assert from 'assert';
bitcoinJsLib.initEccLib(tinysecp);
const ecpair = ECPairFactory(tinysecp);

export const POST: RequestHandler = async ({ request }) => {
	const response = await request.json();
	const { signature, address, message } = response.result;
	const verified = verifyBip322(message, address, signature);

	console.log({ signature, address, message, verified });

	return json(response);
};

function verifyBip322(message: string, address: string, signature: string) {
	const { output, pubkey } = bitcoinJsLib.payments.p2tr({ address });

	if (output === undefined) {
		throw new Error('Only supports p2tr addresses');
	}

	const hash = taggedHash('BIP0322-signed-message', Buffer.from(message, 'utf8'));
	const sigBuff = Buffer.from(signature, 'base64');

	const toSpend = createToSpend(hash, output);
	const toSign = createToSign(toSpend, sigBuff);

	if (pubkey === undefined) {
		throw new Error('Public key is undefined');
	}

	return validateP2tr(toSign, pubkey);
}

function taggedHash(prefix: string, data: Buffer) {
	const prefixBuffer = Buffer.from(prefix, 'utf8');
	const prefixHash = bitcoinJsLib.crypto.sha256(prefixBuffer);
	return bitcoinJsLib.crypto.sha256(Buffer.concat([prefixHash, prefixHash, data]));
}
function createToSpend(messageHash: Buffer, outputScript: Buffer) {
	const { OP_0 } = bitcoinJsLib.opcodes;
	const toSpend = new bitcoinJsLib.Transaction();
	toSpend.version = 0;
	toSpend.locktime = 0;
	toSpend.addInput(
		Buffer.alloc(32, 0),
		0xffffffff,
		0,
		Buffer.concat([Buffer.from([OP_0, 0x20]), messageHash])
	);
	toSpend.addOutput(outputScript, 0);

	return toSpend;
}

function createToSign(
	toSpend: bitcoinJsLib.Transaction,
	signature = Buffer.from([])
): bitcoinJsLib.Transaction {
	const { OP_RETURN } = bitcoinJsLib.opcodes;
	if (signature.length === 65) {
		throw new Error('Legacy signatures can be handled with bitcoinjs-message');
	}
	let toSign;
	let isTx;
	try {
		toSign = bitcoinJsLib.Transaction.fromBuffer(signature);
		isTx = true;
	} catch (e) {
		// If serialization fails, it is a witnessStack only (simplified signature)
		toSign = new bitcoinJsLib.Transaction();
		isTx = false;
	}

	if (isTx) {
		assert(toSign.ins.length === 1);
		assert(toSign.outs.length === 1);
		assert(toSign.ins[0].index === 0);
		assert(toSign.outs[0].value === 0);
		assert(toSign.outs[0].script.length === 1);
		assert(toSign.outs[0].script[0] === OP_RETURN);
		const toSpendHash = toSpend.getHash();
		const input = toSign.ins[0];
		assert.strictEqual(input.hash, toSpendHash);
	} else {
		toSign.version = 0;
		toSign.locktime = 0;
		toSign.addOutput(Buffer.from([OP_RETURN]), 0);
		toSign.addInput(toSpend.getHash(), 0, 0);
		if (signature.length > 0) {
			// We assume 1 input, so witness stack will only have one stack.
			// Skip the item count (first byte)
			toSign.ins[0].witness = bitcoinJsLib.script.toStack(signature.subarray(1));
		}
	}

	return toSign;
}

function validateP2tr(toSign: bitcoinJsLib.Transaction, pubkey: Buffer) {
	// Verify the signatures in toSign transaction
	const [schnorrSig] = toSign.ins[0].witness;

	// Check if pubkey is defined
	const prevOP = bitcoinJsLib.payments.p2tr({ pubkey });
	// p2wpkh uses p2pkh script for creating the sighash for some reason
	if (prevOP.output === undefined) {
		throw new Error('Public key is undefined');
	}
	const hashForSigning = toSign.hashForWitnessV1(
		0,
		[prevOP.output],
		[0],
		bitcoinJsLib.Transaction.SIGHASH_DEFAULT
	);

	// SIGHASH_DEFAULT has no sighash byte
	assert(schnorrSig.length === 64);

	const pair = ecpair.fromPublicKey(Buffer.concat([Buffer.from([2]), pubkey]));

	return pair.verifySchnorr(hashForSigning, schnorrSig);
}
