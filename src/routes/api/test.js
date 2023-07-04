const assert = require('assert');
const bitcoinJsLib = require('bitcoinjs-lib');
const tinysecp = require('tiny-secp256k1');
bitcoinJsLib.initEccLib(tinysecp);
const { ECPairFactory } = require('ecpair');
const ecpair = ECPairFactory(tinysecp);

/**
 * Simple verification for BIP322 signatures
 * @param {string} message A message that is signed ie "Hello world"
 * @param {string} address The address that signed it.
 * @param {string} signature The signature (which is an encoded transaction as per BIP322)
 * @returns {boolean}
 */
function verifyBip322(message, address, signature) {
    const { output, pubkey } = bitcoinJsLib.payments.p2tr({ address });
    if (output === undefined) {
        throw new Error('Only supports p2tr addresses');
    }
    const hash = taggedHash(
        'BIP0322-signed-message',
        Buffer.from(message, 'utf8'),
    );
    const sigBuff = Buffer.from(signature, 'base64');

    const toSpend = createToSpend(hash, output);
    const toSign = createToSign(toSpend, sigBuff);

    return validateP2tr(toSign, pubkey);
}

/**
 * Signs the message according to BIP322 for P2WPKH
 * @param {string} message
 * @param {Buffer} privateKey
 * @param {boolean} tweak
 * @returns {[string, string]} address for validation and signature
 */
function signBip322(message, privateKey, tweak = false) {
    const hash = taggedHash(
        'BIP0322-signed-message',
        Buffer.from(message, 'utf8'),
    );
    let keyPair = ecpair.fromPrivateKey(privateKey);
    let pubkey = keyPair.publicKey.subarray(1);
    if (tweak) {
        const tweakHash = bitcoinJsLib.crypto.taggedHash('TapTweak', pubkey);
        keyPair = keyPair.tweak(tweakHash);
        pubkey = keyPair.publicKey.subarray(1);
    }
    const { output, address } = bitcoinJsLib.payments.p2tr({
        pubkey,
    });
    const toSpend = createToSpend(hash, output);
    const toSign = createToSign(toSpend);
    return [address, signP2tr(toSign, keyPair)];
}

/**
 * Tagged hashing
 * @param {string} prefix
 * @param {Buffer} data
 * @returns {Buffer}
 */
function taggedHash(prefix, data) {
    const prefixHash = bitcoinJsLib.crypto.sha256(prefix);
    return bitcoinJsLib.crypto.sha256(
        Buffer.concat([prefixHash, prefixHash, data]),
    );
}

/**
 * Creates the toSpend tx
 * @param {Buffer} messageHash
 * @param {Buffer} outputScript
 * @returns {bitcoinJsLib.Transaction}
 */
function createToSpend(messageHash, outputScript) {
    const { OP_0 } = bitcoinJsLib.opcodes;
    const toSpend = new bitcoinJsLib.Transaction();
    toSpend.version = 0;
    toSpend.locktime = 0;
    toSpend.addInput(
        Buffer.alloc(32, 0),
        0xffffffff,
        0,
        Buffer.concat([Buffer.from([OP_0, 0x20]), messageHash]),
    );
    toSpend.addOutput(outputScript, 0);

    return toSpend;
}

/**
 * Creates the toSign transaction
 * @param {bitcoinJsLib.Transaction} toSpend
 * @param {Buffer?} signature
 * @returns {bitcoinJsLib.Transaction}
 */
function createToSign(toSpend, signature = Buffer.from([])) {
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
            toSign.ins[0].witness = bitcoinJsLib.script.toStack(
                signature.subarray(1),
            );
        }
    }

    return toSign;
}

/**
 * Validates the toSign transaction
 * @param {bitcoinJsLib.Transaction} toSign
 * @param {Buffer} pubkey the 32 byte xonly pubkey
 * @returns {boolean}
 */
function validateP2tr(toSign, pubkey) {
    // Verify the signatures in toSign transaction
    const [schnorrSig] = toSign.ins[0].witness;
    // p2wpkh uses p2pkh script for creating the sighash for some reason
    const hashForSigning = toSign.hashForWitnessV1(
        0,
        [bitcoinJsLib.payments.p2tr({ pubkey }).output],
        [0],
        bitcoinJsLib.Transaction.SIGHASH_DEFAULT,
    );

    // SIGHASH_DEFAULT has no sighash byte
    assert(schnorrSig.length === 64);

    const pair = ecpair.fromPublicKey(Buffer.concat([Buffer.from([2]), pubkey]));

    return pair.verifySchnorr(hashForSigning, schnorrSig);
}

/**
 * Signs the message with P2WPKH
 * @param {bitcoinJsLib.Transaction} toSign
 * @param {import('ecpair').ECPairInterface} keypair
 * @returns {string}
 */
function signP2tr(toSign, keypair) {
    const signingOutput = bitcoinJsLib.payments.p2tr({
        pubkey: keypair.publicKey.subarray(1),
    }).output;
    const hashForSigning = toSign.hashForWitnessV1(
        0,
        [signingOutput],
        [0],
        bitcoinJsLib.Transaction.SIGHASH_DEFAULT,
    );
    const signature = keypair.signSchnorr(hashForSigning);
    const compiled = Buffer.concat([
        Buffer.from([0x01]),
        bitcoinJsLib.script.compile([signature]),
    ]);
    return compiled.toString('base64');
}

/**
 * This function is for testing the above functions
 */
function test() {
    // The sign function only accepts private key buffers since WIF format is dead
    // It is only really used for displaying test cases for private keys, no wallets support them by default
    const testPrivateKey = ecpair.fromWIF(
        'L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k',
    ).privateKey;
    const testMessage = 'Hello World';

    const testSignature =
        'AUAggmoJubizCppbnNAHcwZ345p2cRhtGMBTu2fyafaKtVggQt+bQddGSuR8hqB2dEfNLMJwPICdKGZVGYjP4yJI';
    const testAddress =
        'bc1pclcjqqcev3pfg0v93rsp4m5yqs3uc48uz5s4y63mshptpj743peq6x880p';
    const testTweakedSignature =
        'AUA8apxpmAbHbKtAMUNkijh0eUI47pD3ekdLtRD27ptV8Iz9xjMTybJ/3k8pp2JCpxYTbgTU5nzw2x82VTfwxTUU';
    const testTweakedAddress =
        'bc1ppv609nr0vr25u07u95waq5lucwfm6tde4nydujnu8npg4q75mr5sxq8lt3';

    const output1 = verifyBip322(testMessage, testAddress, testSignature);
    const output2 = verifyBip322(
        testMessage,
        testAddress,
        signBip322(testMessage, testPrivateKey)[1],
    );
    const output3 = verifyBip322(testMessage, testTweakedAddress, testTweakedSignature);
    const output4 = verifyBip322(
        testMessage,
        testTweakedAddress,
        signBip322(testMessage, testPrivateKey, true)[1],
    );
    const output5 = verifyBip322(
        'Not hello world',
        testAddress,
        signBip322(testMessage, testPrivateKey)[1],
    );
    const output6 = verifyBip322(
        testMessage,
        testAddress,
        signBip322(testMessage, testPrivateKey, true)[1],
    );
    console.log('Verify test case       :', output1);
    console.log('Verify our own signing :', output2);
    console.log('Verify tweaked         :', output3);
    console.log('Verify our own tweaked :', output4);
    console.log('Verify mismatch (false):', output5);
    console.log('Verify mismatch (false):', output6);
    assert(output1);
    assert(output2);
    assert(output3);
    assert(output4);
    assert(output5 === false);
    assert(output6 === false);
}

test();