import rlp from 'rlp';
import hashes from 'js-sha3';
import elliptic from 'elliptic';
const _ec = new elliptic.ec('secp256k1'); // init/reusable
export { blob, roll, isBlob, isList, rmap, unroll, hash, sign, scry, okay, pass, fail, toss, err };
function okay(x) {
    let [ok, val, errs] = x;
    if (ok)
        return val;
    else
        toss(errs[0]);
}
function pass(v) {
    return [true, v, []];
}
function fail(why, whys = []) {
    return [false, null, [...whys, why]];
}
function toss(why) {
    throw err(why);
}
function err(why) {
    return new Error(why);
}
function isList(r) {
    return Array.isArray(r);
}
function isBlob(r) {
    return Buffer.isBuffer(r);
}
function blob(hex) {
    if (hex.length % 2 == 1) {
        hex = '0' + hex;
    }
    return Buffer.from(hex, 'hex');
}
function roll(r) {
    return Buffer.from(rlp.encode(r));
}
function unroll(b) {
    return rmap(rlp.decode(b), Buffer.from);
}
function rmap(r, f) {
    if (Array.isArray(r)) {
        return r.map(x => rmap(x, f));
    }
    else {
        return f(r);
    }
}
function hash(b) {
    return Buffer.from(hashes.keccak256(b), 'hex');
}
// https://github.com/ethers-io/ethers.js/blob/
// c2c0ce75039e7256b287f9a764188d08ed0b7296/
// packages/signing-key/src.ts/index.ts#L51
function sign(msg, key) {
    let dig = hash(msg);
    let keys = _ec.keyFromPrivate(key);
    let sig = keys.sign(dig, { canonical: true });
    let cat = Buffer.concat([
        sig.r.toBuffer('be', 32),
        sig.s.toBuffer('be', 32),
        Buffer.from([sig.recoveryParam ? sig.recoveryParam : 0])
    ]);
    return cat;
}
// https://github.com/ethers-io/ethers.js/blob/
//   c2c0ce75039e7256b287f9a764188d08ed0b7296/
//   packages/signing-key/src.ts/index.ts#L76
function scry(msg, sig) {
    let dig = hash(msg);
    let rs = {
        r: sig.slice(0, 32),
        s: sig.slice(32, 64)
    };
    let v = sig[64];
    let pub = _ec.recoverPubKey(dig, rs, v);
    return Buffer.from(pub.encodeCompressed());
}
