import rlp from 'rlp';
import hashes from 'js-sha3';
import elliptic from 'elliptic';
const _ec = new elliptic.ec('secp256k1'); // init/reusable
export { blen, bleq, chop, isblob, b2h, h2b, t2b, b2t, roll, unroll, rmap, islist, isroll, hash, sign, scry, okay, pass, fail, toss, err, need, aver, };
// precondition / panic assert
// give lambda to defer eval when disabled
export let _aver = true;
function aver(bf, s) {
    if (_aver && !bf()) {
        console.log(`PANIC`);
        toss(s);
    }
}
function okay(x) {
    let [ok, val, err] = x;
    if (ok)
        return val;
    else
        throw err;
}
function pass(val) {
    return [true, val, null];
}
function fail(wut, why) {
    return [false, null, err(wut, why)];
}
function toss(wut, why) {
    throw err(wut, why);
}
function err(wut, why) {
    return new Error(wut, { "cause": why });
}
function need(b, s) {
    if (!b)
        toss(s);
}
export function bnum(b) {
    return BigInt("0x" + b.toString('hex'));
}
function islist(r) {
    return Array.isArray(r);
}
function isblob(r) {
    return Buffer.isBuffer(r);
}
function t2b(t) {
    return Buffer.from(t);
}
function b2t(b) {
    return b.toString();
}
function b2h(blob) {
    return blob.toString('hex');
}
function h2b(hexs) {
    if (hexs.length % 2 == 1) {
        hexs = '0' + hexs;
    }
    return Buffer.from(hexs, 'hex');
}
function isroll(x) {
    if (isblob(x))
        return true;
    if (islist(x)) {
        if (x.length == 0)
            return true;
        if (x.filter(r => isroll(r)).length > 0)
            return true;
    }
    return false;
}
function blen(b) {
    return new Buffer(b).length;
}
function bleq(a, b) {
    return Buffer.from(a).equals(Buffer.from(b));
}
function roll(r) {
    return Buffer.from(rlp.encode(rmap(r, Buffer.from)));
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
function chop(x, k) {
    let len = blen(x);
    need(len >= k, `chop: x.len must be <= k`);
    return x.slice(len - k, len);
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
