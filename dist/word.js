import rlp from 'rlp';
import hashes from 'js-sha3';
import elliptic from 'elliptic';
const _ec = new elliptic.ec('secp256k1'); // init/reusable
export { blen, bleq, isblob, b2h, h2b, roll, unroll, rmap, islist, isroll, hash, sign, scry, okay, pass, fail, toss, err };
// precondition / panic assert
// give lambda to defer eval when disabled
let _aver = true; //false;
function aver(bf, s) {
    if (_aver && !bf()) {
        console.log(`PANIC`);
        toss(s);
    }
}
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
function need(b, s) {
    if (!b)
        toss(s);
}
function islist(r) {
    return Array.isArray(r);
}
function isblob(r) {
    return Buffer.isBuffer(r);
}
function b2h(blob) {
    return new Buffer(blob).toString('hex');
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
    return rlp.decode(Buffer.from(b));
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
