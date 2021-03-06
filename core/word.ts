import rlp from 'rlp'
import hashes from 'js-sha3'
import elliptic from 'elliptic'

const _ec = new elliptic.ec('secp256k1') // init/reusable

export {
    Bnum, Blob, blen, bleq, chop, isblob, b2h, h2b, t2b, b2t,
    Roll, roll, unroll, rmap, islist, isroll,
    Hash, hash,
    Sign, Pubk, Seck, sign, scry,
    Hexs,
    Okay, okay, pass, fail, toss, err, need, aver,
}


type Bnum = bigint
type Blob = Buffer
type Roll = Blob | Roll[]
type Hash = Blob // 32 bytes
type Pubk = Blob // 33 bytes
type Seck = Blob // 32 bytes
type Sign = Blob // 65 bytes
type Hexs = string // hex string

type Okay<T> = [boolean, T, Error?]

// precondition / panic assert
// give lambda to defer eval when disabled
export let _aver = true
function aver(bf :((a?:any)=>boolean), s :string) {
    if (_aver && !bf()) { console.log(`PANIC`); toss(s) }
}

function okay(x :Okay<any>) :any {
    let [ok, val, err] = x
    if (ok) return val
    else throw err
}

function pass(val :any) :Okay<any> {
    return [true, val, null]
}

function fail(wut :string, why? :Error) :Okay<any> {
    return [false, null, err(wut, why)]
}

function toss(wut :string, why? :Error) {
    throw err(wut, why)
}

function err(wut :string, why? :Error) : Error {
    return new Error(wut, { "cause": why })
}

function need(b :boolean, s :string) {
    if (!b) toss(s)
}

export function bnum(b :Blob) :Bnum {
    return BigInt("0x" + b.toString('hex'))
}

function islist(r :any) :boolean {
    return Array.isArray(r)
}

function isblob(r :any) :boolean {
    return Buffer.isBuffer(r)
}

function t2b(t :string) :Blob {
    return Buffer.from(t)
}

function b2t(b :Blob) :string {
    return b.toString()
}

function b2h(blob : Blob) :Hexs {
    return blob.toString('hex')
}

function h2b(hexs :Hexs) :Blob {
    if (hexs.length % 2 == 1) {
        hexs = '0' + hexs
    }
    return Buffer.from(hexs, 'hex')
}

function isroll(x :any) :boolean {
    if (isblob(x)) return true;
    if (islist(x)) {
        if (x.length == 0) return true;
        if (x.filter(r=>isroll(r)).length > 0) return true;
    }
    return false
}

function blen(b :Blob) :number {
    return new Buffer(b).length
}

function bleq(a :Blob, b:Blob) :boolean {
    return Buffer.from(a).equals(Buffer.from(b))
}

function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(rmap(r, Buffer.from)))
}

function unroll(b :Blob) :Roll {
    return rmap(rlp.decode(b), Buffer.from)
}

function rmap(r :any, f :Function) :any {
    if (Array.isArray(r)) {
        return r.map(x => rmap(x, f))
    } else {
        return f(r)
    }
}

function hash(b : Blob) : Hash {
    return Buffer.from(hashes.keccak256(b), 'hex')
}

function chop(x :Blob, k :number) :Blob {
    let len = blen(x)
    need(len >= k, `chop: x.len must be <= k`)
    return x.slice(len - k, len)
}

// https://github.com/ethers-io/ethers.js/blob/
// c2c0ce75039e7256b287f9a764188d08ed0b7296/
// packages/signing-key/src.ts/index.ts#L51
function sign(msg : Blob, key: Seck) : Sign {
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
function scry(msg : Blob, sig : Sign) : Pubk {
    let dig = hash(msg);
    let rs = {
        r: sig.slice(0, 32),
        s: sig.slice(32, 64)
    }
    let v = sig[64];
    let pub = _ec.recoverPubKey(dig, rs, v);
    return Buffer.from(pub.encodeCompressed())
}
