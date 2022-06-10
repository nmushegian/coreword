import rlp from 'rlp'
import hashes from 'js-sha3'
import elliptic from 'elliptic'

const _ec = new elliptic.ec('secp256k1') // init/reusable

export {
  Blob, blob, roll,
  Roll, rmap, unroll,
  Hash, hash,
  Sign, Pubk, Seck, sign, scry,
  Hexs,
  Okay, okay, pass, fail, toss, err
}

type Blob = Buffer
type Roll = Blob | Roll[]
type Hash = Blob // 32 bytes
type Pubk = Blob // 33 bytes
type Seck = Blob // 32 bytes
type Sign = Blob // 65 bytes
type Hexs = string // hex string

type Okay<T> = [true, T]
             | [false, Why]

type Why     = [Error, Why?] // chainable

function okay(x :Okay<any>) :any {
    let [ok, v] = x
    if (ok) return v
    else throw v[0]
}

function pass(v:any) :Okay<any> {
    return [true, v]
}

function fail(why:string, trace?:Why) :Okay<any> {
    return [false, [err(why), trace]]
}

function toss(why :string) {
    throw err(why)
}

function err(why :string) : Error {
    return new Error(why)
}

function blob(hex : Hexs) : Blob {
    return Buffer.from(hex, 'hex')
}

function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(r))
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
    return Buffer.from(pub.encode())
}
