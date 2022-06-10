import rlp from 'rlp'
import hashes from 'js-sha3'
import elliptic from 'elliptic'

export type Blob = Buffer
export type Roll = Blob | Roll[]
export type Hash = Blob // 32 bytes
export type Pubk = Blob // 33 bytes
export type Seck = Blob // 32 bytes
export type Sign = Blob // 65 bytes
export type Hexs = string // hex string

const _ec = new elliptic.ec('secp256k1')

export function blob(hex : Hexs) : Blob {
    return Buffer.from(hex, 'hex')
}

export function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(r))
}

export function hash(b : Blob) : Hash {
    return Buffer.from(hashes.keccak256(b), 'hex')
}

// https://github.com/ethers-io/ethers.js/blob/
// c2c0ce75039e7256b287f9a764188d08ed0b7296/
// packages/signing-key/src.ts/index.ts#L51
export function sign(msg : Blob, key: Seck) : Sign {
    let dig = hash(msg);
    let keys = _ec.keyFromPrivate(key);
    let sig = keys.sign(dig, { canonical: true });
    let cat = Buffer.concat([
      sig.r.toBuffer(),
      sig.s.toBuffer(),
      Buffer.from([sig.recoveryParam])
    ]);
    return cat;
}

// https://github.com/ethers-io/ethers.js/blob/
//   c2c0ce75039e7256b287f9a764188d08ed0b7296/
//   packages/signing-key/src.ts/index.ts#L76
export function scry(msg : Blob, sig : Sign) : Pubk {
    let dig = hash(msg);
    let rs = {
      r: sig.slice(0, 32),
      s: sig.slice(32, 64)
    }
    let v = sig[64];
    let pub = _ec.recoverPubKey(dig, rs, v);
    return Buffer.from(pub.encode())
}
