import rlp from 'rlp'
import hashes from 'js-sha3'

export type Blob = Buffer
export type Roll = Blob | Roll[]
export type Hash = Blob // 32 bytes
export type Pubk = Blob // 32 bytes
export type Seck = Blob // 64 bytes
export type Sign = Blob // 65 bytes
export type Hexs = string // hex string

export function blob(hex : Hexs) : Blob {
    return Buffer.from(hex, 'hex')
}

export function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(r))
}

export function hash(b : Blob) : Hash {
    return Buffer.from(hashes.keccak256(b), 'hex')
}

export function sign(msg : Blob, key: Seck) : Sign {
    throw new Error(`unimplemented`)
}

export function scry(msg : Blob, sig : Sign) : Pubk {
    throw new Error(`unimplemented`)
}
