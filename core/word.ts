import rlp from 'rlp'
import hashes from 'js-sha3'

type Blob = Buffer
type Roll = Blob | Roll[]
type Hash = Blob // 32 bytes
type Pubk = Blob // 32 bytes
type Seck = Blob // 64 bytes
type Sign = Blob // 65 bytes
type Hexs = string // hex string

export function blob(hex : Hexs) : Blob {
    return Buffer.from(hex, 'hex')
}

export function roll(r : Roll) : Blob {
    return Buffer.from(rlp.encode(r))
}

export function hash(b : Blob) : Hash {
    return Buffer.from(hashes.keccak256(b), 'hex')
}

export function sign(msg : Blob, key: Seck, opts : any = {fake:false}) : Sign {
    if (opts.fake === true) {
        return Buffer.from('fakes'.repeat(13)) // 65 bytes
    } else {
        throw new Error(`unimplemented`)
    }
}

export function scry(msg : Blob, sig : Sign, opts : any = {fake:false}) : Pubk {
    if (opts.fake === true) {
        return Buffer.from('pubk'.repeat(8)) // 32 bytes
    } else {
        throw new Error(`unimplemented`)
    }
}
