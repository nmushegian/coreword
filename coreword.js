import rlp from 'rlp'
import hashes from 'js-sha3'
import nacl from 'tweetnacl'

export function roll(v) {
    return rlp.encode(v)
}

export function hash(b) {
    return hashes.keccak256(b)
}

export function sign(msg, key) {
    return nacl.sign(msg, key)
}

export function scry(msg, sig, key) {
    return nacl.verify(msg, sig, key)
}
