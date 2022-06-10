import { test } from 'tapzero'
import { blob, sign, scry } from './word.js'
import elliptic from 'elliptic'

import {randomBytes} from 'crypto'

test("sign/scry", t=>{
  for(let i = 0; i < 100; i++) {
    //console.log('  ')
    let ec = new elliptic.ec('secp256k1')
    let keys = ec.genKeyPair()
    let pubk = Buffer.from(keys.getPublic().encode())
    let seck = keys.priv.toBuffer()
    //console.log(pubk.length, pubk.toString('hex'))
    //console.log(seck.length, seck.toString('hex'))
    let msg = randomBytes(50)
    let sig = sign(msg, seck)
    //console.log(sig.length, sig.toString('hex'))
    let ecr = scry(msg, sig)
    //console.log(ecr.length, ecr.toString('hex'))
    t.ok(pubk.equals(ecr))
  }
})
