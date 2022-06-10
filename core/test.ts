import { test } from 'tapzero'
import { blob, sign, scry } from '../dist/word.js'
import elliptic from 'elliptic'

test("sign/scry", t=>{
  let ec = new elliptic.ec('secp256k1')
  let keys = ec.genKeyPair()
  let pubk = Buffer.from(keys.getPublic().encode())
  let seck = keys.priv.toBuffer()
  let msg = blob('ff00')
  let sig = sign(msg, seck)
  let ecr = scry(msg, sig)
  t.ok(pubk.equals(ecr))
})
