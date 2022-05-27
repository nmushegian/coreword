import { test } from 'tapzero'

import { roll } from './coreword.js'

test('roll', t=>{
    t.ok(roll([]))
})
