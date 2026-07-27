#!/usr/bin/env node
import {generateKey} from '@bc-studio/oauth-core';

const {privateJwk, publicKey} = await generateKey();
console.log(JSON.stringify({privateJwk, publicKey}, null, 2));