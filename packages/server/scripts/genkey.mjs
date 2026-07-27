import {generateKey} from '@bc-studio/oauth-core';

const {privateJwk} = await generateKey();
console.log(JSON.stringify(privateJwk));