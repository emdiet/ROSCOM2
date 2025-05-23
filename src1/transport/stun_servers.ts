// This file is auto-generated by test_stun_comprehensive.ts
    
export type StunServerAddress = {
    url: string, 
    lastWorked?: Number,
    lastLatency?: Number, 
    tests?: Number, // how often it was tested
    failures?: Number // how often it failed
};

// run with:
// bash: (out of src1)
// npm run build && node ts-js-out/transport/test_stun_comprehensive.js
// old ps: (out of src1)
// npm run build; node ts-js-out/transport/test_stun_comprehensive.js

export const stunServers: StunServerAddress[] = [
  {
    "url": "stun.cloudflare.com:3478",
    "tests": 27,
    "lastWorked": 1746338698259,
    "lastLatency": 23
  },
  {
    "url": "stun.l.google.com:19302",
    "tests": 27,
    "lastWorked": 1746338698320,
    "lastLatency": 59
  },
  {
    "url": "stun1.l.google.com:19302",
    "tests": 7,
    "lastWorked": 1746338698381,
    "lastLatency": 60
  }
]