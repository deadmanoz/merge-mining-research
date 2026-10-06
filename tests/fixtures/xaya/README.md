# Xaya child-height authentication fixture

`height902.bin` is the complete unframed native Xaya block at height 902 from
Kraft's October 2026 dump (`blk00000.dat`, frame offset 749637). Its SHA-256 is
`b793be811eefc21f518634183d0beba1308b1c66b6759ebf48884f3002d2e8ff`.
An independent transaction/Merkle audit verified its child identity and height;
see the foundation provenance in `docs/chains/xaya.md`.

The child transaction vector begins at 949, and the SegWit coinbase's canonical
height prefix `028603` begins at 994. The CLI regression changes the encoded
902 to 903 without changing the pure child header or AuxPoW. This must fail
child transaction authentication and preserve the preceding output. The valid
fixture also exercises Xaya's witness commitment profile.
