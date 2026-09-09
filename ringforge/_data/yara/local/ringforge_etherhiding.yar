rule RingForge_EtherHiding_eth_call
{
    meta:
        description = "Implant reading C2 address from a smart contract via eth_call getData() (EtherHiding)"
        author      = "RingForge"
        date        = "2026-08-22"
        reference   = "run c14cb5b6; carved from SecurityHealthHost.exe pid 11096, hollowed by powershell.exe"
        reference2  = "request template confirmed on the wire, run 20260822_134019, via a trusted-CA TLS responder"
        hash        = "7ea500ad175878014fa1ec391416ae477066b2622c96c8b882126febdeddf004"
        note        = "No PE anchor -- must match raw memory dumps, where the header is not at offset 0"
        note2       = "Confirmed against memory 22 Aug, run 4bb6b0d5: 5 of 6 strings hit in SecurityHealthHost.exe pid 7972. $selector was the miss -- see the comment beside it."

    strings:
        // The template as it appears in the binary, and as it went out on the
        // wire: field order `id` before `jsonrpc`, no spaces. That ordering is
        // a hand-rolled client's fingerprint rather than a library's.
        $tmpl     = "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"" ascii
        // **`$selector` is dead against memory, and `$sel_bare` is not
        // redundant with it.** The composed JSON fragment matches a captured
        // *request* and never the implant: run `4bb6b0d5` hit `$tmpl` at dump
        // offset 5561499 and `$sel_bare` at 5561613, 114 bytes apart as two
        // separate literals, and `$selector` not at all. The request is
        // assembled from fragments at runtime, so `"data":"0x3bc5de30"` exists
        // only on the wire. Keep both: `$selector` still earns its place
        // against a pcap or a proxy log. **Do not delete `$sel_bare` as a
        // duplicate of it** -- that would take the memory match with it.
        $selector = "\"data\":\"0x3bc5de30\"" ascii
        $sel_bare = "0x3bc5de30" ascii
        $c2a      = "method=refresh&guid=" ascii
        $c2b      = "method=send&guid=" ascii
        $c2c      = "&address=" ascii

    condition:
        $tmpl or $selector or $sel_bare or all of ( $c2a, $c2b, $c2c )
}

rule RingForge_Clipper_c14cb5b6_wallets
{
    meta:
        description = "Campaign-specific: substitution wallets and getData() contract, run c14cb5b6"
        author      = "RingForge"
        date        = "2026-08-22"
        note        = "CORRECTED 22 Aug. The 20 Aug read named 0x0F14fc3b as the contract; it is not. It sits inside the wallet table between a BTC bech32 and a BCH cashaddr, and is the EVM substitution address. The contract is 0x4E31128a, taken from the eth_call the implant actually sent."
        note2       = "17 substitution wallets, not the 10 first recorded. BCH, XRP, ALGO, TON and Cosmos were missed, as were the second LTC and third BTC formats."
        note3       = "CHECKED on-chain 22 Aug: the contract is LIVE on BSC testnet (chainId 0x61), 2008 bytes of bytecode, and getData() returns the C2 hostname klopasnarhia.cc. The 20 Aug 'contract is dead' result was eth_getCode against 0x0F14fc3b, which is a wallet, so it never said anything about this contract."
        note4       = "$c2 is NOT in the sample. It exists on-chain and, after a successful fetch, in memory -- which is what these PE-anchorless rules scan. A file-only scan will never match it, and that is expected rather than a fault."

    strings:
        $guid = "4b817807-2731-459c-bc5d-4bd914c9eb55" ascii nocase

        // The contract the implant queries. Confirmed on the wire, seven times.
        $con  = "0x4E31128a13AcBD1cF1909D67F072460c853F87f7" ascii nocase

        // The C2 the contract hands back. Retrieved from the live chain rather
        // than from the sample, which is the whole point of EtherHiding: it is
        // in no static artefact and can be rotated without touching the
        // malware. Present in memory only once a fetch has succeeded.
        $c2   = "klopasnarhia.cc" ascii wide

        // The substitution table, in file order. `$eth` is the one that was
        // misfiled as a contract for two days.
        $btc1 = "19eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK" ascii
        $btc3 = "3BFNGKQZW9FcwxHmBGNfctsCdiSiqT8qZk" ascii
        $btcb = "bc1qtmvdcp0p5j3jd9a4k8e8qvv5gy9hrg7w28wxkg" ascii
        $eth  = "0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff" ascii nocase
        $bch  = "qzmvjauj8j2parcdn0a54samn9trnqf30cdufdf555" ascii
        $ltc1 = "LUut5sRxQzEPUM6NobeyanY9Yi748ZztsX" ascii
        $ltc2 = "MAkF7mCn3tPqp662daybvERzwsKQYqnzM8" ascii
        $ltcb = "ltc1qdfryskhwlwyernnpf348qtsh36rereugpgyu9s" ascii
        $doge = "DJhtvoh4N49pt2yfTQWgjnStBBnD4KdbRy" ascii
        $xrp  = "rpZEAWYtiB6bJ16NuLbGCc6CZ6jJdKfb63" ascii
        $dash = "Xet9CxZ8ihR3Cqu32nbShKABRf2FTUqXxd" ascii
        $trx  = "TWXh8n73LuT5MJ23pd8dCjFskRZckveFbP" ascii
        $rvn  = "RTCqpJfyxBS4J3p2b5e5EKju1cc1FjKiMh" ascii
        $algo = "U65INNXNQYFK5WO5KI4UKDJV7XVVUJ36UCVRCQLGYW7ST7IFNM6ZWHASIM" ascii
        $ton  = "UQBNOrnQlzo3ftqm0Jj5Sf9zEHlPApapd-rWsAHREzkweiTw" ascii
        $atom = "cosmos1qmxpyqgh3auy2k090cqu4q7h4y52j0pjv2cp07" ascii
        $sol  = "DcJHrrHSgvFpsYxqb6g97uaQTd2kE31rPUeDZTeDsjVq" ascii

    condition:
        2 of them
}
