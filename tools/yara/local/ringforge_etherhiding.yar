rule RingForge_EtherHiding_eth_call
{
    meta:
        description = "Implant reading C2 address from a smart contract via eth_call getData() (EtherHiding)"
        author      = "RingForge"
        date        = "2026-08-20"
        reference   = "run c14cb5b6; carved from SecurityHealthHost.exe pid 11096, hollowed by powershell.exe"
        hash        = "7ea500ad175878014fa1ec391416ae477066b2622c96c8b882126febdeddf004"
        note        = "No PE anchor -- must match raw memory dumps, where the header is not at offset 0"

    strings:
        $tmpl     = "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"" ascii
        $selector = "\"data\":\"0x3bc5de30\"" ascii
        $c2a      = "method=refresh&guid=" ascii
        $c2b      = "method=send&guid=" ascii
        $c2c      = "&address=" ascii

    condition:
        $tmpl or $selector or all of ( $c2a, $c2b, $c2c )
}

rule RingForge_Clipper_c14cb5b6_wallets
{
    meta:
        description = "Campaign-specific: hardcoded substitution wallets and contract, run c14cb5b6"
        author      = "RingForge"
        date        = "2026-08-20"
        note        = "Campaign IOCs -- contract confirmed dead on BSC testnet and mainnet 2026-08-20; expect staleness"

    strings:
        $guid = "4b817807-2731-459c-bc5d-4bd914c9eb55" ascii nocase
        $con  = "0x0F14fc3bfAc3726172aCd08Fe4bFb79B633E76ff" ascii nocase
        $btc1 = "19eWJh8J6Mx9DrGXKEv3ojKmqw8Cv9pscK" ascii
        $btc3 = "3BFNGKQZW9FcwxHmBGNfctsCdiSiqT8qZk" ascii
        $btcb = "bc1qtmvdcp0p5j3jd9a4k8e8qvv5gy9hrg7w28wxkg" ascii
        $ltc  = "LUut5sRxQzEPUM6NobeyanY9Yi748ZztsX" ascii
        $doge = "DJhtvoh4N49pt2yfTQWgjnStBBnD4KdbRy" ascii
        $dash = "Xet9CxZ8ihR3Cqu32nbShKABRf2FTUqXxd" ascii
        $trx  = "TWXh8n73LuT5MJ23pd8dCjFskRZckveFbP" ascii
        $sol  = "DcJHrrHSgvFpsYxqb6g97uaQTd2kE31rPUeDZTeDsjVq" ascii

    condition:
        2 of them
}