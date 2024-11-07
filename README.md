# SpeculativeDoS

The repository for the paper Speculative Denial-of-Service Attacks in Ethereum (USENIX Security '24):

- [Summary](https://x.com/yaish_aviv/status/1670127539048660993)
- [Talk (Tokenomics)](https://youtu.be/gfMpeQEO50s)
- [Publication in USENIX SECURITY '24](https://www.usenix.org/conference/usenixsecurity24/presentation/yaish)
- [Full paper](https://ia.cr/2023/956) (see "Reproducibility" for instructions on how to use the code)

A large part of our work (1554 lines of code) can be found in the file `builder/eth/block-validation/api_test.go`, which does the following:
 - Sets up a fully-functioning local Ethereum testnet running a fork of [Flashbots' builder client](https://github.com/flashbots/builder), which is a fork of [geth](https://github.com/ethereum/go-ethereum/) (Go Ethereum, Ethereum's most popular execution client)
 - Executes the many attacks we present in the paper on this testnet

For example, run `go test -v -run=TestCombinedAttackTestnet -timeout=0` to execute our combined attack, and see how the local testnet does not succeed in adding honest transactions to blocks:

![Attack demo](https://github.com/AvivYaish/SpeculativeDoS/blob/main/demos/attack.png?raw=true)

Or, as a video:

[![Attack demo](https://github.com/AvivYaish/SpeculativeDoS/blob/main/demos/attack.gif?raw=true)](https://youtu.be/olv45A5TH2c)


As a sanity check, the file can also execute the testnet without attacking it by running `go test -v -run=TestHonestTestnet -timeout=0`, which shows how the testnet does add honest transactions to blocks when it is not under attack:

![Honest demo](https://github.com/AvivYaish/SpeculativeDoS/blob/main/demos/honest.png?raw=true)

Or, as a video:

[![Honest demo](https://github.com/AvivYaish/SpeculativeDoS/blob/main/demos/honest.gif?raw=true)](https://youtu.be/5mNXc3P0UgI)


## Acknowledgements

- This work received two bounties from the Ethereum Foundation and Flashbots
- In addition, this work received a grant from the Ethereum Foundation
- Covered by [blockworks](https://mail.blockworks.com/p/thursday-attacking-mailbag)
- Ranked 63rd in [MLSEC’s Normalized Top-100 Security Papers list](https://web.archive.org/web/20241107203646/https://www.mlsec.org/topnotch/sec_ntop100.html)
