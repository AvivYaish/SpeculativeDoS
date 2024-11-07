# SpeculativeDoS

The repository for the paper Speculative Denial-of-Service Attacks in Ethereum:

- [Summary](https://x.com/yaish_aviv/status/1670127539048660993)
- [Publication in USENIX SECURITY '24](https://www.usenix.org/conference/usenixsecurity24/presentation/yaish)
- [Full paper](https://ia.cr/2023/956) (see the "Reproducibility" appendix for instructions on how to use the code)

The file `builder/eth/block-validation/api_test.go`:
 - Sets up a fully-functioning local Ethereum testnet running a fork of [geth](https://github.com/ethereum/go-ethereum/) (Go Ethereum, Ethereum's most popular execution client)
 - Executes the many attacks we present in the paper on this testnet


## Acknowledgements

- The code is based on [Flashbots' builder client](https://github.com/flashbots/builder), which is in turn based on geth.
- This work received two bounties from the Ethereum Foundation and Flashbots
- In addition, this work received a grant from the Ethereum Foundation
