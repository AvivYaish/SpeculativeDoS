# Generator-Nodes Modularized SpecDOS 

This guide explains how to physically separate the transaction generator from the edge nodes that validate transactions and produce blocks.

```text
Tx Generator
  - Creates honest transactions
  - Creates attack transactions
  - Sends transactions to edge nodes through RPC

Edge Nodes
  - Validate transactions
  - Generate blocks
```

Important: edge nodes must run the modified geth/builder fork in this repository, not a stock geth binary.

## Build

```bash
cd builder
go build ./cmd/specdos
```

## Modified Files

To commit and push only the modularized SpecDOS changes, stage only these files:

```text
SpeculativeDoS-Modularized/
├── .gitignore
├── README.md
└── builder/
    ├── cmd/
    │   └── specdos/
    │       └── main.go
    └── specdos/
        ├── config.go
        ├── monitor.go
        └── txgen.go
```

## 1. Create Lab Config

```bash
./specdos init \
  --out ./lab \
  --validators 3 \
  --honest 5120 \
  --attackers 5120 \
  --chain-id 13371337 \
  --clique-period 12
```

Generated files:

```text
./lab/genesis.json
./lab/keys.json
```

`keys.json` contains plaintext private keys. Use it only for a private test chain and do not commit it.

## 2. Run Edge Nodes

Validator 0:

```bash
./specdos node \
  --genesis ./lab/genesis.json \
  --keys ./lab/keys.json \
  --validator-index 0 \
  --datadir ./node0 \
  --http.addr 0.0.0.0 \
  --http.port 8545 \
  --p2p.addr 0.0.0.0 \
  --p2p.port 30303
```

For validator 1 and later, pass a previous node's `enode` URL through `--staticnodes`.

```bash
./specdos node \
  --genesis ./lab/genesis.json \
  --keys ./lab/keys.json \
  --validator-index 1 \
  --datadir ./node1 \
  --http.addr 0.0.0.0 \
  --http.port 8545 \
  --p2p.addr 0.0.0.0 \
  --p2p.port 30303 \
  --staticnodes "enode://..."
```

To enable the censorship blocklist used by the original tests, add:

```bash
--verify-censorship
```

## 3. Run Tx Generator

Honest only:

```bash
./specdos txgen \
  --keys ./lab/keys.json \
  --rpc http://EDGE_NODE_IP:8545 \
  --mode honest
```

ConditionalExhaust:

```bash
./specdos txgen \
  --keys ./lab/keys.json \
  --rpc http://EDGE_NODE_IP:8545 \
  --mode conditional \
  --attacker-accounts 140 \
  --attacker-rate 2 \
  --attacker-chunk 140
```

Combined MemPurge + ConditionalExhaust:

```bash
./specdos txgen \
  --keys ./lab/keys.json \
  --rpc http://EDGE_NODE_IP:8545 \
  --mode combined \
  --mem-purge-len 2 \
  --attacker-accounts 140 \
  --attacker-rate 2 \
  --attacker-chunk 140 \
  --contract-out ./lab/contract-address.txt
```

Parameter meaning:

```text
attacker-accounts = number of attacker accounts
attacker-rate     = chunks sent per second
attacker-chunk    = attack transactions per chunk
```

Total attack transaction count:

```text
conditional = attacker-accounts * attacker-txs-per-account
combined    = attacker-accounts * mem-purge-len
```

## 4. Run Monitor

Record block-level transaction inclusion metrics as JSONL:

```bash
./specdos monitor \
  --keys ./lab/keys.json \
  --rpc http://EDGE_NODE_IP:8545 \
  --start latest \
  --interval 1s \
  --out ./specdos-metrics-edge0.jsonl
```

Recorded fields include:

```text
block number
tx count
honest tx count
attacker tx count
empty block status
gas used
```

## Network

Recommended ports:

```text
8545/TCP       tx generator -> edge node RPC
30303/TCP+UDP  edge node <-> edge node P2P
22/TCP         SSH management
```

Do not expose RPC port `8545` directly to the public internet. Restrict access with a VPN, security group, or firewall so that only the tx generator can reach it.

For repeatable experiments, reset each edge node datadir or generate a fresh key set before each run.

## Reference

This work references the original [AvivYaish/SpeculativeDoS](https://github.com/AvivYaish/SpeculativeDoS) repository and modularizes its in-process txpool injection workflow into a separated tx generator and edge-node RPC transmission workflow.
