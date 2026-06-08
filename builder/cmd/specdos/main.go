package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/fdlimit"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/specdos"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "node":
		err = runNode(os.Args[2:])
	case "txgen":
		err = runTxgen(os.Args[2:])
	case "monitor":
		err = runMonitor(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: specdos <init|node|txgen|monitor> [flags]")
}

func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	outDir := fs.String("out", "specdos-lab", "output directory")
	validators := fs.Int("validators", 1, "number of Clique validator keys")
	honest := fs.Int("honest", specdos.TxPoolSize, "number of honest sender keys")
	attackers := fs.Int("attackers", specdos.TxPoolSize, "number of attacker sender keys")
	chainID := fs.Uint64("chain-id", specdos.DefaultChainID, "private chain id")
	cliquePeriod := fs.Uint64("clique-period", specdos.DefaultCliquePeriod, "Clique block period in seconds")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0700); err != nil {
		return err
	}
	genesis, keys, err := specdos.GenerateLabConfig(*validators, *honest, *attackers, *chainID, *cliquePeriod)
	if err != nil {
		return err
	}
	genesisPath := filepath.Join(*outDir, "genesis.json")
	keysPath := filepath.Join(*outDir, "keys.json")
	if err := specdos.SaveGenesis(genesisPath, genesis); err != nil {
		return err
	}
	if err := specdos.SaveKeys(keysPath, keys); err != nil {
		return err
	}
	fmt.Println("wrote", genesisPath)
	fmt.Println("wrote", keysPath)
	fmt.Printf("validators=%d honest=%d attackers=%d chainID=%d\n", len(keys.Validators), len(keys.Honest), len(keys.Attackers), keys.ChainID)
	return nil
}

func runNode(args []string) error {
	fs := flag.NewFlagSet("node", flag.ExitOnError)
	genesisPath := fs.String("genesis", "", "genesis.json from specdos init")
	keysPath := fs.String("keys", "", "keys.json from specdos init")
	validatorIndex := fs.Int("validator-index", 0, "validator key index from keys.json")
	dataDir := fs.String("datadir", "specdos-node", "node data directory")
	httpAddr := fs.String("http.addr", "127.0.0.1", "HTTP RPC listen address")
	httpPort := fs.Int("http.port", 8545, "HTTP RPC listen port")
	p2pAddr := fs.String("p2p.addr", "0.0.0.0", "P2P listen address")
	p2pPort := fs.Int("p2p.port", 30303, "P2P listen port")
	bootnodesRaw := fs.String("bootnodes", "", "comma-separated enode URLs")
	staticRaw := fs.String("staticnodes", "", "comma-separated enode URLs to keep connected")
	mineThreads := fs.Int("mine.threads", 1, "mining threads")
	verifyCensorship := fs.Bool("verify-censorship", false, "enable the same miner blocklist used by the original tests")
	maxPeers := fs.Int("maxpeers", 25, "maximum P2P peers")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *genesisPath == "" || *keysPath == "" {
		return fmt.Errorf("--genesis and --keys are required")
	}
	genesis, err := specdos.LoadGenesis(*genesisPath)
	if err != nil {
		return err
	}
	keys, err := specdos.LoadKeys(*keysPath)
	if err != nil {
		return err
	}
	if *validatorIndex < 0 || *validatorIndex >= len(keys.Validators) {
		return fmt.Errorf("validator index %d out of range", *validatorIndex)
	}
	validatorRecord := keys.Validators[*validatorIndex]
	validatorKey, err := specdos.PrivateKey(validatorRecord)
	if err != nil {
		return err
	}

	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	fdlimit.Raise(2048)

	minerCfg := ethconfig.Defaults.Miner
	minerCfg.Blocklist = append([]common.Address(nil), minerCfg.Blocklist...)
	if *verifyCensorship {
		minerCfg.Blocklist = append(minerCfg.Blocklist, specdos.BlacklistedAddress)
	}
	ethcfg := &ethconfig.Config{
		Genesis:         genesis,
		TxPool:          ethconfig.Defaults.TxPool,
		Miner:           minerCfg,
		GPO:             ethconfig.Defaults.GPO,
		NetworkId:       genesis.Config.ChainID.Uint64(),
		SyncMode:        downloader.FullSync,
		DatabaseCache:   256,
		DatabaseHandles: 256,
	}
	bootnodes, err := parseNodes(*bootnodesRaw)
	if err != nil {
		return err
	}
	staticNodes, err := parseNodes(*staticRaw)
	if err != nil {
		return err
	}
	stack, err := node.New(&node.Config{
		Name:         "specdos",
		Version:      params.Version,
		DataDir:      *dataDir,
		HTTPHost:     *httpAddr,
		HTTPPort:     *httpPort,
		HTTPModules:  []string{"eth", "net", "web3", "txpool"},
		HTTPVirtualHosts: []string{"*"},
		P2P: p2p.Config{
			ListenAddr:     fmt.Sprintf("%s:%d", *p2pAddr, *p2pPort),
			NoDiscovery:    true,
			MaxPeers:       *maxPeers,
			BootstrapNodes: bootnodes,
			StaticNodes:    staticNodes,
		},
	})
	if err != nil {
		return err
	}
	defer stack.Close()

	ethservice, err := eth.New(stack, ethcfg)
	if err != nil {
		return err
	}
	if err := stack.Start(); err != nil {
		return err
	}

	ks := keystore.NewKeyStore(stack.KeyStoreDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, err := ks.ImportECDSA(validatorKey, "")
	if errors.Is(err, keystore.ErrAccountAlreadyExists) {
		account, err = ks.Find(accounts.Account{Address: validatorRecord.Address})
	}
	if err != nil {
		return err
	}
	if err := ks.Unlock(account, ""); err != nil {
		return err
	}
	stack.AccountManager().AddBackend(ks)

	ethservice.SetEtherbase(validatorRecord.Address)
	ethservice.APIBackend.Miner().SetEtherbase(validatorRecord.Address)
	ethservice.SetSynced()
	if err := ethservice.StartMining(*mineThreads); err != nil {
		return err
	}
	waitForMiningState(ethservice.Miner(), true)

	info := stack.Server().NodeInfo()
	fmt.Println("validator", validatorRecord.Address.Hex())
	fmt.Println("rpc", fmt.Sprintf("http://%s:%d", *httpAddr, *httpPort))
	fmt.Println("enode", info.Enode)
	fmt.Println("listening; press Ctrl+C to stop")
	waitForSignal()
	return nil
}

func runTxgen(args []string) error {
	fs := flag.NewFlagSet("txgen", flag.ExitOnError)
	keysPath := fs.String("keys", "", "keys.json from specdos init")
	rpcRaw := fs.String("rpc", "", "comma-separated HTTP RPC endpoints")
	modeRaw := fs.String("mode", string(specdos.ModeHonest), "honest, conditional, or combined")
	contractRaw := fs.String("contract", "", "deployed attack contract address; deploys a new one if omitted in attack modes")
	contractOut := fs.String("contract-out", "", "optional path to save the deployed or selected attack contract address")
	deploy := fs.Bool("deploy", true, "deploy attack contract when --contract is omitted")
	honestAccounts := fs.Int("honest-accounts", 0, "number of honest keys to use; 0 means all")
	attackerAccounts := fs.Int("attacker-accounts", 0, "number of attacker keys to use; 0 means all")
	honestTxsPerAccount := fs.Uint64("honest-txs-per-account", 1, "honest transactions per honest account")
	attackerTxsPerAccount := fs.Uint64("attacker-txs-per-account", 1, "attack transactions per attacker account")
	memPurgeLen := fs.Int("mem-purge-len", -1, "MemPurge chain length; default is 2 for combined, 0 otherwise")
	honestRate := fs.Int("honest-rate", 2, "honest send chunks per second")
	attackerRate := fs.Int("attacker-rate", 2, "attacker send chunks per second")
	honestChunk := fs.Int("honest-chunk", 1, "honest transactions per send chunk")
	attackerChunk := fs.Int("attacker-chunk", 1, "attacker transactions per send chunk")
	fanout := fs.Bool("fanout", false, "send every transaction to every RPC endpoint instead of round-robin")
	ignoreNonceTooLow := fs.Bool("ignore-nonce-too-low", false, "treat nonce-too-low send errors as known duplicate/retry errors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keysPath == "" || *rpcRaw == "" {
		return fmt.Errorf("--keys and --rpc are required")
	}
	mode := specdos.AttackMode(*modeRaw)
	if mode != specdos.ModeHonest && mode != specdos.ModeConditional && mode != specdos.ModeCombined {
		return fmt.Errorf("invalid mode %q", *modeRaw)
	}
	keys, err := specdos.LoadKeys(*keysPath)
	if err != nil {
		return err
	}
	rpcs := splitCSV(*rpcRaw)
	if len(rpcs) == 0 {
		return fmt.Errorf("--rpc must contain at least one endpoint")
	}
	clients := make([]*ethclient.Client, len(rpcs))
	for i, endpoint := range rpcs {
		client, err := ethclient.Dial(endpoint)
		if err != nil {
			return fmt.Errorf("connect %s: %w", endpoint, err)
		}
		clients[i] = client
		defer client.Close()
	}
	contract := common.Address{}
	if *contractRaw != "" {
		contract = common.HexToAddress(*contractRaw)
	}
	mpLen := uint64(0)
	if *memPurgeLen >= 0 {
		mpLen = uint64(*memPurgeLen)
	} else if mode == specdos.ModeCombined {
		mpLen = 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	workload, err := specdos.BuildWorkload(ctx, clients[0], specdos.TxgenConfig{
		Mode:                  mode,
		Contract:              contract,
		DeployContract:        *deploy,
		HonestRecords:         specdos.LimitRecords(keys.Honest, *honestAccounts),
		AttackerRecords:       specdos.LimitRecords(keys.Attackers, *attackerAccounts),
		HonestTxsPerAccount:   *honestTxsPerAccount,
		AttackerTxsPerAccount: *attackerTxsPerAccount,
		MemPurgeLen:           mpLen,
	})
	if err != nil {
		return err
	}
	if *contractOut != "" && workload.Contract != (common.Address{}) {
		if err := specdos.SaveContractAddress(*contractOut, workload.Contract); err != nil {
			return err
		}
	}
	fmt.Printf("prepared honest=%d attacker=%d contract=%s\n", len(workload.HonestTxs), len(workload.AttackerTxs), workload.Contract.Hex())
	stats, err := specdos.SendWorkload(ctx, clients, workload, specdos.SendConfig{
		HonestRatePerSecond:   *honestRate,
		AttackerRatePerSecond: *attackerRate,
		HonestChunkSize:       *honestChunk,
		AttackerChunkSize:     *attackerChunk,
		Fanout:                *fanout,
		IgnoreNonceTooLow:     *ignoreNonceTooLow,
	})
	if err != nil {
		return err
	}
	fmt.Printf("sent all transactions: attempted=%d sent=%d known=%d failed=%d duration=%s\n", stats.Attempted, stats.Sent, stats.Known, stats.Failed, stats.Duration().Round(time.Millisecond))
	return nil
}

func runMonitor(args []string) error {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	keysPath := fs.String("keys", "", "keys.json from specdos init")
	rpc := fs.String("rpc", "", "HTTP RPC endpoint")
	outPath := fs.String("out", "-", "JSONL output path, or - for stdout")
	startRaw := fs.String("start", "latest", "start block number, or latest")
	interval := fs.Duration("interval", time.Second, "poll interval")
	honestAccounts := fs.Int("honest-accounts", 0, "number of honest keys to classify; 0 means all")
	attackerAccounts := fs.Int("attacker-accounts", 0, "number of attacker keys to classify; 0 means all")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keysPath == "" || *rpc == "" {
		return fmt.Errorf("--keys and --rpc are required")
	}
	keys, err := specdos.LoadKeys(*keysPath)
	if err != nil {
		return err
	}
	client, err := ethclient.Dial(*rpc)
	if err != nil {
		return err
	}
	defer client.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	startBlock, err := parseStartBlock(ctx, client, *startRaw)
	if err != nil {
		return err
	}

	out := os.Stdout
	if *outPath != "" && *outPath != "-" {
		if err := os.MkdirAll(filepath.Dir(*outPath), 0755); err != nil {
			return err
		}
		file, err := os.Create(*outPath)
		if err != nil {
			return err
		}
		defer file.Close()
		out = file
	}
	err = specdos.MonitorBlocks(
		ctx,
		client,
		specdos.LimitRecords(keys.Honest, *honestAccounts),
		specdos.LimitRecords(keys.Attackers, *attackerAccounts),
		startBlock,
		*interval,
		out,
	)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func parseStartBlock(ctx context.Context, client *ethclient.Client, raw string) (uint64, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "latest", "head":
		return client.BlockNumber(ctx)
	default:
		return strconv.ParseUint(raw, 10, 64)
	}
}

func parseNodes(raw string) ([]*enode.Node, error) {
	parts := splitCSV(raw)
	nodes := make([]*enode.Node, 0, len(parts))
	for _, part := range parts {
		node, err := enode.ParseV4(part)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func waitForMiningState(m *miner.Miner, mining bool) {
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if m.Mining() == mining {
			return
		}
	}
}

func waitForSignal() {
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	<-sigc
}
