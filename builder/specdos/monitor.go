package specdos

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

type BlockMetric struct {
	ObservedAt  time.Time   `json:"observedAt"`
	Number      uint64      `json:"number"`
	Hash        common.Hash `json:"hash"`
	Timestamp   uint64      `json:"timestamp"`
	TxCount     int         `json:"txCount"`
	HonestTxs   int         `json:"honestTxs"`
	AttackerTxs int         `json:"attackerTxs"`
	OtherTxs    int         `json:"otherTxs"`
	UnknownTxs  int         `json:"unknownTxs"`
	Empty       bool        `json:"empty"`
	GasUsed     uint64      `json:"gasUsed"`
	GasLimit    uint64      `json:"gasLimit"`
}

func MonitorBlocks(ctx context.Context, client *ethclient.Client, honestRecords []KeyRecord, attackerRecords []KeyRecord, startBlock uint64, interval time.Duration, out io.Writer) error {
	if interval <= 0 {
		interval = time.Second
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		return fmt.Errorf("chain id: %w", err)
	}
	signer := types.LatestSignerForChainID(chainID)
	honest := addressSet(honestRecords)
	attackers := addressSet(attackerRecords)
	enc := json.NewEncoder(out)
	next := startBlock
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		head, err := client.BlockNumber(ctx)
		if err != nil {
			return fmt.Errorf("latest block number: %w", err)
		}
		for next <= head {
			block, err := client.BlockByNumber(ctx, new(big.Int).SetUint64(next))
			if err != nil {
				return fmt.Errorf("block %d: %w", next, err)
			}
			metric := BlockMetricFromBlock(signer, block, honest, attackers)
			if err := enc.Encode(metric); err != nil {
				return err
			}
			next++
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func BlockMetricFromBlock(signer types.Signer, block *types.Block, honest map[common.Address]struct{}, attackers map[common.Address]struct{}) BlockMetric {
	metric := BlockMetric{
		ObservedAt: time.Now().UTC(),
		Number:     block.NumberU64(),
		Hash:       block.Hash(),
		Timestamp:  block.Time(),
		TxCount:    block.Transactions().Len(),
		Empty:      block.Transactions().Len() == 0,
		GasUsed:    block.GasUsed(),
		GasLimit:   block.GasLimit(),
	}
	for _, tx := range block.Transactions() {
		from, err := types.Sender(signer, tx)
		if err != nil {
			metric.UnknownTxs++
			continue
		}
		if _, ok := honest[from]; ok {
			metric.HonestTxs++
			continue
		}
		if _, ok := attackers[from]; ok {
			metric.AttackerTxs++
			continue
		}
		metric.OtherTxs++
	}
	return metric
}

func addressSet(records []KeyRecord) map[common.Address]struct{} {
	set := make(map[common.Address]struct{}, len(records))
	for _, record := range records {
		set[record.Address] = struct{}{}
	}
	return set
}
