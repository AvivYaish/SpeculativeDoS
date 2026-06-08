package specdos

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

const (
	DefaultChainID      = uint64(13371337)
	DefaultGasLimit     = uint64(30000000)
	DefaultCliquePeriod = uint64(12)
)

var (
	// ConditionalExhaust is the block-height variant used by the original tests.
	ConditionalExhaustCode = common.Hex2Bytes("608060405234801561001057600080fd5b50610173806100206000396000f3fe60806040526004361061001e5760003560e01c806302069f7d14610023575b600080fd5b61003d600480360381019061003891906100fd565b61003f565b005b8143101561007d575b600081111561005c57600181039050610048565b60008060008060017316000000000000000000000000000000000000005af1505b5050565b600080fd5b600063ffffffff82169050919050565b61009f81610086565b81146100aa57600080fd5b50565b6000813590506100bc81610096565b92915050565b600062ffffff82169050919050565b6100da816100c2565b81146100e557600080fd5b50565b6000813590506100f7816100d1565b92915050565b6000806040838503121561011457610113610081565b5b6000610122858286016100ad565b9250506020610133858286016100e8565b915050925092905056fea264697066735822122081e43b6d25cffa7a56a18db005bfd0d691c4b5d831a17d8f755f6dcf55a20edd64736f6c63430008120033")
	ConditionalExhaustData = common.Hex2Bytes("02069f7d0000000000000000000000000000000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000008f0ff")

	// CombinedAttack combines MemPurge with ConditionalExhaust, matching api_test.go.
	CombinedAttackCode = common.Hex2Bytes("608060405234801561001057600080fd5b506101a0806100206000396000f3fe60806040526004361061001e5760003560e01c806302069f7d14610023575b600080fd5b61003d6004803603810190610038919061012a565b61003f565b005b8143101561008b575b600081111561005c57600181039050610048565b60008060008060017316000000000000000000000000000000000000005af15060008060008060013403325af1005b60008060008034735b38da6a701c568545dcfcb03fcb875f56beddc45af1505050565b600080fd5b600063ffffffff82169050919050565b6100cc816100b3565b81146100d757600080fd5b50565b6000813590506100e9816100c3565b92915050565b600062ffffff82169050919050565b610107816100ef565b811461011257600080fd5b50565b600081359050610124816100fe565b92915050565b60008060408385031215610141576101406100ae565b5b600061014f858286016100da565b925050602061016085828601610115565b915050925092905056fea2646970667358221220d8bcf73b9276e90ae2cea0e53138653e88b78b93f78b8d2cb026194c85d9a20464736f6c63430008120033")
	CombinedAttackData = common.Hex2Bytes("02069f7d0000000000000000000000000000000000000000000000000000000001100000000000000000000000000000000000000000000000000000000000000008f0ff")

	BlacklistedAddress = common.Address{0x16}
	TxPoolSize         = int(txpool.DefaultConfig.GlobalSlots + txpool.DefaultConfig.GlobalQueue)
)

type KeyRecord struct {
	Index      int            `json:"index"`
	Address    common.Address `json:"address"`
	PrivateKey string         `json:"privateKey"`
}

type KeyFile struct {
	ChainID    uint64      `json:"chainId"`
	Validators []KeyRecord `json:"validators"`
	Honest     []KeyRecord `json:"honest"`
	Attackers  []KeyRecord `json:"attackers"`
}

func GenerateLabConfig(validators, honest, attackers int, chainID, cliquePeriod uint64) (*core.Genesis, *KeyFile, error) {
	if validators <= 0 {
		return nil, nil, fmt.Errorf("validators must be greater than 0")
	}
	if honest < 0 || attackers < 0 {
		return nil, nil, fmt.Errorf("honest and attacker key counts must be non-negative")
	}
	if chainID == 0 {
		chainID = DefaultChainID
	}
	if cliquePeriod == 0 {
		cliquePeriod = DefaultCliquePeriod
	}

	validatorKeys, validatorRecords, err := generateRecords(validators)
	if err != nil {
		return nil, nil, err
	}
	_, honestRecords, err := generateRecords(honest)
	if err != nil {
		return nil, nil, err
	}
	_, attackerRecords, err := generateRecords(attackers)
	if err != nil {
		return nil, nil, err
	}

	alloc := make(core.GenesisAlloc)
	defaultBalance := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
	for _, record := range append(append(validatorRecords, honestRecords...), attackerRecords...) {
		alloc[record.Address] = core.GenesisAccount{Balance: new(big.Int).Set(defaultBalance)}
	}

	config := *params.AllCliqueProtocolChanges
	config.ChainID = new(big.Int).SetUint64(chainID)
	config.Clique = &params.CliqueConfig{
		Period: cliquePeriod,
		Epoch:  params.AllCliqueProtocolChanges.Clique.Epoch,
	}

	genesis := &core.Genesis{
		Config:     &config,
		GasLimit:   DefaultGasLimit,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(0),
		Alloc:      alloc,
		ExtraData:  cliqueExtraData(validatorKeys),
	}
	keys := &KeyFile{
		ChainID:    chainID,
		Validators: validatorRecords,
		Honest:     honestRecords,
		Attackers:  attackerRecords,
	}
	return genesis, keys, nil
}

func SaveGenesis(path string, genesis *core.Genesis) error {
	return writeJSON(path, genesis)
}

func LoadGenesis(path string) (*core.Genesis, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var genesis core.Genesis
	if err := json.NewDecoder(file).Decode(&genesis); err != nil {
		return nil, err
	}
	return &genesis, nil
}

func SaveKeys(path string, keys *KeyFile) error {
	return writeJSON(path, keys)
}

func LoadKeys(path string) (*KeyFile, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var keys KeyFile
	if err := json.NewDecoder(file).Decode(&keys); err != nil {
		return nil, err
	}
	return &keys, nil
}

func PrivateKey(record KeyRecord) (*ecdsa.PrivateKey, error) {
	return crypto.HexToECDSA(strings.TrimPrefix(record.PrivateKey, "0x"))
}

func PrivateKeys(records []KeyRecord) ([]*ecdsa.PrivateKey, []common.Address, error) {
	keys := make([]*ecdsa.PrivateKey, len(records))
	addrs := make([]common.Address, len(records))
	for i, record := range records {
		key, err := PrivateKey(record)
		if err != nil {
			return nil, nil, fmt.Errorf("decode key %d: %w", i, err)
		}
		addr := crypto.PubkeyToAddress(key.PublicKey)
		if addr != record.Address {
			return nil, nil, fmt.Errorf("key %d address mismatch: key=%s file=%s", i, addr.Hex(), record.Address.Hex())
		}
		keys[i] = key
		addrs[i] = addr
	}
	return keys, addrs, nil
}

func LimitRecords(records []KeyRecord, limit int) []KeyRecord {
	if limit <= 0 || limit >= len(records) {
		return records
	}
	return records[:limit]
}

func generateRecords(n int) ([]*ecdsa.PrivateKey, []KeyRecord, error) {
	keys := make([]*ecdsa.PrivateKey, n)
	records := make([]KeyRecord, n)
	for i := 0; i < n; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			return nil, nil, err
		}
		keys[i] = key
		records[i] = KeyRecord{
			Index:      i,
			Address:    crypto.PubkeyToAddress(key.PublicKey),
			PrivateKey: "0x" + hex.EncodeToString(crypto.FromECDSA(key)),
		}
	}
	return keys, records, nil
}

func cliqueExtraData(keys []*ecdsa.PrivateKey) []byte {
	signers := make([]common.Address, len(keys))
	for i, key := range keys {
		signers[i] = crypto.PubkeyToAddress(key.PublicKey)
	}
	sort.Slice(signers, func(i, j int) bool {
		return bytes.Compare(signers[i][:], signers[j][:]) < 0
	})
	extra := make([]byte, 32+(len(signers)*common.AddressLength)+65)
	for i, signer := range signers {
		copy(extra[32+i*common.AddressLength:], signer[:])
	}
	return extra
}

func writeJSON(path string, v interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
