package solidity

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	eddsaSig "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/accumulator/merkle"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/suite"
)

type consolidatedCircuit struct {
	curveID   tedwards.ID
	PublicKey eddsa.PublicKey         
	Signature eddsa.Signature         
	Message   frontend.Variable 
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
}

func (circuit *consolidatedCircuit) Define(api frontend.API) error {
	// Merkle Verify circuit
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	merkle.VerifyProof(api, hFunc, circuit.RootHash, circuit.Path, circuit.Helper)

	// EdDSA circuit
	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &hFunc)
}

type ExportSolidityTestSuite struct {
	suite.Suite

	// backend
	backend *backends.SimulatedBackend

	// verifier contract
	verifierContract *Verifier

	// groth16 gnark objects
	vk      groth16.VerifyingKey
	pk      groth16.ProvingKey
	circuit consolidatedCircuit
	r1cs    frontend.CompiledConstraintSystem
}

func TestRunExportSolidityTestSuite(t *testing.T) {
	suite.Run(t, new(ExportSolidityTestSuite))
}

func (t *ExportSolidityTestSuite) SetupTest() {

	const gasLimit uint64 = 4712388

	// setup simulated backend
	key, _ := crypto.GenerateKey()
	auth, err := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	t.NoError(err, "init keyed transactor")

	genesis := map[common.Address]core.GenesisAccount{
		auth.From: {Balance: big.NewInt(1000000000000000000)}, // 1 Eth
	}
	t.backend = backends.NewSimulatedBackend(genesis, gasLimit)

	// deploy verifier contract
	_, _, v, err := DeployVerifier(auth, t.backend)
	t.NoError(err, "deploy verifier contract failed")
	t.verifierContract = v
	t.backend.Commit()

	t.r1cs, err = frontend.Compile(ecc.BN254, r1cs.NewBuilder, &t.circuit)
	t.NoError(err, "compiling R1CS failed")

	// read proving and verifying keys
	t.pk = groth16.NewProvingKey(ecc.BN254)
	{
		f, _ := os.Open("provingKey.pk")
		_, err = t.pk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading proving key failed")
	}
	t.vk = groth16.NewVerifyingKey(ecc.BN254)
	{
		f, _ := os.Open("verifyingKey.vk")
		_, err = t.vk.ReadFrom(f)
		f.Close()
		t.NoError(err, "reading verifying key failed")
	}

}

func (t *ExportSolidityTestSuite) TestVerifyProof() {

	// Merkle Setup
	// generate random data
	// makes sure that each chunk of 64 bits fits in a fr modulus, otherwise there are bugs due to the padding (domain separation)
	// TODO since when using mimc the user should be aware of this fact (otherwise one can easily finds collision), I am not sure we should take care of that in the code
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		var leaf fr.Element
		if _, err := leaf.SetRandom(); err != nil {
			// fmt.Printf("%v", err)
		}
		b := leaf.Bytes()
		buf.Write(b[:])
	}

	// fmt.Println("buf:", buf.Bytes())

	// build & verify proof for an elmt in the file
	proofIndex := uint64(0)
	segmentSize := 32
	merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn254.NewMiMC(), segmentSize, proofIndex)
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(-1)
	}
	proofHelper := merkle.GenerateProofHelper(proof, proofIndex, numLeaves)

	verified := merkletree.VerifyProof(bn254.NewMiMC(), merkleRoot, proof, proofIndex, numLeaves)
	if !verified {
		fmt.Printf("The merkle proof in plain go should pass")
	}

	// EdDSA Setup
	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, tedwards.BN254},
	}

	seed := time.Now().Unix()
	// fmt.Printf("setting seed in rand %d", seed)
	randomness := rand.New(rand.NewSource(seed))

	snarkCurve, err := twistededwards.GetSnarkCurve(confs[0].curve)
	if err != nil {os.Exit(-1)}

	// generate parameters for the signatures
	privKey, err := eddsaSig.New(confs[0].curve, randomness)
	if err != nil {
		// fmt.Printf("%v", err)
		os.Exit(-1)
	}

	// pick a message to sign
	var msg big.Int
	msg.Rand(randomness, snarkCurve.Info().Fr.Modulus())
	// fmt.Println("msg to sign", msg.String())
	msgData := msg.Bytes()

	// generate signature
	signature, err := privKey.Sign(msgData[:], confs[0].hash.New())
	if err != nil {
		// fmt.Printf("%v", err)
		os.Exit(-1)
	}

	// check if there is no problem in the signature
	pubKey := privKey.Public()
	checkSig, err := pubKey.Verify(signature, msgData[:], confs[0].hash.New())
	if err != nil {
		// fmt.Printf("%v", "verifying signature")
		os.Exit(-1)
	}
	if !checkSig {
		// fmt.Printf("signature verification failed")
		os.Exit(-1)
	}

	// creatin witness
	assignment := consolidatedCircuit{
		Path:     make([]frontend.Variable, len(proof)),
		Helper:   make([]frontend.Variable, len(proof)-1),
		RootHash: (merkleRoot),
	}
	for i := 0; i < len(proof); i++ {
		assignment.Path[i] = (proof[i])
	}
	for i := 0; i < len(proof)-1; i++ {
		assignment.Helper[i] = (proofHelper[i])
	}
	assignment.Message = msg
	assignment.PublicKey.Assign(snarkCurve, pubKey.Bytes())
	assignment.Signature.Assign(snarkCurve, signature)

	// witness creation
	witness, err := frontend.NewWitness(&assignment, ecc.BN254)
	t.NoError(err, "witness creation failed")

	// prove
	_proof, err := groth16.Prove(t.r1cs, t.pk, witness)
	t.NoError(err, "proving failed")

	// ensure gnark (Go) code verifies it
	publicWitness, _ := witness.Public()
	err = groth16.Verify(_proof, t.vk, publicWitness)
	t.NoError(err, "verifying failed")

	// get proof bytes
	const fpSize = 4 * 8
	var buff bytes.Buffer
	_proof.WriteRawTo(&buff)
	proofBytes := buff.Bytes()

	// solidity contract inputs
	var (
		a     [2]*big.Int
		b     [2][2]*big.Int
		c     [2]*big.Int
		input [1]*big.Int
	)

	// proof.Ar, proof.Bs, proof.Krs
	a[0] = new(big.Int).SetBytes(proofBytes[fpSize*0 : fpSize*1])
	a[1] = new(big.Int).SetBytes(proofBytes[fpSize*1 : fpSize*2])
	b[0][0] = new(big.Int).SetBytes(proofBytes[fpSize*2 : fpSize*3])
	b[0][1] = new(big.Int).SetBytes(proofBytes[fpSize*3 : fpSize*4])
	b[1][0] = new(big.Int).SetBytes(proofBytes[fpSize*4 : fpSize*5])
	b[1][1] = new(big.Int).SetBytes(proofBytes[fpSize*5 : fpSize*6])
	c[0] = new(big.Int).SetBytes(proofBytes[fpSize*6 : fpSize*7])
	c[1] = new(big.Int).SetBytes(proofBytes[fpSize*7 : fpSize*8])

	// public witness
	input[0] = new(big.Int).SetBytes(merkleRoot)

	// call the contract
	res, err := t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.True(res, "calling verifier on chain didn't succeed")

	// (wrong) public witness
	input[0] = new(big.Int).SetUint64(42)

	// call the contract should fail
	res, err = t.verifierContract.VerifyProof(nil, a, b, c, input)
	t.NoError(err, "calling verifier on chain gave error")
	t.False(res, "calling verifier on chain succeed, and shouldn't have")
}
