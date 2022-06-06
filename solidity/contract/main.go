package main

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"os"
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


// run this from /integration/solidity to regenerate files
// note: this is not in go generate format to avoid solc dependency in circleCI for now.
// go run contract/main.go && abigen --sol contract.sol --pkg solidity --out solidity.go
func main() {
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
	// proofHelper := merkle.GenerateProofHelper(proof, proofIndex, numLeaves)

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

		
	// creating circuit
	circuit := consolidatedCircuit{
		Path:   make([]frontend.Variable, len(proof)),
		Helper: make([]frontend.Variable, len(proof)-1),
	}
	circuit.curveID = confs[0].curve



	r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		panic(err)
	}
	{
		f, err := os.Create("verifyingKey.vk")
		if err != nil {
			panic(err)
		}
		_, err = vk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}
	{
		f, err := os.Create("provingKey.pk")
		if err != nil {
			panic(err)
		}
		_, err = pk.WriteRawTo(f)
		if err != nil {
			panic(err)
		}
	}

	{
		f, err := os.Create("verifier.sol")
		if err != nil {
			panic(err)
		}
		err = vk.ExportSolidity(f)
		if err != nil {
			panic(err)
		}
	}

}
