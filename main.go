package main

import (
	// "fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"math/big"
)	

type Circuit struct {
	Evaluation  frontend.Variable `gnark:"Supposed evaluation of the polynomial for the verifier query"`
	InitialPolynomialEvaluations []frontend.Variable `gnark:"Expected Sum"`
	InitialCombinationRandomness frontend.Variable `gnark:"Combination Randomness"` //This one should be squeezed out of the proof
	OODEvaluation frontend.Variable `gnark:"Combination Randomness"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	sumOverBools := api.Add(circuit.InitialPolynomialEvaluations[0], circuit.InitialPolynomialEvaluations[1])
	plugInEvaluation := api.Add(circuit.OODEvaluation, api.Mul(circuit.InitialCombinationRandomness, circuit.Evaluation))
	api.AssertIsEqual(sumOverBools, plugInEvaluation)
	return nil
}

func main() {
	var initialPolynomialPlaceholder = make([]frontend.Variable, 3)
	var circuit = Circuit{
		InitialPolynomialEvaluations: initialPolynomialPlaceholder,
	}
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)
	
	evaluation, _ := new(big.Int).SetString("6", 10)
	coeff1, _ := new(big.Int).SetString("7529750666988914074745719251931937881520028440248195310154011364354260691222", 10)
	coeff2, _ := new(big.Int).SetString("9794441924853000479973554649540588199056692045660459233737985907256721979560", 10)
	coeff3, _ := new(big.Int).SetString("13329240161431836426016876217180991137593108258493123784047829475319792427981", 10)
	oodEvaluation, _ := new(big.Int).SetString("17056459034653802837952596924932948883816720581463178781510726994247050239464", 10)
	 
	initialCombinationRandomness, _:= new(big.Int).SetString("7340703216811110360209914744509021228976121450879590741629613108419258237092", 10)
	
	assignment := Circuit{
		Evaluation: evaluation, 
		InitialPolynomialEvaluations:  []frontend.Variable{coeff1, coeff2, coeff3},
		InitialCombinationRandomness: initialCombinationRandomness,
		OODEvaluation: oodEvaluation,
	}

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
