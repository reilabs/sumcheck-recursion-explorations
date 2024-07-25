package main

import(
	// "github.com/vocdoni/gnark-crypto-primitives/poseidon"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	// "github.com/kr/pretty"j
	"tutorial/sumcheck-verifier-circuit/polynomials"
)

type Circuit struct {
	c1 frontend.Variable `gnark:"C1"`
	g1Coeff frontend.Variable `gnark:"g_1 Coefficients"`
	// Y frontend.Variable `gnark:",public"`
}

func (circuit *Circuit) Define (api frontend.API) error {
	g1_0 := polynomials.CircUniPoly(circuit.g1Coeff.([]frontend.Variable), 0, api)
	g1_1 := polynomials.CircUniPoly(circuit.g1Coeff.([]frontend.Variable), 1, api)
	api.AssertIsEqual(g1_0, g1_1)
	return nil
}

func main() {
	var circuit Circuit 
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)

	//g(x, y) := 1 + 3x + 7y + 10xy
	assignment := Circuit{
		c1: 34,
		g1Coeff: []frontend.Variable{9, 16},
	}
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
