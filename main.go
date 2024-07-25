package main

import(
	"github.com/vocdoni/gnark-crypto-primitives/poseidon"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"tutorial/sumcheck-verifier-circuit/polynomials"
	// "github.com/kr/pretty"
	"math/big"
)

type Circuit struct {
	Seed frontend.Variable `gnark:"Seed"` 
	C1 frontend.Variable `gnark:"C1"`
	R1 frontend.Variable `gnark:"R1"`
	R2 frontend.Variable `gnark:"R2"`
	G_Coeffs [4]frontend.Variable `gnark:"G Coefficients"`
	G1_Coeffs [2]frontend.Variable `gnark:"G1 Coefficients"`
	G2_Coeffs [2]frontend.Variable `gnark:"G2 Coefficients"`
}

func (circuit *Circuit) Define (api frontend.API) error {
	g1_0 := polynomials.CircUniPoly(circuit.G1_Coeffs[:], 0, api)
	g1_1 := polynomials.CircUniPoly(circuit.G1_Coeffs[:], 1, api)
	api.AssertIsEqual(circuit.C1, api.Add(g1_0, g1_1))
	api.AssertIsEqual(circuit.R1, poseidon.Hash(api, circuit.Seed))
	g2_0 := polynomials.CircUniPoly(circuit.G2_Coeffs[:], 0, api)
	g2_1 := polynomials.CircUniPoly(circuit.G2_Coeffs[:], 1, api)
	g1_r1 := polynomials.CircUniPoly(circuit.G1_Coeffs[:], circuit.R1, api)
	api.AssertIsEqual(api.Add(g2_0, g2_1), g1_r1)
	api.AssertIsEqual(poseidon.Hash(api, circuit.R1), circuit.R2)
	g2_r2 := polynomials.CircUniPoly(circuit.G2_Coeffs[:], circuit.R2, api)
	g_eval := polynomials.CircMultPoly(circuit.G_Coeffs[:], []frontend.Variable{circuit.R1, circuit.R2}, api)
	api.AssertIsEqual(g2_r2, g_eval)
	return nil
}

func main() {
	var circuit Circuit 
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	pk, vk, _ := groth16.Setup(ccs)
	// ------
	R1, _ := new(big.Int).SetString("9256297558679035993185603119224026483248878132105160101344427504900917382708", 10)
	R2, _ := new(big.Int).SetString("1501086694344315373207989466448958625613689647511317698257372243506299745486", 10)
	G2_0, _ := new(big1Int).SetString("5880649804197832757310403612414804361198269995899445960335078328126943652508", 10)
	G2_1, _ := new(big.Int).SetString("5010004099433259042870408211211164478295323719387463638651458302705939844619", 10)

	assignment := Circuit{ 
		Seed: 47,
		C1: 34,
		R1: R1,
		R2: R2,
		G_Coeffs: [4]frontend.Variable{1,3,7,10}, //g(x, y) := 1 + 3x + 7y + 10xy
		G1_Coeffs: [2]frontend.Variable{9,16},
		G2_Coeffs: [2]frontend.Variable{G2_0, G2_1},
	}
	// ------
	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
