package main

import (
    "math/big"
    "github.com/consensys/gnark/std/math/uints"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "reilabs/whir-verifier-circuit/keccakSponge"
)

type Circuit struct {
    IOPattern []frontend.Variable
    Root []frontend.Variable
    OOD_Answer []frontend.Variable

    Evaluation  frontend.Variable `gnark:"Supposed evaluation of the polynomial for the verifier query"`
	InitialPolynomialEvaluations []frontend.Variable `gnark:"Expected Sum"`
}

func U8SliceToVariableBigEndian(api frontend.API, u8Slice []uints.U8) frontend.Variable {
    frontendVar := frontend.Variable(0)
    for i := range u8Slice {
        frontendVar = api.Add(api.Mul(256, frontendVar), u8Slice[i].Val)
    }
    return frontendVar
}

func U8SliceToVariableLittleEndian(api frontend.API, u8Slice []uints.U8) frontend.Variable {
    frontendVar := frontend.Variable(0)
    for i := range u8Slice {
        frontendVar = api.Add(api.Mul(256, frontendVar), u8Slice[len(u8Slice) - 1 - i].Val)
    }
    return frontendVar
}

func VariableSliceToU8Slice(api frontend.API, frontendSlice []frontend.Variable) []uints.U8 {
	u8Slice := make([]uints.U8, len(frontendSlice))
    for i := range frontendSlice {
        u8Slice[i].Val = frontendSlice[i]
    }
    return u8Slice
}

func uint8SliceToVariableSlice(uint8Slice []uint8) []frontend.Variable {
    frontendSlice := make([]frontend.Variable, len(uint8Slice))
    for i := range frontendSlice {
        frontendSlice[i] = frontend.Variable(uint8Slice[i])
    }
    return frontendSlice
}

func squeezeTagFromIOPattern (api frontend.API, iopattern []uints.U8) []uints.U8 {
	sponge, _ := keccakSponge.NewKeccak(api)
	sponge.Write(iopattern)
	return sponge.Sum(32)
}

func (circuit *Circuit) Define(api frontend.API) error {
    tag := squeezeTagFromIOPattern(api, VariableSliceToU8Slice(api, circuit.IOPattern)) 
	mainSponge, _ := keccakSponge.NewKeccakWithTag(api, tag)
    mainSponge.Write(VariableSliceToU8Slice(api, circuit.Root))
    _ = U8SliceToVariableBigEndian(api, mainSponge.Sum(47))
    oOD_Answer := VariableSliceToU8Slice(api, circuit.OOD_Answer)
    mainSponge.Write(oOD_Answer)
    initialCombinationRandomness := U8SliceToVariableBigEndian(api, mainSponge.Sum(47))
    sumOverBools := api.Add(circuit.InitialPolynomialEvaluations[0], circuit.InitialPolynomialEvaluations[1])
    plugInEvaluation := api.Add(U8SliceToVariableLittleEndian(api, oOD_Answer), api.Mul(initialCombinationRandomness, circuit.Evaluation))
	api.AssertIsEqual(sumOverBools, plugInEvaluation)
    return nil
}

func main() {
    iopattern := uint8SliceToVariableSlice([]uint8{240, 159, 140, 170, 239, 184, 143, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 52, 55, 105, 110, 105, 116, 105, 97, 108, 95, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 51, 50, 115, 116, 105, 114, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100, 0, 83, 52, 55, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 102, 105, 110, 97, 108, 95, 99, 111, 101, 102, 102, 115, 0, 83, 51, 50, 102, 105, 110, 97, 108, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100})
    root := uint8SliceToVariableSlice([]uint8{117, 219, 183, 48, 66, 2, 168, 33, 165, 72, 106, 246, 82, 158, 98, 42, 29, 150, 218, 108, 53, 43, 49, 242, 151, 3, 90, 123, 210, 62, 179, 114})
    ood_answer := uint8SliceToVariableSlice([]uint8{232, 157, 134, 234, 158, 134, 91, 70, 113, 77, 8, 124, 33, 234, 255, 131, 168, 158, 236, 153, 242, 231, 64, 95, 146, 251, 84, 154, 27, 157, 181, 37})

    evaluation, _ := new(big.Int).SetString("6", 10)
	coeff1, _ := new(big.Int).SetString("7529750666988914074745719251931937881520028440248195310154011364354260691222", 10)
	coeff2, _ := new(big.Int).SetString("9794441924853000479973554649540588199056692045660459233737985907256721979560", 10)
	coeff3, _ := new(big.Int).SetString("13329240161431836426016876217180991137593108258493123784047829475319792427981", 10)

    var circuit = Circuit{
        IOPattern: make([]frontend.Variable, len(iopattern)),
        Root: make([]frontend.Variable, len(root)),
        OOD_Answer: make([]frontend.Variable, len(ood_answer)),
		InitialPolynomialEvaluations: make([]frontend.Variable, 3),
    }

    ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    pk, vk, _ := groth16.Setup(ccs)
    
    assignment := Circuit{
        IOPattern: iopattern,
        Root: root,
        OOD_Answer: ood_answer,

        Evaluation: evaluation, 
		InitialPolynomialEvaluations:  []frontend.Variable{coeff1, coeff2, coeff3},
        
    }

    witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    publicWitness, _ := witness.Public()
    proof, _ := groth16.Prove(ccs, pk, witness)
    groth16.Verify(proof, vk, publicWitness)
}


