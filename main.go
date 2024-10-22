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
    OOD_Point frontend.Variable
}

func U8SliceToVariable(api frontend.API, u8Slice []uints.U8) frontend.Variable {
    frontendVar := frontend.Variable(0)
    for i := range u8Slice {
        frontendVar = api.Add(api.Mul(256, frontendVar), u8Slice[i].Val)
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
    ood_point := U8SliceToVariable(api, mainSponge.Sum(47))
    api.AssertIsEqual(ood_point, circuit.OOD_Point)
    return nil
}

func main() {
    iopattern := uint8SliceToVariableSlice([]uint8{240, 159, 140, 170, 239, 184, 143, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 52, 55, 105, 110, 105, 116, 105, 97, 108, 95, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 51, 50, 115, 116, 105, 114, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100, 0, 83, 52, 55, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 102, 105, 110, 97, 108, 95, 99, 111, 101, 102, 102, 115, 0, 83, 51, 50, 102, 105, 110, 97, 108, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100})
    root := uint8SliceToVariableSlice([]uint8{117, 219, 183, 48, 66, 2, 168, 33, 165, 72, 106, 246, 82, 158, 98, 42, 29, 150, 218, 108, 53, 43, 49, 242, 151, 3, 90, 123, 210, 62, 179, 114})
    ood_point, _ := new(big.Int).SetString("13170359327494281504307648069332795916956650169018289630205755501423589343739", 10)

    var circuit = Circuit{
        IOPattern: make([]frontend.Variable, len(iopattern)),
        Root: make([]frontend.Variable, len(root)),
    }

    ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    pk, vk, _ := groth16.Setup(ccs)
    
    assignment := Circuit{
        IOPattern: iopattern,
        Root: root,
        OOD_Point: ood_point,
    }

    witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    publicWitness, _ := witness.Public()
    proof, _ := groth16.Prove(ccs, pk, witness)
    groth16.Verify(proof, vk, publicWitness)
}


