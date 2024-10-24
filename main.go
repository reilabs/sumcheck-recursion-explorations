package main

import (
    "math/big"
    "github.com/consensys/gnark-crypto/ecc"
    "github.com/consensys/gnark/backend/groth16"
    "github.com/consensys/gnark/frontend"
    "github.com/consensys/gnark/frontend/cs/r1cs"
    "reilabs/whir-verifier-circuit/keccakSponge"
    "reilabs/whir-verifier-circuit/typeConverters"
)

type Circuit struct {
    IOPattern []frontend.Variable
    MerkleRoot []frontend.Variable
    OOD_Answer []frontend.Variable
    Evaluation  frontend.Variable `gnark:"Supposed evaluation of the polynomial for the verifier query"`
	InitialPolyEvals [][]frontend.Variable `gnark:"Expected Sum"`
    SecondPolyEvals [][]frontend.Variable `gnark:"Expected Sum"`
}

func initializeSpongeWithIOPatternAndMerkleRoot (circuit *Circuit, api frontend.API) *keccakSponge.Digest {
    helperSponge, _ := keccakSponge.NewKeccak(api)
	helperSponge.Write(circuit.IOPattern)
	mainSponge, _ := keccakSponge.NewKeccakWithTag(api, helperSponge.Sum(32))
    mainSponge.Write(circuit.MerkleRoot)
    _ = typeConverters.BigEndian(api, mainSponge.Sum(47))
    return mainSponge
}

func checkFirstSumcheckOfFirstRound (mainSponge *keccakSponge.Digest, circuit *Circuit, api frontend.API) {
    mainSponge.Write(circuit.OOD_Answer)
    initialCombinationRandomness := typeConverters.BigEndian(api, mainSponge.Sum(47))
    sumOverBools := api.Add(
        typeConverters.LittleEndian(api, circuit.InitialPolyEvals[0]), 
        typeConverters.LittleEndian(api, circuit.InitialPolyEvals[1]),
    )
    plugInEvaluation := api.Add(
        typeConverters.LittleEndian(api, circuit.OOD_Answer), 
        api.Mul(initialCombinationRandomness, circuit.Evaluation),
    )
	api.AssertIsEqual(sumOverBools, plugInEvaluation)
}

func evaluateFunction(api frontend.API, evaluations [][]frontend.Variable, point frontend.Variable) (ans frontend.Variable) {
    inv2 := api.Inverse(2)
    b0 := typeConverters.LittleEndian(api, evaluations[0])
    b1 := api.Mul(api.Add(api.Neg(typeConverters.LittleEndian(api, evaluations[2])), api.Mul(4, typeConverters.LittleEndian(api, evaluations[1])), api.Mul(-3, typeConverters.LittleEndian(api, evaluations[0]))), inv2)
    b2 := api.Mul(api.Add(typeConverters.LittleEndian(api, evaluations[2]),api.Mul(-2, typeConverters.LittleEndian(api, evaluations[1])), typeConverters.LittleEndian(api, evaluations[0])), inv2)
    return api.Add(api.Mul(point, point, b2), api.Mul(point, b1), b0)
}

func (circuit *Circuit) Define(api frontend.API) error {
    mainSponge := initializeSpongeWithIOPatternAndMerkleRoot(circuit, api)
    checkFirstSumcheckOfFirstRound(mainSponge, circuit, api)
    mainSponge.Write(circuit.InitialPolyEvals[0])
    mainSponge.Write(circuit.InitialPolyEvals[1])
    mainSponge.Write(circuit.InitialPolyEvals[2])
    foldingRandomness := typeConverters.BigEndian(api, mainSponge.Sum(47))
    // api.AssertIsEqual(foldingRandomness, 0)
    randEval := evaluateFunction(api, circuit.InitialPolyEvals, foldingRandomness)
    sumOverBools := api.Add(
        typeConverters.LittleEndian(api, circuit.SecondPolyEvals[0]), 
        typeConverters.LittleEndian(api, circuit.SecondPolyEvals[1]),
    )
    api.AssertIsEqual(randEval, sumOverBools)
    return nil
}


func main() {
    // iopattern := typeConverters.ByteArrToVarArr([]uint8{240, 159, 140, 170, 239, 184, 143, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 52, 55, 105, 110, 105, 116, 105, 97, 108, 95, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 51, 50, 115, 116, 105, 114, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100, 0, 83, 52, 55, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 102, 105, 110, 97, 108, 95, 99, 111, 101, 102, 102, 115, 0, 83, 51, 50, 102, 105, 110, 97, 108, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100})
    // merkleRoot := typeConverters.ByteArrToVarArr([]uint8{117, 219, 183, 48, 66, 2, 168, 33, 165, 72, 106, 246, 82, 158, 98, 42, 29, 150, 218, 108, 53, 43, 49, 242, 151, 3, 90, 123, 210, 62, 179, 114})
    // ood_answer := typeConverters.ByteArrToVarArr([]uint8{232, 157, 134, 234, 158, 134, 91, 70, 113, 77, 8, 124, 33, 234, 255, 131, 168, 158, 236, 153, 242, 231, 64, 95, 146, 251, 84, 154, 27, 157, 181, 37})

    // evaluation, _ := new(big.Int).SetString("6", 10)
    // evaluation1 := typeConverters.ByteArrToVarArr([]uint8{22, 105, 183, 149, 56, 20, 140, 234, 240, 34, 233, 231, 169, 7, 114, 141, 86, 55, 88, 95, 1, 119, 158, 11, 108, 193, 18, 223, 22, 176, 165, 16})
    // evaluation2 := typeConverters.ByteArrToVarArr([]uint8{168, 184, 232, 187, 4, 247, 162, 177, 253, 99, 27, 11, 241, 44, 192, 153, 60, 77, 148, 95, 179, 208, 207, 99, 10, 7, 90, 77, 42, 117, 167, 21})
    // evaluation3 := typeConverters.ByteArrToVarArr([]uint8{205, 99, 138, 194, 177, 16, 232, 189, 108, 188, 241, 241, 247, 72, 100, 236, 143, 73, 82, 83, 98, 125, 100, 220, 227, 214, 96, 232, 35, 21, 120, 29})
    
    iopattern := typeConverters.ByteArrToVarArr([]uint8{240, 159, 140, 170, 239, 184, 143, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 52, 55, 105, 110, 105, 116, 105, 97, 108, 95, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 109, 101, 114, 107, 108, 101, 95, 100, 105, 103, 101, 115, 116, 0, 83, 52, 55, 111, 111, 100, 95, 113, 117, 101, 114, 121, 0, 65, 51, 50, 111, 111, 100, 95, 97, 110, 115, 0, 83, 51, 50, 115, 116, 105, 114, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100, 0, 83, 51, 50, 112, 111, 119, 95, 113, 117, 101, 114, 105, 101, 115, 0, 65, 56, 112, 111, 119, 45, 110, 111, 110, 99, 101, 0, 83, 52, 55, 99, 111, 109, 98, 105, 110, 97, 116, 105, 111, 110, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 57, 54, 115, 117, 109, 99, 104, 101, 99, 107, 95, 112, 111, 108, 121, 0, 83, 52, 55, 102, 111, 108, 100, 105, 110, 103, 95, 114, 97, 110, 100, 111, 109, 110, 101, 115, 115, 0, 65, 51, 50, 102, 105, 110, 97, 108, 95, 99, 111, 101, 102, 102, 115, 0, 83, 51, 50, 102, 105, 110, 97, 108, 95, 113, 117, 101, 114, 105, 101, 115, 95, 115, 101, 101, 100, 0, 83, 51, 50, 112, 111, 119, 95, 113, 117, 101, 114, 105, 101, 115, 0, 65, 56, 112, 111, 119, 45, 110, 111, 110, 99, 101})
    merkleRoot := typeConverters.ByteArrToVarArr([]uint8{91, 191, 10, 79, 160, 14, 48, 231, 9, 136, 174, 237, 91, 33, 107, 115, 61, 110, 60, 253, 34, 13, 138, 139, 134, 177, 20, 13, 47, 236, 192, 235})
    ood_answer := typeConverters.ByteArrToVarArr([]uint8{4, 27, 46, 84, 196, 191, 23, 182, 251, 220, 156, 128, 85, 238, 179, 56, 241, 254, 128, 107, 179, 72, 236, 44, 74, 87, 108, 154, 134, 218, 53, 46})

    evaluation, _ := new(big.Int).SetString("120", 10)
    evaluation1 := typeConverters.ByteArrToVarArr([]uint8{234, 189, 202, 54, 254, 88, 189, 252, 248, 56, 103, 9, 240, 34, 51, 53, 126, 240, 161, 15, 102, 232, 227, 162, 20, 171, 67, 203, 28, 187, 7, 35})
    evaluation2 := typeConverters.ByteArrToVarArr([]uint8{122, 188, 153, 3, 135, 248, 158, 26, 251, 56, 179, 32, 27, 103, 127, 18, 95, 129, 84, 119, 107, 228, 43, 122, 196, 145, 177, 118, 228, 95, 204, 16})
    evaluation3 := typeConverters.ByteArrToVarArr([]uint8{56, 72, 87, 174, 9, 109, 239, 51, 172, 233, 60, 234, 229, 97, 191, 86, 153, 135, 143, 195, 24, 128, 27, 138, 31, 222, 138, 101, 13, 168, 180, 24})

    evaluation2_1 := typeConverters.ByteArrToVarArr([]uint8{231, 75, 148, 173, 131, 39, 90, 195, 50, 11, 215, 81, 40, 61, 106, 172, 193, 66, 163, 254, 180, 87, 208, 152, 226, 131, 238, 244, 156, 197, 182, 19})
    evaluation2_2 := typeConverters.ByteArrToVarArr([]uint8{64, 116, 125, 243, 22, 29, 240, 25, 207, 88, 133, 217, 154, 237, 11, 147, 97, 57, 19, 224, 98, 90, 212, 49, 72, 25, 155, 136, 17, 34, 83, 24})
    evaluation2_3 := typeConverters.ByteArrToVarArr([]uint8{126, 12, 163, 53, 95, 139, 201, 187, 180, 185, 12, 238, 250, 117, 239, 47, 202, 167, 3, 220, 87, 21, 182, 39, 144, 147, 76, 242, 46, 225, 0, 47})

    var circuit = Circuit{
        IOPattern: make([]frontend.Variable, len(iopattern)),
        MerkleRoot: make([]frontend.Variable, len(merkleRoot)),
        OOD_Answer: make([]frontend.Variable, len(ood_answer)),
		InitialPolyEvals: [][]frontend.Variable{
            make([]frontend.Variable, 32),
            make([]frontend.Variable, 32),
            make([]frontend.Variable, 32),
        },
        SecondPolyEvals: [][]frontend.Variable{
            make([]frontend.Variable, 32),
            make([]frontend.Variable, 32),
            make([]frontend.Variable, 32),
        },
    }

    ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
    pk, vk, _ := groth16.Setup(ccs)
    
    assignment := Circuit{
        IOPattern: iopattern,
        MerkleRoot: merkleRoot,
        OOD_Answer: ood_answer,
        Evaluation: evaluation, 
		InitialPolyEvals: [][]frontend.Variable{evaluation1, evaluation2, evaluation3},
        SecondPolyEvals: [][]frontend.Variable{evaluation2_1, evaluation2_2, evaluation2_3},
    }

    witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
    publicWitness, _ := witness.Public()
    proof, _ := groth16.Prove(ccs, pk, witness)
    groth16.Verify(proof, vk, publicWitness)
}


