package main

import (
	"math/big"
	"tutorial/sumcheck-verifier-circuit/hashmanager"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
)

type VerifyMerkleProofCircuit struct {
	// Inputs
	Leaves                []frontend.Variable
	LeafIndexes           []frontend.Variable
	LeafSiblingHashes     []frontend.Variable
	AuthPathPrefixLenghts []frontend.Variable
	AuthPathSuffixes      [][]frontend.Variable //in Incremental Encoding
	// Public Input
	RootHash frontend.Variable `gnark:",public"`
}

func DecodePrefixPath(api frontend.API, circuitPrevPath []frontend.Variable, circuitPrefixLen frontend.Variable, circuitSuffix []frontend.Variable) []frontend.Variable {
	const maxPrevPathLen = 20
	const maxSuffixLen = 20
	comparator := cmp.NewBoundedComparator(api, big.NewInt(1<<32-1), false)

	const resultLen = maxPrevPathLen + maxSuffixLen

	prevPath := make([]frontend.Variable, maxPrevPathLen)
	suffix := make([]frontend.Variable, maxSuffixLen)
	result := make([]frontend.Variable, resultLen)

	for i := 0; i < maxPrevPathLen; i++ {
		prevPath[i] = circuitPrevPath[i]
	}
	for i := 0; i < maxSuffixLen; i++ {
		suffix[i] = circuitSuffix[i]
	}

	for i := 0; i < resultLen; i++ {
		iVar, _ := api.ConstantValue(uint64(i))

		isLessThanPrefixLen := comparator.IsLess(iVar, circuitPrefixLen)
		indexInSuffix := api.Sub(iVar, circuitPrefixLen)
		isInSuffixRange := comparator.IsLess(indexInSuffix, maxSuffixLen)

		prevPathElement := api.Select(isLessThanPrefixLen, prevPath[i], frontend.Variable(0))
		suffixElement := api.Select(isInSuffixRange, suffix[indexInSuffix], frontend.Variable(0))

		result[i] = api.Add(prevPathElement, suffixElement)
	}

	return result
}

func (circuit *VerifyMerkleProofCircuit) Define(api frontend.API) error {
	const N = 100

	var manager = hashmanager.NewHashManager(api)
	numLeaves := len(circuit.Leaves)
	// ``treeHeight := len(circuit.AuthPathSuffixes[0]) + 2

	prevPath := circuit.AuthPathSuffixes[0]
	for i := 0; i < numLeaves; i++ {
		leaf := circuit.Leaves[i]
		leafIndex := circuit.LeafIndexes[i]
		leafSiblingHash := circuit.LeafSiblingHashes[i]

		// DecodePrefixPath(api)
		authPath := prevPath
		if circuit.AuthPathPrefixLenghts[i] == 0 {
			authPath = circuit.AuthPathSuffixes[i]
		} else {

		}

		claimedLeafHash := manager.WriteInputAndCollectAndReturnHash(leaf)

		dir := api.And(leafIndex, 1)
		leftChild := api.Select(dir, leafSiblingHash, claimedLeafHash)
		rightChild := api.Select(dir, claimedLeafHash, leafSiblingHash)

		currentHash := manager.WriteInputAndCollectAndReturnHash(leftChild, rightChild)

		index := api.Div(leafIndex, 2)

		for level := 0; level < len(authPath); level++ {
			siblingHash := authPath[level]

			dir := api.And(index, 1)
			left := api.Select(dir, siblingHash, currentHash)
			right := api.Select(dir, currentHash, siblingHash)

			currentHash = manager.WriteInputAndCollectAndReturnHash(left, right)

			index = api.Div(index, 2)
		}

		api.AssertIsEqual(currentHash, circuit.RootHash)
	}

	return nil
}
