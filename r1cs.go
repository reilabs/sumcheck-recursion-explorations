package main

import (
	"fmt"
)

func VerifyR1CS() {
	const numConstraints = 6
	const numVariables = 8

	//row-major order
	a := []int{
		0, 1, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 0, 0, 0,
		0, 1, 0, 1, 0, 0, 0, 0,
		-5, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 1, 0,
		0, 0, 0, 0, 0, 1, 0, 0,
	}

	b := []int{
		0, 1, 0, 0, 0, 0, 0, 0,
		0, 1, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 1, 0,
		1, 0, 0, 0, 0, 0, 0, 0,
	}

	c := []int{
		0, 0, 1, 0, 0, 0, 0, 0,
		0, 0, 0, 1, 0, 0, 0, 0,
		0, 0, 0, 0, 1, 0, 0, 0,
		0, 0, 0, 0, 0, 1, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1,
		0, 0, 0, 0, 0, 0, 0, 1,
	}

	// Witness
	z := []int{
		1,
		3,
		9,
		27,
		30,
		25,
		5,
		25,
	}

	valid := true
	for i := 0; i < numConstraints; i++ {

		Aiz := 0
		Biz := 0
		Ciz := 0

		for j := 0; j < numVariables; j++ {
			index := i*numVariables + j
			Aiz += a[index] * z[j]
			Biz += b[index] * z[j]
			Ciz += c[index] * z[j]
		}

		if Aiz*Biz != Ciz {
			valid = false
			fmt.Printf("Constraint %d failed: (A_i z) * (B_i z) != C_i z\n", i+1)
			fmt.Printf("A_i z = %d, B_i z = %d, C_i z = %d\n", Aiz, Biz, Ciz)
		} else {
			fmt.Printf("Constraint %d passed: (A_i z) * (B_i z) = C_i z\n", i+1)
			fmt.Printf("A_i z = %d, B_i z = %d, C_i z = %d\n", Aiz, Biz, Ciz)
		}
	}

	if valid {
		fmt.Println("All constraints are satisfied.")
	} else {
		fmt.Println("Some constraints are not satisfied.")
	}
}
