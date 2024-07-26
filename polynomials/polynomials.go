package polynomials

import(
	"github.com/consensys/gnark/frontend"
)

func UniP (coefs []frontend.Variable, x frontend.Variable, api frontend.API) frontend.Variable {
	var result frontend.Variable = coefs[len(coefs)-1]
	for i:=1; i < len(coefs); i++ {
		result = api.Mul(result, x)
		result = api.Add(result, coefs[len(coefs)-1-i])
	}
	return result
}

func MultP (coefs []frontend.Variable, vars []frontend.Variable, api frontend.API) frontend.Variable {
	if (len(vars) == 0) { return coefs[0] }
	deg_zero := MultP(coefs[:len(coefs)/2], vars[:len(vars)-1], api)
	deg_one := api.Mul(vars[len(vars)-1], MultP(coefs[len(coefs)/2:], vars[:len(vars)-1], api))
	return api.Add(deg_zero, deg_one)
}