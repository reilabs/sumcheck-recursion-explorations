package typeConverters

import (
	"github.com/consensys/gnark/frontend"
)

func BigEndian(api frontend.API, varArr []frontend.Variable) frontend.Variable {
    frontendVar := frontend.Variable(0)
    for i := range varArr {
		frontendVar = api.Add(api.Mul(256, frontendVar), varArr[i])
	}
    return frontendVar
}

func LittleEndian(api frontend.API, varArr []frontend.Variable) frontend.Variable {
	frontendVar := frontend.Variable(0)
    for i := range varArr {
		frontendVar = api.Add(api.Mul(256, frontendVar), varArr[len(varArr) - 1 - i])
    }
    return frontendVar
}

func ByteArrToVarArr(uint8Arr []uint8) []frontend.Variable {
    frontendArr := make([]frontend.Variable, len(uint8Arr))
    for i := range frontendArr {
        frontendArr[i] = frontend.Variable(uint8Arr[i])
    }
    return frontendArr
}