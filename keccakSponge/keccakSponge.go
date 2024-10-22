package keccakSponge

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/permutation/keccakf"
)

type digest struct {
	api 	frontend.API
	uapi      *uints.BinaryField[uints.U64]
	state     [25]uints.U64
	absorb_pos int
    squeeze_pos int
}

func NewKeccak(api frontend.API) (*digest, error) {
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, err
	}
	return &digest{
		api: 	  api,
		uapi:      uapi,
		state:     newState(),
		absorb_pos: 0,
        squeeze_pos: 136,
	}, nil
}

func NewKeccakWithTag(api frontend.API, tag []uints.U8) (*digest, error) {
	d, _ := NewKeccak(api)
	for i := 136; i < 136 + len(tag); i++ {
		d.state[i/8][i%8] = tag[i-136]
	}

	return d, nil
}

func (d *digest) Write(in []uints.U8) {
	for _, inputByte := range in {
		if d.absorb_pos == 136 {
			d.state = keccakf.Permute(d.uapi, d.state)
			d.absorb_pos = 0
		} 
		d.state[d.absorb_pos/8][d.absorb_pos%8] = inputByte
		d.absorb_pos++
	}
	d.squeeze_pos = 136
}

func (d *digest) Sum(len int) (result []uints.U8) {
	for i := 0; i < len; i++ {
		if d.squeeze_pos == 136 {
			d.squeeze_pos = 0
			d.absorb_pos = 0
			d.state = keccakf.Permute(d.uapi, d.state)
		}
		result = append(result, d.state[d.squeeze_pos/8][d.squeeze_pos%8])
		d.squeeze_pos++
	}
	return result
}

func newState() (state [25]uints.U64) {
	for i := range state {
		state[i] = uints.NewU64(0)
	}
	return
}