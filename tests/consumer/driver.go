/*
	Verifying Drands BLS12-381 Signatures in GoLang

	Using the following randomness payloads:
	{
		"round": 1657526,
		"randomness": "58b26a65bf4032555748c2949311abb2c4f580e7d7d7f70b13d0533b793c4c7d",
		"signature": "8434e45af135f363b04b792c1d77b83e36ef66829b0a09f7eed058103429f0e7f759ebf6d001cf73e9138f5b7a7f04b602c4167390c323432562d6367e09169422707a9778eba260c4d6434ea5e1d2c81462a4e3cd430990aebc593f4ae7517c",
		"previous_signature": "ab9e594732265dd737b536a144fb955bfeabe929116fc78f7bb740de3f43629691cabcec507eeb39a98d51be11942cf4062b0a38dd1be18be5e23bea7efd3935bb23032dba4da0374899e583feb937119f33f6b645048e0e91cde0de00e3e9ee"
	},
	{
		"round": 1657527,
		"randomness": "f62110e3f46d3f89be0dfa38b740fb8653f7106251cd0c360021d2d7d60b3ceb",
		"signature": "83480a950bd42bc20cc0f34dfa80901322ca99c0cf0cb105bd87a64bc134a607eb53d0a21e7e687ca7315ad0c15124a31863c20d6a41b0bb4f0dcfe5c348797c042807964069e279026306f989ff67523052ddba82c0862800f002dc5de40772",
		"previous_signature": "8434e45af135f363b04b792c1d77b83e36ef66829b0a09f7eed058103429f0e7f759ebf6d001cf73e9138f5b7a7f04b602c4167390c323432562d6367e09169422707a9778eba260c4d6434ea5e1d2c81462a4e3cd430990aebc593f4ae7517c"
	}

	The chain info:
	{
		"public_key": "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31",
		"period": 30,
		"genesis_time": 1595431050,
		"hash": "8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce",
		"groupHash": "176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a"
	}
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	bls "github.com/kilic/bls12-381"
)

func main() {

	var payload = Payload{
		prevSig:    fromHex(96, "8434e45af135f363b04b792c1d77b83e36ef66829b0a09f7eed058103429f0e7f759ebf6d001cf73e9138f5b7a7f04b602c4167390c323432562d6367e09169422707a9778eba260c4d6434ea5e1d2c81462a4e3cd430990aebc593f4ae7517c"),
		currSig:    fromHex(96, "83480a950bd42bc20cc0f34dfa80901322ca99c0cf0cb105bd87a64bc134a607eb53d0a21e7e687ca7315ad0c15124a31863c20d6a41b0bb4f0dcfe5c348797c042807964069e279026306f989ff67523052ddba82c0862800f002dc5de40772"),
		randomness: fromHex(32, "f62110e3f46d3f89be0dfa38b740fb8653f7106251cd0c360021d2d7d60b3ceb"),
		publicKey:  fromHex(48, "868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31"),
		currRound:  1657527,
	}

	//check byte array was consumed correctly
	//var num = hex.EncodeToString(in)
	//	fmt.Println(num)

	var engine = bls.NewEngine()

	var G1 = bls.G1One
	var SIG, err_sig = bls.NewG2().FromCompressed(payload.prevSig)

	if err_sig != nil {
		println("error")
		println(err_sig.Error())
	}

	var pairOne = engine.AddPair(&G1, SIG).Result()

	var pub, err_pub = bls.NewG1().FromCompressed(payload.publicKey)

	if err_pub != nil {
		println("error")
		println(err_pub.Error())
	}

	var g = bls.NewG2()
	msg_hashed := Message(payload.currRound, payload.prevSig)
	domain := []byte("BLS12381G2_XMD:SHA-256_SSWU_NU_TESTGEN")
	msg_on_curve, err_msg := g.EncodeToCurve(msg_hashed, domain)

	if err_msg != nil {
		println("error")
		println(err_msg.Error())
	}

	var pairTwo = engine.AddPair(pub, msg_on_curve).Result()

	GT := engine.GT()

	if !GT.IsValid(pairOne) {
		println("pairing One result is not valid, please check G1 and SIG")
	}

	if !GT.IsValid(pairTwo) {
		println("pairing One result is not valid, please check Public key and msg")
	}

	var equalPairs = pairOne.Equal(pairTwo)

	print("The two pairs are ")
	println(equalPairs)

}

type Payload struct {
	prevSig    []byte
	currSig    []byte
	randomness []byte
	publicKey  []byte
	currRound  uint64
}

func fromHex(size int, hexStrs ...string) []byte {
	var out []byte
	if size > 0 {
		out = make([]byte, size*len(hexStrs))
	}
	for i := 0; i < len(hexStrs); i++ {
		hexStr := hexStrs[i]
		if hexStr[:2] == "0x" {
			hexStr = hexStr[2:]
		}
		if len(hexStr)%2 == 1 {
			hexStr = "0" + hexStr
		}
		bytes, err := hex.DecodeString(hexStr)
		if err != nil {
			panic(err)
		}
		if size <= 0 {
			out = append(out, bytes...)
		} else {
			if len(bytes) > size {
				panic(fmt.Sprintf("bad input string\ninput: %x\nsize: %d\nlenght: %d\n", bytes, size, len(bytes)))
			}
			offset := i*size + (size - len(bytes))
			copy(out[offset:], bytes)
		}
	}
	return out
}

func Message(currRound uint64, prevSig []byte) []byte {
	h := sha256.New()
	_, _ = h.Write(prevSig)
	_, _ = h.Write(RoundToBytes(currRound))
	return h.Sum(nil)
}

func RoundToBytes(r uint64) []byte {
	var buff bytes.Buffer
	_ = binary.Write(&buff, binary.BigEndian, r)
	return buff.Bytes()
}
