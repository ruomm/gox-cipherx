/**
 * @copyright www.ruomm.com
 * @author 牛牛-wanruome@126.com
 * @create 2024/6/20 09:50
 * @version 1.0
 */
package cipherx

import (
	"crypto/rand"
	"github.com/tjfoc/gmsm/x509"

	"github.com/tjfoc/gmsm/sm2"
)

type XGuomi struct {
	ModePadding     MODE_PADDING
	SizeOfKey       int
	SizeAuto        bool
	PublicKey       *sm2.PublicKey
	PrivateKey      *sm2.PrivateKey
	PaddingHelper   func(data []byte, blockSize int) []byte
	UnPaddingHelper func(data []byte, blockSize int) []byte
}

// key模式
//func (x *XGuomi) ModeOfKey() MODE_KEY {
//	return ParseKeyMode(x.ModeKey)
//}

// 生成秘钥对
func (x *XGuomi) GenrateKeyPair() error {
	priKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	x.PrivateKey = priKey
	x.PublicKey = &priKey.PublicKey
	return nil
}

// 获取SM2秘钥对
func (x *XGuomi) KeyPair() (*sm2.PrivateKey, *sm2.PublicKey) {
	return x.PrivateKey, x.PublicKey
}

// 设置秘钥长度
func (x *XGuomi) SetSizeOfKey(sizeOfKey int) {
	if sizeOfKey%8 == 0 {
		x.SizeOfKey = sizeOfKey
	}
}

// 获取秘钥长度
func (x *XGuomi) GetSizeOfKey() int {
	if x.SizeOfKey > 0 && x.SizeOfKey%8 == 0 {
		return x.SizeOfKey
	} else {
		return 2048
	}
}

// 公钥长度
func (x *XGuomi) SizeOfPublicKey() int {
	if x.SizeOfKey > 0 && x.SizeOfKey%8 == 0 {
		return x.SizeOfKey
	} else {
		return 2048
	}
}

// 秘钥长度
func (x *XGuomi) SizeOfPrivateKey() int {
	if x.SizeOfKey > 0 && x.SizeOfKey%8 == 0 {
		return x.SizeOfKey
	} else {
		return 2048
	}
}

// 字节转字符串编码方案
//func (x *XGuomi) ModeOfEncode() MODE_ENCODE {
//	return ParseEncodeMode(x.ModeEncode)
//}

// Padding的模式
func (x *XGuomi) ModeOfPadding() MODE_PADDING {
	return ParsePaddingMode(x.ModePadding)
}

// 设置公钥
func (x *XGuomi) SetPubicKey(pubKey []byte) error {
	parsePub, err := x509.ParseSm2PublicKey(pubKey)
	if err != nil {
		return err
	}
	x.PublicKey = parsePub
	return nil
}

// 设置私钥
func (x *XGuomi) SetPrivateKey(priKey []byte) error {
	parsePri, err := x509.ParseSm2PrivateKey(priKey)
	if err != nil {
		return err
	}
	x.PrivateKey = parsePri
	return nil
}

// 加载公钥
func (x *XGuomi) LoadPulicKey(modeOfKey MODE_KEY, pubKeyStr string) error {
	keyByte, err := Sm2KeyStringToByte(ParseKeyMode(modeOfKey), pubKeyStr)
	if err != nil {
		return err
	}
	parsePub, err := x509.ParseSm2PublicKey(keyByte)
	if err != nil {
		return err
	}
	x.PublicKey = parsePub
	return nil
}

// 加载私钥
func (x *XGuomi) LoadPrivateKey(modeOfKey MODE_KEY, priKeyStr string, pwd []byte) error {
	keyByte, err := Sm2KeyStringToByte(ParseKeyMode(modeOfKey), priKeyStr)
	if err != nil {
		return err
	}
	parsePri, err := x509.ParsePKCS8PrivateKey(keyByte, pwd)
	if err != nil {
		return err
	}
	x.PrivateKey = parsePri
	return nil
}

// 格式化公钥
func (x *XGuomi) FormatPublicKey(modeOfKey MODE_KEY) (string, error) {
	keyData, err := x509.MarshalSm2PublicKey(x.PublicKey)
	if err != nil {
		return "", err
	}
	return Sm2KeyByteToString(ParseKeyMode(modeOfKey), keyData, true)
}

// 格式化私钥
func (x *XGuomi) FormatPrivateKey(modeOfKey MODE_KEY, pwd []byte) (string, error) {
	keyData, err := x509.MarshalSm2PrivateKey(x.PrivateKey, pwd)
	if err != nil {
		return "", err
	}
	return Sm2KeyByteToString(ParseKeyMode(modeOfKey), keyData, false)
}
