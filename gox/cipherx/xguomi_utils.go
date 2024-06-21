/**
 * @copyright www.ruomm.com
 * @author 牛牛-wanruome@126.com
 * @create 2024/6/20 09:50
 * @version 1.0
 */
package cipherx

import (
	"crypto/rand"
	"errors"
	"github.com/tjfoc/gmsm/x509"

	"github.com/tjfoc/gmsm/sm2"
)

type SM2_MODE int

const (
	SM2_C1C3C2 SM2_MODE = 0
	SM2_C1C2C3 SM2_MODE = 1
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

// 使用公钥进行SM2加密-字节模式
func (x *XGuomi) Encrypt(origMsg []byte, c1c2c3Mode bool) ([]byte, error) {
	if nil == x.PublicKey {
		return nil, errors.New("XGuomi.PublicKey is nil")
	}
	if nil == origMsg || len(origMsg) <= 0 {
		return nil, errors.New("origMsg is nil or empty")
	}
	sm2_mode := parseSm2Mode(c1c2c3Mode)
	return sm2.Encrypt(x.PublicKey, origMsg, rand.Reader, sm2_mode)
}

// 使用私钥进行SM2解密-字节模式
func (x *XGuomi) Decrypt(encMsg []byte, c1c2c3Mode bool) ([]byte, error) {
	if nil == x.PrivateKey {
		return nil, errors.New("XGuomi.PrivateKey is nil")
	}
	if nil == encMsg || len(encMsg) <= 0 {
		return nil, errors.New("encMsg is nil or empty")
	}
	sm2_mode := parseSm2Mode(c1c2c3Mode)
	return sm2.Decrypt(x.PrivateKey, encMsg, sm2_mode)
}

// 使用公钥进行SM2加密-字节模式
func (x *XGuomi) EncryptAsn1(origMsg []byte) ([]byte, error) {
	if nil == x.PublicKey {
		return nil, errors.New("XGuomi.PublicKey is nil")
	}
	if nil == origMsg || len(origMsg) <= 0 {
		return nil, errors.New("origMsg is nil or empty")
	}
	return sm2.EncryptAsn1(x.PublicKey, origMsg, rand.Reader)
}

// 使用私钥进行SM2解密-字节模式
func (x *XGuomi) DecryptAsn1(encMsg []byte) ([]byte, error) {
	if nil == x.PrivateKey {
		return nil, errors.New("XGuomi.PrivateKey is nil")
	}
	if nil == encMsg || len(encMsg) <= 0 {
		return nil, errors.New("encMsg is nil or empty")
	}
	return sm2.DecryptAsn1(x.PrivateKey, encMsg)
}

// 使用公钥进行SM2加密-字符串模式
func (x *XGuomi) EncryptString(encodeMode MODE_ENCODE, origStr string, c1c2c3Mode bool) (string, error) {
	encMsg, err := x.Encrypt([]byte(origStr), c1c2c3Mode)
	if nil != err {
		return "", err
	}
	return EncodingToString(encodeMode, encMsg)
}

// 使用私钥进行SM2解密-字符串模式
func (x *XGuomi) DecryptString(encodeMode MODE_ENCODE, encStr string, c1c2c3Mode bool) (string, error) {
	encMsg, err := DecodingToByte(encodeMode, encStr)
	if nil != err {
		return "", err
	}
	decMsg, err := x.Decrypt(encMsg, c1c2c3Mode)
	if nil != err {
		return "", err
	}
	return string(decMsg), nil
}

// 使用公钥进行SM2加密-字符串模式
func (x *XGuomi) EncryptAsn1String(encodeMode MODE_ENCODE, origStr string) (string, error) {
	encMsg, err := x.EncryptAsn1([]byte(origStr))
	if nil != err {
		return "", err
	}
	return EncodingToString(encodeMode, encMsg)
}

// 使用私钥进行SM2解密-字符串模式
func (x *XGuomi) DecryptAsn1String(encodeMode MODE_ENCODE, encStr string) (string, error) {
	encMsg, err := DecodingToByte(encodeMode, encStr)
	if nil != err {
		return "", err
	}
	decMsg, err := x.DecryptAsn1(encMsg)
	if nil != err {
		return "", err
	}
	return string(decMsg), nil
}

func parseSm2Mode(c1c2c3Mode bool) int {
	if c1c2c3Mode {
		return sm2.C1C2C3
	} else {
		return sm2.C1C3C2
	}
}
