/**
 * @copyright www.ruomm.com
 * @author 牛牛-wanruome@126.com
 * @create 2024/6/20 09:50
 * @version 1.0
 */
package cipherx

import (
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"github.com/tjfoc/gmsm/x509"
	"math/big"

	"github.com/tjfoc/gmsm/sm2"
)

type SM2_MODE int

type sm2Signature struct {
	R, S *big.Int
}

type XSm2 struct {
	ModePadding     MODE_PADDING
	SizeOfKey       int
	SizeAuto        bool
	PublicKey       *sm2.PublicKey
	PrivateKey      *sm2.PrivateKey
	PaddingHelper   func(data []byte, blockSize int) []byte
	UnPaddingHelper func(data []byte, blockSize int) []byte
}

// key模式
//func (x *XSm2) ModeOfKey() MODE_KEY {
//	return ParseKeyMode(x.ModeKey)
//}

// 生成秘钥对
func (x *XSm2) GenrateKeyPair() error {
	priKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	x.PrivateKey = priKey
	x.PublicKey = &priKey.PublicKey
	return nil
}

// 获取SM2秘钥对
func (x *XSm2) KeyPair() (*sm2.PrivateKey, *sm2.PublicKey) {
	return x.PrivateKey, x.PublicKey
}

// 设置秘钥长度
func (x *XSm2) SetSizeOfKey(sizeOfKey int) {
	if sizeOfKey%8 == 0 {
		x.SizeOfKey = sizeOfKey
	}
}

// 获取秘钥长度
func (x *XSm2) GetSizeOfKey() int {
	if x.SizeOfKey > 0 && x.SizeOfKey%8 == 0 {
		return x.SizeOfKey
	} else {
		return 2048
	}
}

// 公钥长度
func (x *XSm2) SizeOfPublicKey() int {
	if x.SizeOfKey > 0 && x.SizeOfKey%8 == 0 {
		return x.SizeOfKey
	} else {
		return 2048
	}
}

// 秘钥长度
func (x *XSm2) SizeOfPrivateKey() int {
	if x.SizeOfKey > 0 && x.SizeOfKey%8 == 0 {
		return x.SizeOfKey
	} else {
		return 2048
	}
}

// 字节转字符串编码方案
//func (x *XSm2) ModeOfEncode() MODE_ENCODE {
//	return ParseEncodeMode(x.ModeEncode)
//}

// Padding的模式
func (x *XSm2) ModeOfPadding() MODE_PADDING {
	return ParsePaddingMode(x.ModePadding)
}

// 设置公钥
func (x *XSm2) SetPubicKey(pubKey []byte) error {
	parsePub, err := x509.ParseSm2PublicKey(pubKey)
	if err != nil {
		return err
	}
	x.PublicKey = parsePub
	return nil
}

// 设置私钥
func (x *XSm2) SetPrivateKey(priKey []byte) error {
	parsePri, err := x509.ParseSm2PrivateKey(priKey)
	if err != nil {
		return err
	}
	x.PrivateKey = parsePri
	return nil
}

// 加载公钥
func (x *XSm2) LoadPulicKey(modeOfKey MODE_KEY, pubKeyStr string) error {
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
func (x *XSm2) LoadPrivateKey(modeOfKey MODE_KEY, priKeyStr string, pwd []byte) error {
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
func (x *XSm2) FormatPublicKey(modeOfKey MODE_KEY) (string, error) {
	keyData, err := x509.MarshalSm2PublicKey(x.PublicKey)
	if err != nil {
		return "", err
	}
	return Sm2KeyByteToString(ParseKeyMode(modeOfKey), keyData, true)
}

// 格式化私钥
func (x *XSm2) FormatPrivateKey(modeOfKey MODE_KEY, pwd []byte) (string, error) {
	keyData, err := x509.MarshalSm2PrivateKey(x.PrivateKey, pwd)
	if err != nil {
		return "", err
	}
	return Sm2KeyByteToString(ParseKeyMode(modeOfKey), keyData, false)
}

// 使用公钥进行SM2加密-字节模式
func (x *XSm2) Encrypt(origMsg []byte, c1c2c3Mode bool) ([]byte, error) {
	if nil == x.PublicKey {
		return nil, errors.New("XSm2.PublicKey is nil")
	}
	if nil == origMsg || len(origMsg) <= 0 {
		return nil, errors.New("origMsg is nil or empty")
	}
	sm2_mode := parseSm2Mode(c1c2c3Mode)
	return sm2.Encrypt(x.PublicKey, origMsg, rand.Reader, sm2_mode)
}

// 使用私钥进行SM2解密-字节模式
func (x *XSm2) Decrypt(encMsg []byte, c1c2c3Mode bool) ([]byte, error) {
	if nil == x.PrivateKey {
		return nil, errors.New("XSm2.PrivateKey is nil")
	}
	if nil == encMsg || len(encMsg) <= 0 {
		return nil, errors.New("encMsg is nil or empty")
	}
	sm2_mode := parseSm2Mode(c1c2c3Mode)
	return sm2.Decrypt(x.PrivateKey, encMsg, sm2_mode)
}

// 使用公钥进行SM2加密-字节模式
func (x *XSm2) EncryptAsn1(origMsg []byte) ([]byte, error) {
	if nil == x.PublicKey {
		return nil, errors.New("XSm2.PublicKey is nil")
	}
	if nil == origMsg || len(origMsg) <= 0 {
		return nil, errors.New("origMsg is nil or empty")
	}
	return sm2.EncryptAsn1(x.PublicKey, origMsg, rand.Reader)
}

// 使用私钥进行SM2解密-字节模式
func (x *XSm2) DecryptAsn1(encMsg []byte) ([]byte, error) {
	if nil == x.PrivateKey {
		return nil, errors.New("XSm2.PrivateKey is nil")
	}
	if nil == encMsg || len(encMsg) <= 0 {
		return nil, errors.New("encMsg is nil or empty")
	}
	return sm2.DecryptAsn1(x.PrivateKey, encMsg)
}

// 使用公钥进行SM2加密-字符串模式
func (x *XSm2) EncryptString(encodeMode MODE_ENCODE, origStr string, c1c2c3Mode bool) (string, error) {
	encMsg, err := x.Encrypt([]byte(origStr), c1c2c3Mode)
	if nil != err {
		return "", err
	}
	return EncodingToString(encodeMode, encMsg)
}

// 使用私钥进行SM2解密-字符串模式
func (x *XSm2) DecryptString(encodeMode MODE_ENCODE, encStr string, c1c2c3Mode bool) (string, error) {
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
func (x *XSm2) EncryptAsn1String(encodeMode MODE_ENCODE, origStr string) (string, error) {
	encMsg, err := x.EncryptAsn1([]byte(origStr))
	if nil != err {
		return "", err
	}
	return EncodingToString(encodeMode, encMsg)
}

// 使用私钥进行SM2解密-字符串模式
func (x *XSm2) DecryptAsn1String(encodeMode MODE_ENCODE, encStr string) (string, error) {
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

// 使用私钥进行签名-字节数组模式
func (x *XSm2) Sm2Sign(origMsg []byte, uid []byte) ([]byte, error) {
	if nil == x.PrivateKey {
		return nil, errors.New("XSm2.PrivateKey is nil")
	}
	if nil == origMsg || len(origMsg) <= 0 {
		return nil, errors.New("origMsg is nil or empty")
	}
	r, s, err := sm2.Sm2Sign(x.PrivateKey, origMsg, uid, rand.Reader)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(sm2Signature{r, s})
}

// 使用公钥验证签名-字节数组模式
func (x *XSm2) Sm2Verify(origMsg []byte, uid []byte, sign []byte) (bool, error) {
	if nil == x.PublicKey {
		return false, errors.New("XSm2.PublicKey is nil")
	}
	if nil == origMsg || len(origMsg) <= 0 {
		return false, errors.New("origMsg is nil or empty")
	}
	var sm2Sign sm2Signature
	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return false, err
	}
	verifyResult := sm2.Sm2Verify(x.PublicKey, origMsg, uid, sm2Sign.R, sm2Sign.S)
	if !verifyResult {
		return false, errors.New("Sm2Verify Result:false")
	} else {
		return true, nil
	}
}

// 使用私钥进行签名-字节串模式
func (x *XSm2) Sm2SignString(encodeMode MODE_ENCODE, origMsg string, uid []byte) (string, error) {
	sig, err := x.Sm2Sign([]byte(origMsg), uid)
	if err != nil {
		return "", err
	}
	return EncodingToString(encodeMode, sig)
}

// 使用公钥验证签名-字节串模式
func (x *XSm2) Sm2VerifyString(encodeMode MODE_ENCODE, origMsg string, uid []byte, sigStr string) (bool, error) {
	sig, err := DecodingToByte(encodeMode, sigStr)
	if err != nil {
		return false, err
	}
	return x.Sm2Verify([]byte(origMsg), uid, sig)
}

func parseSm2Mode(c1c2c3Mode bool) int {
	if c1c2c3Mode {
		return sm2.C1C2C3
	} else {
		return sm2.C1C3C2
	}
}
