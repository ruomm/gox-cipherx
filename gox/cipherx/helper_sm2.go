/**
 * @copyright www.ruomm.com
 * @author 牛牛-wanruome@126.com
 * @create 2024/6/21 14:07
 * @version 1.0
 */
package cipherx

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"strings"
)

type Sm2Helper interface {
	// 生成秘钥对
	GenrateKeyPair() error
	// 获取SM2秘钥对
	KeyPair() (*sm2.PrivateKey, *sm2.PublicKey)
	// 设置秘钥长度
	SetSizeOfKey(sizeOfKey int)
	// 获取秘钥长度
	GetSizeOfKey() int
	// 公钥长度
	SizeOfPublicKey() int
	// 秘钥长度
	SizeOfPrivateKey() int
	// Padding的模式
	ModeOfPadding() MODE_PADDING
	// 设置公钥
	SetPubicKey(pubKey []byte) error
	// 设置私钥
	SetPrivateKey(priKey []byte) error
	// 加载公钥
	LoadPulicKey(modeOfKey MODE_KEY, pubKeyStr string) error
	// 加载私钥
	LoadPrivateKey(modeOfKey MODE_KEY, priKeyStr string, pwd []byte) error
	// 格式化公钥
	FormatPublicKey(modeOfKey MODE_KEY) (string, error)
	// 格式化私钥
	FormatPrivateKey(modeOfKey MODE_KEY, pwd []byte) (string, error)
	// 使用公钥进行SM2加密-字节模式
	Encrypt(origMsg []byte, c1c2c3Mode bool) ([]byte, error)
	// 使用私钥进行SM2解密-字节模式
	Decrypt(encMsg []byte, c1c2c3Mode bool) ([]byte, error)
	// 使用公钥进行SM2加密-字符串模式
	EncryptString(encodeMode MODE_ENCODE, origStr string, c1c2c3Mode bool) (string, error)
	// 使用私钥进行SM2解密-字符串模式
	DecryptString(encodeMode MODE_ENCODE, encStr string, c1c2c3Mode bool) (string, error)

	// 使用公钥进行SM2加密-字节模式
	EncryptAsn1(origMsg []byte) ([]byte, error)
	// 使用私钥进行SM2解密-字节模式
	DecryptAsn1(encMsg []byte) ([]byte, error)
	// 使用公钥进行SM2加密-字符串模式
	EncryptAsn1String(encodeMode MODE_ENCODE, origStr string) (string, error)
	// 使用私钥进行SM2解密-字符串模式
	DecryptAsn1String(encodeMode MODE_ENCODE, encStr string) (string, error)
}

func Sm2KeyStringToByte(keyMode MODE_KEY, keyStr string) ([]byte, error) {
	if len(keyStr) <= 0 {
		return []byte{}, errors.New("lenght of keyStr(string) must greater than 0")
	}
	if keyMode == MODE_KEY_BASE64 {
		return base64.StdEncoding.DecodeString(keyStr)
	} else if keyMode == MODE_KEY_HEX_LOWER {
		return hex.DecodeString(strings.ToLower(keyStr))
	} else if keyMode == MODE_KEY_HEX_UPPER {
		return hex.DecodeString(strings.ToLower(keyStr))
	} else if keyMode == MODE_KEY_STRING {
		return ReadFormatKey(keyStr)
	} else if keyMode == MODE_KEY_PEM {
		block, _ := pem.Decode([]byte(keyStr))
		if block == nil || len(block.Bytes) == 0 {
			return nil, errors.New("decode pem error!")
		}
		return block.Bytes, nil
	} else {
		return ReadFormatKey(keyStr)
	}
}
func Sm2KeyByteToString(keyMode MODE_KEY, keyData []byte, public bool) (string, error) {
	if len(keyData) <= 0 {
		return "", errors.New("lenght of keyData([]byte) must greater than 0")
	}
	if keyMode == MODE_KEY_BASE64 {
		return base64.StdEncoding.EncodeToString(keyData), nil
	} else if keyMode == MODE_KEY_HEX_LOWER {
		return strings.ToLower(hex.EncodeToString(keyData)), nil
	} else if keyMode == MODE_KEY_HEX_UPPER {
		return strings.ToUpper(hex.EncodeToString(keyData)), nil
	} else if keyMode == MODE_KEY_STRING {
		tag := "SM2 PRIVATE KEY"
		if public {
			tag = "SM2 PUBLIC KEY"
		}
		return FormatKeyByData(keyData, tag)
	} else if keyMode == MODE_KEY_PEM {
		tag := "SM2 PRIVATE KEY"
		if public {
			tag = "SM2 PUBLIC KEY"
		}
		pemBlock := &pem.Block{
			Type:  tag,
			Bytes: keyData,
		}
		return string(pem.EncodeToMemory(pemBlock)), nil
	} else {
		tag := "SM2 PRIVATE KEY"
		if public {
			tag = "SM2 PUBLIC KEY"
		}
		return FormatKeyByData(keyData, tag)
	}
}
