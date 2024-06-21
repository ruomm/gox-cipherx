/**
 * @copyright www.ruomm.com
 * @author 牛牛-wanruome@126.com
 * @create 2024/6/21 17:53
 * @version 1.0
 */
package cipherx

import (
	"fmt"
	"testing"
)

func TestGuomiSm2Common(t *testing.T) {
	var PWD []byte = []byte("123456")
	//var PWD []byte = nil
	//time, _ := TimeParseByString(TIME_PATTERN_STANDARD, "2023-01-01 00:50:11")
	var xHelper Sm2Helper
	xHelper = &XSm2{
		ModePadding: MODE_PADDING_PKCS5,
	}
	xHelper.GenrateKeyPair()
	pubKey, _ := xHelper.FormatPublicKey(MODE_KEY_BASE64)
	priKey, _ := xHelper.FormatPrivateKey(MODE_KEY_BASE64, PWD)

	fmt.Println(pubKey)
	fmt.Println(priKey)
	err := xHelper.LoadPulicKey(MODE_KEY_BASE64, pubKey)
	fmt.Println(err)
	err = xHelper.LoadPrivateKey(MODE_KEY_BASE64, priKey, PWD)
	fmt.Println(err)
	origStr := generateToken(64) + "      中华人民共和国      "
	//origStr = "a"
	//encStr, _ := xHelper.EncryptString(MODE_ENCODE_BASE64, origStr, true)
	encStr, _ := xHelper.EncryptAsn1String(MODE_ENCODE_BASE64, origStr)
	fmt.Println(encStr)
	//decStr, _ := xHelper.DecryptString(MODE_ENCODE_BASE64, encStr, true)
	decStr, _ := xHelper.DecryptAsn1String(MODE_ENCODE_BASE64, encStr)
	fmt.Println(decStr)
	if origStr == decStr {
		fmt.Println("加密解密验证通过")
	} else {
		fmt.Println("加密解密验证不通过通过")
	}
	xHelper.SetSignMarshalMode(SIGN_MARSHAL_SR)
	sigStr, _ := xHelper.Sm2SignString(MODE_ENCODE_HEX_LOWER, origStr, PWD)
	fmt.Println(sigStr)
	xHelper.SetSignMarshalMode(SIGN_MARSHAL_SR)
	_, verifyErr := xHelper.Sm2VerifyString(MODE_ENCODE_HEX_LOWER, origStr, PWD, sigStr)
	if verifyErr == nil && len(sigStr) > 0 {
		fmt.Println("签名验证通过")
	} else {
		fmt.Printf("签名验证不通过:%v", verifyErr)
	}

}

func TestSm3Common(t *testing.T) {
	origFile := "/Users/qx/Downloads/文本bom测试.txt"
	//encFile := "/Users/qx/Downloads/文本bom测试_ENC.txt"
	//decFile := "/Users/qx/Downloads/文本bom测试_DEC.txt"
	sha, _ := Sm3SumFileByString(MODE_ENCODE_HEX_LOWER, origFile)
	fmt.Println("sha:", sha)
	shaStr, _ := Sm3SumByString(MODE_ENCODE_HEX_LOWER, origFile)
	fmt.Println("shaStr:", shaStr)
}

func TestSm4Common(t *testing.T) {

	//time, _ := TimeParseByString(TIME_PATTERN_STANDARD, "2023-01-01 00:50:11")
	var xHelper EncryptHelper
	//xencrypt.
	xHelper = &XSm4{
		ModeKey:     MODE_KEY_PEM,
		ModeEncode:  MODE_ENCODE_BASE64,
		ModePadding: MODE_PADDING_PKCS5,
	}
	//xHelper.SetAutoFillKey(true)
	keyStr, _ := xHelper.GenKeyIvString(16)
	ivStr, _ := xHelper.GenIVString()
	fmt.Println(keyStr)
	fmt.Println(ivStr)
	xHelper.SetKeyString(keyStr)
	xHelper.SetIVString(ivStr)
	//xHelper.SetBlockSize(16)
	origStr := "      中华人民共和国      " + generateToken(1024) + "      中华人民共和国      "
	//origStr = ""
	encStr, _ := xHelper.EncStringECB(origStr)
	fmt.Println(encStr)
	decStr, _ := xHelper.DecStringECB(encStr)
	fmt.Println(decStr)
	if origStr == decStr {
		fmt.Println("加密解密验证通过")
	} else {
		fmt.Println("加密解密验证不通过通过")
	}

	origFile := "/Users/qx/Downloads/文本bom测试.txt"
	encFile := "/Users/qx/Downloads/文本bom测试_ENC.txt"
	decFile := "/Users/qx/Downloads/文本bom测试_DEC.txt"
	err := xHelper.EncFileECB(origFile, encFile)
	if err == nil {
		fmt.Println("文件加密通过")
	} else {
		fmt.Printf("文件加密不通过:%v", err)
	}
	err = xHelper.DecFileECB(encFile, decFile)
	if err == nil {
		fmt.Println("文件解密通过")
	} else {
		fmt.Printf("文件解密不通过:%v", err)
	}
}
