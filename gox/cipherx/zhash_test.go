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

func TestShaCommon(t *testing.T) {
	origFile := "/Users/qx/Downloads/文本bom测试.txt"
	//encFile := "/Users/qx/Downloads/文本bom测试_ENC.txt"
	//decFile := "/Users/qx/Downloads/文本bom测试_DEC.txt"
	sha, _ := Sm3SumFileByString(MODE_ENCODE_HEX_LOWER, origFile)
	fmt.Println("sha:", sha)
	shaStr, _ := Sm3SumByString(MODE_ENCODE_HEX_LOWER, origFile)
	fmt.Println("shaStr:", shaStr)

}
