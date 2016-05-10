'use strict'

var _ = require("lodash");
var crypto = require('crypto');
/**
 * 加密工具类
 */
class EncryptTool {

    /**
     * base64加密
     * @param str   被加密的字符串
     * @param encoding  加密方式
     * @returns {*}
     */
    static base64_encode(str, encoding) {
        if (_.isEmpty(str)) {
            return "";
        }
        encoding = encoding || "utf8"
        if (!_.isString(str)) str = str.toString();
        var encodeStr = new Buffer(str, encoding).toString("base64");
        return encodeStr;
    }

    /**
     * base64 解密
     * @param decodingStr  被加密的字符串
     * @param encoding     解密类型
     * @returns {*}
     */
    static base64_decode(encodingStr, encoding) {
        encoding = encoding || "base64";
        if (_.isEmpty(encodingStr)) return "";
        var decodingStr = new Buffer(encodingStr, encoding);
        return decodingStr;
    }


    /**
     * @fn static aes_encode(data): string
     * @brief  aes加密.
     * @param  data    要加密的字符串
     * @return 加密后字符串.
     */

    static aes_encode(encodekey, data) {
        //使用的加密算法
        var algorithm = 'AES-256-ECB';
        //使用的加密字符串
        var key = crypto.createHash("sha256").update(encodekey).digest()
        //输入的数据编码
        var inputEncoding = 'utf8';
        //初始化向量
        //输出数据编码
        var outputEncoding = 'base64';
        //创建加密器
        var cipher = crypto.createCipheriv(algorithm, key, "");
        cipher.setAutoPadding(true);
        //更新加密器：对数据进行加密
        var encodingStr = cipher.update(data, inputEncoding, outputEncoding);
        encodingStr += cipher.final(outputEncoding);
        //返回加密后字符串
        return encodingStr;

    }


    /**
     * @fn static aes_decode(encodingStr: string): string
     * @brief  aes 解密.
     * @param  encodingStr 要解密的字符串.
     * @return 解密后字符串.
     */

    static aes_decode(decodeKey, encodingStr) {
        //使用的算法
        var algorithm = 'AES-256-ECB';
        var key = crypto.createHash("sha256").update(decodeKey).digest()
        //输出的格式
        var outputEncoding = 'utf8';
        //输入数据编码
        var inputEncoding = 'base64';
        //创建解密器
        var decipher = crypto.createDecipheriv(algorithm, key, "");
        decipher.setAutoPadding(true);

        //解密数据
        var data = decipher.update(encodingStr, inputEncoding, outputEncoding);
        data += decipher.final(outputEncoding);
        return data;
    }


}

var str = "test";
var encodedata = EncryptTool.aes_encode("12345678", str);
var decodedata = EncryptTool.aes_decode("12345678", encodedata);
console.log("encodeData:",str, "\nencodedStr:", encodedata,"\ndecodedStr:", decodedata)

