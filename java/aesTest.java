import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class aesTest {
    /**解密
     * @param content  待加密内容
     * @param password 加密密钥
     * @return
     */
    public static String encrypt(String content, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] thedigest = md.digest(password.getBytes("UTF-8"));
            SecretKeySpec key = new SecretKeySpec(thedigest, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            byte[] byteContent = content.getBytes("utf-8");
            cipher.init(Cipher.ENCRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(byteContent);
            return new String(Base64.getEncoder().encode(result));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }


    /**解密
     * @param content  待解密内容
     * @param password 解密密钥
     * @return
     */
    public static byte[] decrypt(String content, String password) {
        try {
            byte[] data = Base64.getDecoder().decode(content);
            byte[] keyb = password.getBytes("UTF-8");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] thedigest = md.digest(keyb);
            SecretKeySpec key = new SecretKeySpec(thedigest, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");// 创建密码器
            cipher.init(Cipher.DECRYPT_MODE, key);// 初始化
            byte[] result = cipher.doFinal(data);
            return result; // 加密
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) throws IOException {
        try {
            String content = "test";
            String password = "12345678";
            //加密
            System.out.println("加密前：" + content);
            String encryptResult = encrypt(content, password);
            System.out.println("加密后：" + encryptResult);
            //解密
            byte[] decryptResult = decrypt(encryptResult, password);
            System.out.println("解密后：" + new String(decryptResult));
        }catch (Exception err){
            err.printStackTrace();
        }
    }
}

