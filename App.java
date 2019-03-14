package dz;

import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

class Main {
  private static Integer PBKDF2_ITERATIONS  = 1024;
  private static Integer KEY_BYTE_SIZE = 128;
  private static String cText = "cWKz2Ajf8LPntPBqGdwIZT-3TxXKw40wCahYJRPGKzWzz2mHacBCTnoy43LOc1bZ0OoaVK734Azc_LsQd--Hl_VI_tCjF4-67-7-frheoK5m5ViaShI9n--nfAex2Jin";
  private static byte[] cTextB = null;
  private static String[] split = null;

  public static byte[] applyPBKDF2(Integer password) throws NoSuchAlgorithmException
  {

    if(password == 6543)
    {
      int i = 0;
    }
    char[] passChars = intPassToStr(password).toCharArray();
    //byte[] salt = Arrays.copyOfRange(cTextB, 0, 4);
    byte[] salt = new byte[16]; // use salt size at least as long as hash
    //byte[] salt = split[1].getBytes();
    PBEKeySpec spec = new PBEKeySpec(passChars, salt, PBKDF2_ITERATIONS, KEY_BYTE_SIZE);
    SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    byte[] hash;
    try
    {
      hash = skf.generateSecret(spec).getEncoded();
    }
    catch(InvalidKeySpecException e)
    {
      e.printStackTrace();
      hash = new byte[1];
    }
    return hash;
  }

  public static String decrypt(String alg, byte[] key)
  {
    //NoSuchAlgorithmException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    //SecretKeySpec keySpec = new SecretKeySpec(Arrays.copyOfRange(key, 16, 32), alg);
    SecretKeySpec keySpec = new SecretKeySpec(key, alg);
    try {
      Cipher c = Cipher.getInstance(alg+"/CBC/PKCS5Padding"); //PKCS5Padding NoPadding
      //byte[] IV = Arrays.copyOfRange(key, 0, 16);//"1x߮+V&gbb".getBytes();
      byte[] IV = new byte[16];
      IvParameterSpec IVSpec = new IvParameterSpec(IV);
      c.init(Cipher.DECRYPT_MODE, keySpec, IVSpec);
      byte[] ct = cTextB;//cTextB;//Arrays.copyOfRange(cTextB, 4, 96);
      byte[] decrypted = c.doFinal(ct);
      return new String(decrypted);
    }
    catch (BadPaddingException e)
    {
      return e.getMessage();
    }
    catch (InvalidKeyException e)
    {
      e.printStackTrace();
      return "Wrong key size";
    }
    //catch(InvalidAlgorithmParameterException e)
    //{
    //  e.printStackTrace();
    //  return "Wrong parameter";
    //}
    catch (Exception e) {
      e.printStackTrace();
      return e.getMessage();
    }
  }

  public static String intPassToStr(Integer password)
  {
    String result = Integer.toString(password);
    while(result.length() < 4)
    {
      result = "0" + result;
    }
    return result;
  }

  public static void main(String[] args) throws NoSuchAlgorithmException, IOException
  {
    cTextB = Base64.getUrlDecoder().decode(cText.getBytes("ascii"));
    String tmp = new String(cTextB, "ascii");
    split = tmp.split("\t");
    byte[][] splitB = {split[0].getBytes("ascii"), split[1].getBytes("ascii")};
    System.out.println(cText);
    System.out.println(cTextB);
    
    Integer password = 0;
    FileWriter fileWriter = new FileWriter("result.txt");
    while(password < 10000)
    {
      byte[] passHash = applyPBKDF2(password);
      if(passHash.length == 1)
      {
        break;
      }
      String res = decrypt("AES", passHash);
      if(res.contains("Wrong"))
      {
        break;
      }
      //System.out.println(res);
      if(res != "Given final block not properly padded. Such issues can arise if a bad key is used during decryption.")
      {
        fileWriter.write(password + ": " + res + "\n");
        if(res.toUpperCase().contains("FLAG") || res.toUpperCase().contains("KEY"))
        {
          System.out.println(res);
        }
      }
      password++;
    }
    fileWriter.close();
    System.out.println("done");
  }
}