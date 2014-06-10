package edu.tamu.tcat.crypto.bouncycastle;

import java.security.SecureRandom;
import java.util.Random;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.PBKDF2;

public class PasswordHashTest
{
   private CryptoProvider provider;
   
   @Before
   public void getProvider()
   {
      provider = new BouncyCastleCryptoProvider();
   }
   
   @Ignore
   @Test
   public void hashKnownPassword()
   {
      String password = "SetYourDesiredPasswordHere";
      printHash(password);
   }
   
   @Ignore
   @Test
   public void hashNewPassword()
   {
      char[] allSymbols = {'`', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-', '+', '=', '{', '}', '[', ']', '\\', '|', ':', ';', '"', '\'', '<', '>', ',', '.', '?', '/'};
      char[] nonEscappedSymbols = {'`', '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '-', '+', '=', '{', '}', '[', ']', '|', ':', ';', '<', '>', ',', '.', '?', '/'};  // \ ' and " have been excluded
      char[] simpleSymbols = {'!', '@', '#', '$', '%', '^', '&', '*', '+', '=', '<', '>', '?', '/'};  // \ ' and " have been excluded
      char[] symbols = simpleSymbols;
      char[] passwordDomain = new char[26*2 + 10 + symbols.length];  //Upper/lower case; numbers; symbols
      System.arraycopy(symbols, 0, passwordDomain, 0, symbols.length);
      char lower = 'a';
      char upper = 'A';
      for (int i = 0; i < 26; i++)
      {
         passwordDomain[i + symbols.length] = lower;
         passwordDomain[i + symbols.length + 26] = upper;
         lower++;
         upper++;
      }
      char digit = '0';
      for (int i = 0; i< 10; i++)
      {
         passwordDomain[i + symbols.length + 26 * 2] = digit;
         digit++;
      }
      
      int length = 24;  //Set your desired password length here
      StringBuilder buffer = new StringBuilder();
      Random random = new SecureRandom();
      for (int i = 0; i < length; i++)
      {
         int index = random.nextInt(passwordDomain.length);
         buffer.append(passwordDomain[index]);
      }
      String password = buffer.toString();
      
      printHash(password);
   }

   private void printHash(String password)
   {
      PBKDF2 pbkdf2 = provider.getPbkdf2(DigestType.SHA512);
      String hash = pbkdf2.deriveHash(password);
      System.out.println("Hash for [" + password + "] is [" + hash + "]");
   }
}
