package edu.tamu.tcat.crypto.spongycastle;

import edu.tamu.tcat.crypto.ASN1SeqKey;
import edu.tamu.tcat.crypto.AsymmetricKeyBuilder;
import edu.tamu.tcat.crypto.CryptoProvider;
import edu.tamu.tcat.crypto.DigestType;
import edu.tamu.tcat.crypto.HashBuilder;
import edu.tamu.tcat.crypto.PBKDF2;
import edu.tamu.tcat.crypto.SecureToken;
import edu.tamu.tcat.crypto.SignatureBuilder;
import edu.tamu.tcat.crypto.SymmetricCipherBuilder;
import edu.tamu.tcat.crypto.TokenException;
import edu.tamu.tcat.crypto.X509KeyDecoder;

public class BouncyCastleCryptoProvider implements CryptoProvider
{
   @Override
   public SecureToken geSecureToken(String hexKey) throws TokenException
   {
      return new SecureTokenImpl(hexKey);
   }
   
   @Override
   public SecureToken geSecureToken(byte[] key) throws TokenException
   {
      return new SecureTokenImpl(key);
   }

   @Override
   public PBKDF2 getPbkdf2(DigestType digestType)
   {
      return new PBKDF2Impl(digestType);
   }

   @Override
   public HashBuilder getHashBuilder()
   {
      return new HashBuilderImpl();
   }

   @Override
   public AsymmetricKeyBuilder getAsymmetricKeyBuilder()
   {
      return new AsymmetricKeyBuilderImpl();
   }

   @Override
   public SignatureBuilder getSignatureBuilder()
   {
      return new SignatureBuilderImpl();
   }

   @Override
   public SymmetricCipherBuilder getSymmetricCipherBuilder()
   {
      return new SymmetricCipherBuilderImpl();
   }

   @Override
   public ASN1SeqKey getAsn1SeqKey()
   {
      return new ASN1SeqKeyImpl();
   }

   @Override
   public X509KeyDecoder getX509KeyDecoder()
   {
      return new X509KeyDecoderImpl();
   }

}
