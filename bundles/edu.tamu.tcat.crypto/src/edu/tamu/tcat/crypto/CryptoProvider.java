package edu.tamu.tcat.crypto;

public interface CryptoProvider
{
   SecureToken getSecureToken(String hexKey) throws TokenException;
   
   SecureToken getSecureToken(byte[] key) throws TokenException;
   
   PBKDF2 getPbkdf2(DigestType digestType);
   
   HashBuilder getHashBuilder();
   
   AsymmetricKeyBuilder getAsymmetricKeyBuilder();
   
   SignatureBuilder getSignatureBuilder();
   
   SymmetricCipherBuilder getSymmetricCipherBuilder();
   
   ASN1SeqKey getAsn1SeqKey();
   
   X509KeyDecoder getX509KeyDecoder();
}
