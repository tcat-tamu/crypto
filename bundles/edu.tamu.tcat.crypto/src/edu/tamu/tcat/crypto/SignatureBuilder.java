package edu.tamu.tcat.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * @since 1.1
 */
public interface SignatureBuilder
{
   /**
    * Create a {@link SignatureSigner} to sign data.
    * @param privateKey The {@link PrivateKey} used to sign the data.
    * @param digest The {@link DigestType} used in the signature.
    * @return A {@link SignatureSigner} to sign data.
    * @throws CipherException Thrown if the signer cannot be created.
    */
   public SignatureSigner buildSigner(PrivateKey privateKey, DigestType digest) throws CipherException;
   
   /**
    * Create a {@link SignatureVerifier} to verify a signature.
    * @param publicKey The {@link PublicKey} for verifying the signature.
    * @param digest The {@link DigestType} use in the signature.
    * @param signatureBytes The signature data.
    * @return A {@link SignatureVerifier} to verify the signature.
    * @throws CipherException Thrown if the verifier cannot be created.
    */
   public SignatureVerifier buildVerifier(PublicKey publicKey, DigestType digest, byte[] signatureBytes) throws CipherException;
}
