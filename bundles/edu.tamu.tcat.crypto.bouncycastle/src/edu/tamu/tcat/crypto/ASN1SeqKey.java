/*******************************************************************************
 * Copyright © 2007-14, All Rights Reserved.
 * Texas Center for Applied Technology
 * Texas A&M Engineering Experiment Station
 * The Texas A&M University System
 * College Station, Texas, USA 77843
 *
 * Use is granted only to authorized licensee.
 * Proprietary information, not for redistribution.
 ******************************************************************************/

package edu.tamu.tcat.crypto;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECPointUtil;

import edu.tamu.tcat.crypto.internal.Activator;

public class ASN1SeqKey
{
   /*
    * Currently this does not work, but is committed in case it may be useful later on.
    */
   
   
   /**
    * Decodes a private key from a byte array using
    * @param type one of "RSA", "DSA", "EC", etc.
    * @param encodedKey byte[] representing the private key in the X.509 format
    * @return the private key represented by the X.509 structure
    * @throws EncodingException
    */
   public static PrivateKey decodePrivateKey(String type, byte[] encodedKey) throws EncodingException
   {
      switch (type)
      {
         case "EC":
            return decodeECKey(encodedKey);
         default:
            throw new EncodingException("Don't know how to decode a private key of type " + type);
      }
   }

   private static PrivateKey decodeECKey(byte[] encodedKey) throws EncodingException
   {
      try
      {
         ECPrivateKey priv = ECPrivateKey.getInstance(encodedKey);
         ASN1Sequence parameters = (ASN1Sequence)priv.getParameters();
         
         ASN1Integer version = (ASN1Integer)parameters.getObjectAt(0);
         if (version.getPositiveValue().intValue() != 1)
            throw new EncodingException("Only know how to decode version 1");
         ASN1Sequence fieldId = (ASN1Sequence)parameters.getObjectAt(1);
         ASN1Encodable fieldType = fieldId.getObjectAt(0);
         ECField field;
         if (fieldType.toString().equals("1.2.840.10045.1.1"))
         {
            ASN1Integer primeObject = (ASN1Integer)fieldId.getObjectAt(1);
            field = new ECFieldFp(primeObject.getPositiveValue());
         }
         else
            throw new EncodingException("Only know how to decode prime fields");
         ASN1Sequence curveSeq = (ASN1Sequence)parameters.getObjectAt(2);
         
         ASN1OctetString a = (ASN1OctetString)curveSeq.getObjectAt(0);
         ASN1OctetString b = (ASN1OctetString)curveSeq.getObjectAt(1);
         EllipticCurve curve;
         if (curveSeq.size() > 2)
         {
            DERBitString seed = (DERBitString)curveSeq.getObjectAt(2);
            curve = new EllipticCurve(field, getInteger(a.getOctets()), getInteger(b.getOctets()), seed.getBytes());
         }
         else
            curve = new EllipticCurve(field, getInteger(a.getOctets()), getInteger(b.getOctets()));
         
         ASN1OctetString gEncoded = (ASN1OctetString)parameters.getObjectAt(3);
         ECPoint g = ECPointUtil.decodePoint(curve, gEncoded.getOctets());
         ASN1Integer n = (ASN1Integer)parameters.getObjectAt(4);
         ASN1Integer h = (ASN1Integer)parameters.getObjectAt(5);
         ECParameterSpec paramSpec = new ECParameterSpec(curve, g, n.getPositiveValue(), h.getPositiveValue().intValue());
         
         ECPrivateKeySpec spec = new ECPrivateKeySpec(priv.getKey(), paramSpec);
         KeyFactory factory = KeyFactory.getInstance("EC", Activator.getDefault().getBouncyCastleProvider());
         PrivateKey key = factory.generatePrivate(spec);
         return key;
      }
      catch (NoSuchAlgorithmException | InvalidKeySpecException e)
      {
         throw new EncodingException("Failed decoding type [EC]", e);
      }
   }
   
   private static BigInteger getInteger(byte[] bytes)
   {
      byte[] inner = new byte[bytes.length + 1];
      inner[0] = 0;
      System.arraycopy(bytes, 0, inner, 1, bytes.length);
      return new BigInteger(inner);
   }
   
   public static byte[] encodeKey(PrivateKey key) throws EncodingException
   {
      if (key instanceof java.security.interfaces.ECPrivateKey)
      {
         java.security.interfaces.ECPrivateKey ecKey = (java.security.interfaces.ECPrivateKey)key;
         return encodeECKey(ecKey);
      }
      throw new EncodingException("Don't know how to encode " + key);
   }
   
   private static byte[] encodeECKey(java.security.interfaces.ECPrivateKey key) throws EncodingException
   {
      ASN1Sequence parameters = getParameters(key.getParams());
      DERBitString publicKey = getPublic(key);
      ECPrivateKey encoded = new ECPrivateKey(key.getS(), publicKey, parameters);
      try
      {
         return encoded.getEncoded();
      }
      catch (IOException e)
      {
         throw new EncodingException(e);
      }
   }
   
   private static ASN1Sequence getParameters(ECParameterSpec ecParameterSpec) throws EncodingException
   {
      ASN1EncodableVector v = new ASN1EncodableVector();
      v.add(new ASN1Integer(1));
      EllipticCurve curve = ecParameterSpec.getCurve();
      
      ASN1Sequence fieldId = getField(curve.getField());
      v.add(fieldId);
      v.add(getCurve(curve));
      
      org.bouncycastle.math.ec.ECPoint g = EC5Util.convertPoint(ecParameterSpec, ecParameterSpec.getGenerator(), false);
      byte[] encoded = g.getEncoded();
      v.add(new DEROctetString(encoded));
      
      v.add(new ASN1Integer(ecParameterSpec.getOrder()));
      v.add(new ASN1Integer(ecParameterSpec.getCofactor()));

      return new DERSequence(v);
   }
   
   private static DERBitString getPublic(java.security.interfaces.ECPrivateKey key) throws EncodingException
   {
      BCECPrivateKey priv = (BCECPrivateKey)key;
      org.bouncycastle.math.ec.ECPoint g = priv.getParameters().getG();
      org.bouncycastle.math.ec.ECPoint q = g.multiply(priv.getS());
      return new DERBitString(q.getEncoded());
   }
   
   private static ASN1Sequence getField(ECField field) throws EncodingException
   {
      ASN1EncodableVector v = new ASN1EncodableVector();
      if (field instanceof ECFieldFp)
      {
         ECFieldFp fpField = (ECFieldFp)field;
         v.add(new ASN1ObjectIdentifier("1.2.840.10045.1.1"));
         v.add(new ASN1Integer(fpField.getP()));
      }
      else
         throw new EncodingException("Only know how to encode prime fields");
      
      return new DERSequence(v);
   }

   private static ASN1Sequence getCurve(EllipticCurve curve) throws EncodingException
   {
      ASN1EncodableVector v = new ASN1EncodableVector();
      
      v.add(new DEROctetString(getInteger(curve.getA())));
      v.add(new DEROctetString(getInteger(curve.getB())));
      byte[] seed = curve.getSeed();
      if (seed != null)
         v.add(new DERBitString(seed));
      
      return new DERSequence(v);
   }

   private static byte[] getInteger(BigInteger value)
   {
      byte[] bytes = value.toByteArray();
      if (bytes[0] != 0)
         return bytes;
      byte[] cropped = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, cropped, 0, cropped.length);
      return cropped;
   }
}
