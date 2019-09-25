/*
 * Copyright 2014-2019 Texas A&M Engineering Experiment Station
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.tamu.tcat.crypto.spongycastle;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Integer;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.DERBitString;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.sec.ECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jce.ECPointUtil;

import edu.tamu.tcat.crypto.ASN1SeqKey;
import edu.tamu.tcat.crypto.EncodingException;
import edu.tamu.tcat.crypto.spongycastle.internal.Activator;

public class ASN1SeqKeyImpl implements ASN1SeqKey
{
   private final Provider provider;

   @Deprecated
   public ASN1SeqKeyImpl()
   {
      provider = Activator.getDefault().getBouncyCastleProvider();
   }

   /**
    * @since 1.3
    */
   public ASN1SeqKeyImpl(Provider provider)
   {
      this.provider = provider;
   }

   @Override
   public PrivateKey decodePrivateKey(String type, byte[] encodedKey) throws EncodingException
   {
      switch (type)
      {
         case "EC":
            return decodeECKey(encodedKey, provider);
         default:
            throw new EncodingException("Don't know how to decode a private key of type " + type);
      }
   }

   private static PrivateKey decodeECKey(byte[] encodedKey, Provider provider) throws EncodingException
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
         KeyFactory factory = KeyFactory.getInstance("EC", provider);
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

   @Override
   public byte[] encodeKey(PrivateKey key) throws EncodingException
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

      org.spongycastle.math.ec.ECPoint g = EC5Util.convertPoint(ecParameterSpec, ecParameterSpec.getGenerator(), false);
      byte[] encoded = g.getEncoded();
      v.add(new DEROctetString(encoded));

      v.add(new ASN1Integer(ecParameterSpec.getOrder()));
      v.add(new ASN1Integer(ecParameterSpec.getCofactor()));

      return new DERSequence(v);
   }

   private static DERBitString getPublic(java.security.interfaces.ECPrivateKey key) throws EncodingException
   {
      BCECPrivateKey priv = (BCECPrivateKey)key;
      org.spongycastle.math.ec.ECPoint g = priv.getParameters().getG();
      org.spongycastle.math.ec.ECPoint q = g.multiply(priv.getS());
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
