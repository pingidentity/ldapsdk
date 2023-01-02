/*
 * Copyright 2022-2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2023 Ping Identity Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Copyright (C) 2022-2023 Ping Identity Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (GPLv2 only)
 * or the terms of the GNU Lesser General Public License (LGPLv2.1 only)
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses>.
 */
package com.unboundid.util.ssl.cert;



import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.unboundid.asn1.ASN1Constants;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
import com.unboundid.asn1.ASN1ObjectIdentifier;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class provides a set of utility methods for interacting with encrypted
 * PKCS #8 private keys.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PKCS8EncryptionHandler
{
  /**
   * Prevents this utility class from being instantiated.
   */
  private PKCS8EncryptionHandler()
  {
    // No implementation is required.
  }



  /**
   * Encrypts the provided PKCS #8 private key using the provided settings.
   *
   * @param  privateKey            The private key to encrypt.  It must not be
   *                               {@code null}.
   * @param  encryptionPassword    The password to use to generate the
   *                               encryption key.  It must not be {@code null}.
   * @param  encryptionProperties  The properties to use when encrypting the
   *                               key.  It must not be {@code null}.
   *
   * @return  The bytes that contain the DER-encoded encrypted representation of
   *          the private key.
   *
   * @throws  CertException  If a problem occurs while attempting to encrypt the
   *                         provided certificate with the given settings.
   */
  @NotNull()
  public static byte[] encryptPrivateKey(
              @NotNull final PKCS8PrivateKey privateKey,
              @NotNull final char[] encryptionPassword,
              @NotNull final PKCS8EncryptionProperties encryptionProperties)
         throws CertException
  {
    return encryptPrivateKey(privateKey.getPKCS8PrivateKeyBytes(),
         encryptionPassword, encryptionProperties);
  }



  /**
   * Encrypts the provided PKCS #8 private key using the provided settings.
   *
   * @param  privateKeyBytes       The bytes that comprise the private key to
   *                               encrypt.  It must not be {@code null}.
   * @param  encryptionPassword    The password to use to generate the
   *                               encryption key.  It must not be {@code null}.
   * @param  encryptionProperties  The properties to use when encrypting the
   *                               key.  It must not be {@code null}.
   *
   * @return  The bytes that contain the DER-encoded encrypted representation of
   *          the private key.
   *
   * @throws  CertException  If a problem occurs while attempting to encrypt the
   *                         provided certificate with the given settings.
   */
  @NotNull()
  public static byte[] encryptPrivateKey(
              @NotNull final byte[] privateKeyBytes,
              @NotNull final char[] encryptionPassword,
              @NotNull final PKCS8EncryptionProperties encryptionProperties)
         throws CertException
  {
    final PKCS5AlgorithmIdentifier keyFactoryPRFAlgorithm =
         encryptionProperties.getKeyFactoryPRFAlgorithm();
    final int keyFactoryIterationCount =
         encryptionProperties.getKeyFactoryIterationCount();
    final int keyFactorySaltLengthBytes =
         encryptionProperties.getKeyFactorySaltLengthBytes();
    final PKCS5AlgorithmIdentifier cipherTransformationAlgorithm =
         encryptionProperties.getCipherTransformationAlgorithm();

    final String keyFactoryAlgorithm = PKCS5AlgorithmIdentifier.
         getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(
              keyFactoryPRFAlgorithm);
    final String cipherAlgorithm =
         PKCS5AlgorithmIdentifier.getCipherAlgorithmName(
              cipherTransformationAlgorithm);
    final String cipherTransformation =
         PKCS5AlgorithmIdentifier.getCipherTransformationName(
              cipherTransformationAlgorithm);
    final int cipherKeyLengthBits =
         PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
              cipherTransformationAlgorithm);


    // Generate the secret key.
    final SecretKey secretKey;
    final byte[] keyFactorySalt =
         StaticUtils.randomBytes(keyFactorySaltLengthBytes, true);
    try
    {
      final SecretKeyFactory keyFactory =
           CryptoHelper.getSecretKeyFactory(keyFactoryAlgorithm);
      final PBEKeySpec pbeKeySpec = new PBEKeySpec(encryptionPassword,
           keyFactorySalt, keyFactoryIterationCount, cipherKeyLengthBits);
      secretKey = new SecretKeySpec(
           keyFactory.generateSecret(pbeKeySpec).getEncoded(),
           cipherAlgorithm);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_CREATE_ENC_SECRET_KEY.get(
                keyFactoryAlgorithm, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Generate the cipher.
    final Cipher cipher;
    final byte[] cipherInitializationVector;
    try
    {
      cipher = CryptoHelper.getCipher(cipherTransformation);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      cipherInitializationVector = cipher.getIV();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_CREATE_ENC_CIPHER.get(
                cipherTransformation, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Encrypt the private key.
    final byte[] encryptedPrivteKeyData;
    try
    {
      encryptedPrivteKeyData = cipher.doFinal(privateKeyBytes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_ENCRYPT_PRIVATE_KEY.get(
                cipherTransformation, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Create the and return DER representation of the encrypted key.
    try
    {
      final ASN1Sequence kdfParametersSequence = new ASN1Sequence(
           new ASN1OctetString(keyFactorySalt),
           new ASN1Integer(keyFactoryIterationCount),
           new ASN1Sequence(
                new ASN1ObjectIdentifier(keyFactoryPRFAlgorithm.getOID()),
                new ASN1Null()));
      final ASN1Sequence kdfIdentifierSequence = new ASN1Sequence(
           new ASN1ObjectIdentifier(PKCS5AlgorithmIdentifier.PBKDF2.getOID()),
           kdfParametersSequence);

      final ASN1Sequence cipherSequence = new ASN1Sequence(
           new ASN1ObjectIdentifier(cipherTransformationAlgorithm.getOID()),
           new ASN1OctetString(cipherInitializationVector));

      final ASN1Sequence pbes2ParametersSequence = new ASN1Sequence(
           kdfIdentifierSequence,
           cipherSequence);

      final ASN1Sequence pbes2Sequence = new ASN1Sequence(
           new ASN1ObjectIdentifier(PKCS5AlgorithmIdentifier.PBES2.getOID()),
           pbes2ParametersSequence);

      final ASN1Sequence encryptedPrivateKeySequence = new ASN1Sequence(
           pbes2Sequence,
           new ASN1OctetString(encryptedPrivteKeyData));

      return encryptedPrivateKeySequence.encode();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_ENCODE_ENC_PRIVATE_KEY.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Attempts to decrypt the provided data as a PKCS #8 private key.
   *
   * @param  encryptedPrivateKeyBytes  The bytes that comprise the encrypted
   *                                   representation of a PKCS #8 private key.
   *                                   It must not be {@code null}.
   * @param  encryptionPassword        The password used to generate the
   *                                   encryption key.  It must not be
   *                                   {@code null}.
   *
   * @return  The decrypted and decoded PKCS #8 private key.
   *
   * @throws  CertException  If a problem occurs while attempting to decrypt the
   *                         encrypted private key.
   */
  @NotNull()
  public static PKCS8PrivateKey decryptPrivateKey(
              @NotNull final byte[] encryptedPrivateKeyBytes,
              @NotNull final char[] encryptionPassword)
         throws CertException
  {
    // Try to decode the private key bytes as an ASN.1 sequence of two elements.
    final ASN1Sequence encryptedKeySequence;
    try
    {
      encryptedKeySequence =
           ASN1Sequence.decodeAsSequence(encryptedPrivateKeyBytes);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_PARSE_AS_ENC_KEY_SEQUENCE.get(),
           e);
    }

    final ASN1Element[] encryptedKeyElements = encryptedKeySequence.elements();
    if (encryptedKeyElements.length != 2)
    {
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_SEQUENCE_UNEXPECTED_ENC_KEY_ELEMENT_COUNT.get(
                encryptedKeyElements.length));
    }


    // The first element of the sequence should be the algorithm identifier for
    // the encryption scheme.  It should be a sequence containing two elements.
    final ASN1Sequence keyEncryptionSchemeSequence;
    try
    {
      keyEncryptionSchemeSequence = encryptedKeyElements[0].decodeAsSequence();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_KEY_SCHEME_ELEMENT_NOT_SEQUENCE.get(),
           e);
    }

    final ASN1Element[] keyEncryptionSchemeElements =
         keyEncryptionSchemeSequence.elements();
    if (keyEncryptionSchemeElements.length != 2)
    {
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_SEQUENCE_UNEXPECTED_KEY_SCHEME_ELEMENT_COUNT.
                get(keyEncryptionSchemeElements.length));
    }


    // The first element of the encryption scheme sequence should be the OID of
    // the encryption scheme.  This implementation only supports the PBES2
    // scheme.
    final ASN1ObjectIdentifier keyEncryptionSchemeOID;
    try
    {
      keyEncryptionSchemeOID =
           keyEncryptionSchemeElements[0].decodeAsObjectIdentifier();
    }
    catch (final Exception e)
    {
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_PARSE_KEY_SCHEME_OID.get(), e);
    }

    if (! keyEncryptionSchemeOID.getOID().equals(
         PKCS5AlgorithmIdentifier.PBES2.getOID()))
    {
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_ENC_SCHEME_NOT_PBES2.get(
                keyEncryptionSchemeOID.getOID().toString()));
    }


    // The second element of the encryption scheme sequence should itself be a
    // sequence containing two elements.
    final ASN1Sequence pbes2Sequence;
    try
    {
      pbes2Sequence = keyEncryptionSchemeElements[1].decodeAsSequence();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_PBES2_PARAMS_NOT_SEQUENCE.get(), e);
    }

    final ASN1Element[] pbes2Elements = pbes2Sequence.elements();
    if (pbes2Elements.length != 2)
    {
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_PBES2_UNEXPECTED_PARAMS_SEQUENCE_ELEMENT_COUNT.
                get(pbes2Elements.length));
    }


    // The first element of the PBES2 algorithm parameters sequence should be
    // a sequence containing an OID and a sequence of parameters that describe
    // the key derivation function to use.  This implementation only supports
    // the PBKDF2 key derivation function.
    final String keyFactoryAlgorithm;
    final byte[] keyFactorySalt;
    final int keyFactoryIterationCount;
    Integer encryptionKeyLength = null;
    try
    {
      final ASN1Element[] kdfElements =
           pbes2Elements[0].decodeAsSequence().elements();
      final ASN1ObjectIdentifier kdfOID =
           kdfElements[0].decodeAsObjectIdentifier();
      if (! kdfOID.getOID().equals(PKCS5AlgorithmIdentifier.PBKDF2.getOID()))
      {
        throw new CertException(ERR_PKCS8_ENC_HANDLER_UNSUPPORTED_KDF.get(
             kdfOID.getOID().toString()));
      }

      final ASN1Element[] pbkdf2Elements =
           kdfElements[1].decodeAsSequence().elements();
      keyFactorySalt = pbkdf2Elements[0].decodeAsOctetString().getValue();
      keyFactoryIterationCount = pbkdf2Elements[1].decodeAsInteger().intValue();

      PKCS5AlgorithmIdentifier prf = PKCS5AlgorithmIdentifier.HMAC_SHA_1;
      for (int i=2; i < pbkdf2Elements.length; i++)
      {
        if (pbkdf2Elements[i].getType() == ASN1Constants.UNIVERSAL_INTEGER_TYPE)
        {
          encryptionKeyLength = pbkdf2Elements[i].decodeAsInteger().intValue();
        }
        else if (pbkdf2Elements[i].getType() ==
             ASN1Constants.UNIVERSAL_SEQUENCE_TYPE)
        {
          final ASN1ObjectIdentifier prfOID = pbkdf2Elements[i].
               decodeAsSequence().elements()[0].decodeAsObjectIdentifier();
          prf = PKCS5AlgorithmIdentifier.forOID(prfOID.getOID());
          if (prf == null)
          {
            throw new CertException(
                 ERR_PKCS8_ENC_HANDLER_UNSUPPORTED_PBKDF2_PRF.get(
                      prfOID.getOID().toString()));
          }
        }
      }

      keyFactoryAlgorithm = PKCS5AlgorithmIdentifier.
           getPBKDF2SecretKeyFactoryAlgorithmForPseudorandomFunction(prf);
      if (keyFactoryAlgorithm == null)
      {
        throw new CertException(
             ERR_PKCS8_ENC_HANDLER_UNSUPPORTED_PBKDF2_PRF.get(
                  prf.getOID().toString()));
      }
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_DECODE_KDF_SETTINGS.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // The second element of the PBES2 algorithm parameters sequence should be a
    // sequence containing an OID and an octet string with parameters for the
    // encryption algorithm.
    final String cipherAlgorithm;
    final String cipherTransformation;
    final byte[] initializationVector;
    try
    {
      final ASN1Element[] cipherElements =
           pbes2Elements[1].decodeAsSequence().elements();
      final ASN1ObjectIdentifier cipherOID =
           cipherElements[0].decodeAsObjectIdentifier();
      final PKCS5AlgorithmIdentifier cipherIdentifier =
           PKCS5AlgorithmIdentifier.forOID(cipherOID.getOID());
      if (cipherIdentifier == null)
      {
        throw new CertException(
             ERR_PKCS8_ENC_HANDLER_UNSUPPORTED_CIPHER.get(
                  cipherOID.getOID().toString()));
      }

      cipherAlgorithm =
           PKCS5AlgorithmIdentifier.getCipherAlgorithmName(cipherIdentifier);
      cipherTransformation =
           PKCS5AlgorithmIdentifier.getCipherTransformationName(
                cipherIdentifier);
      if (encryptionKeyLength == null)
      {
        encryptionKeyLength = PKCS5AlgorithmIdentifier.getCipherKeySizeBits(
             cipherIdentifier);
      }

      if ((cipherAlgorithm == null) || (cipherTransformation == null) ||
           (encryptionKeyLength == null))
      {
        throw new CertException(
             ERR_PKCS8_ENC_HANDLER_UNSUPPORTED_CIPHER.get(
                  cipherOID.getOID().toString()));
      }

      initializationVector = cipherElements[1].decodeAsOctetString().getValue();
    }
    catch (final CertException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_DECODE_CIPHER_SETTINGS.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Generate the secret key to use for the decryption.
    final SecretKey secretKey;
    try
    {
      final SecretKeyFactory keyFactory =
           CryptoHelper.getSecretKeyFactory(keyFactoryAlgorithm);
      final PBEKeySpec keySpec = new PBEKeySpec(encryptionPassword,
           keyFactorySalt, keyFactoryIterationCount, encryptionKeyLength);
      secretKey = new SecretKeySpec(
           keyFactory.generateSecret(keySpec).getEncoded(),
           cipherAlgorithm);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_CREATE_DEC_SECRET_KEY.get(
                keyFactoryAlgorithm, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Generate the cipher to use for the decryption.
    final Cipher cipher;
    try
    {
      cipher = CryptoHelper.getCipher(cipherTransformation);
      cipher.init(Cipher.DECRYPT_MODE, secretKey,
           new IvParameterSpec(initializationVector));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_CREATE_DEC_CIPHER.get(
                cipherTransformation, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Decrypt the encrypted key data.
    final byte[] decryptedKeyData;
    try
    {
      decryptedKeyData = cipher.doFinal(
           encryptedKeyElements[1].decodeAsOctetString().getValue());
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_DECRYPT_KEY.get(
                cipherTransformation, StaticUtils.getExceptionMessage(e)),
           e);
    }


    // Decode and return the decrypted key.
    try
    {
      return new PKCS8PrivateKey(decryptedKeyData);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new CertException(
           ERR_PKCS8_ENC_HANDLER_CANNOT_PARSE_DECRYPTED_KEY.get(
                cipherTransformation, StaticUtils.getExceptionMessage(e)),
           e);
    }
  }
}
