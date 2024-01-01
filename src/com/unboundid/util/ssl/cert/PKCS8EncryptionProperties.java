/*
 * Copyright 2022-2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2024 Ping Identity Corporation
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
 * Copyright (C) 2022-2024 Ping Identity Corporation
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



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.ssl.cert.CertMessages.*;



/**
 * This class defines a set of properties that may be used when encrypting a
 * PKCS #8 private key.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PKCS8EncryptionProperties
       implements Serializable
{
  /**
   * The default value that will be used for the key factory iteration count.
   */
  private static final int DEFAULT_KEY_FACTORY_ITERATION_COUNT = 2048;



  /**
   * The default value that will be used for the key factory salt length.
   */
  private static final int DEFAULT_KEY_FACTORY_SALT_LENGTH_BYTES = 8;



  /**
   * The default value that will be used for the encryption cipher
   * transformation.
   */
  @NotNull()
  private static final PKCS5AlgorithmIdentifier DEFAULT_CIPHER_TRANSFORMATION =
       PKCS5AlgorithmIdentifier.AES_128_CBC_PAD;



  /**
   * The default value that will be used for the pseudorandom function for the
   * key factory algorithm.
   */
  @NotNull()
  private static final PKCS5AlgorithmIdentifier DEFAULT_KEY_FACTORY_PRF =
       PKCS5AlgorithmIdentifier.HMAC_SHA_256;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9162621645150582722L;



  // The iteration count to use when generating the encryption key from the
  // encryption password.
  private int keyFactoryIterationCount;

  // The length of the key factory salt to create, in bytes.
  private int keyFactorySaltLengthBytes;

  // The cipher transformation to use to encrypt the private key.
  @NotNull private PKCS5AlgorithmIdentifier cipherTransformationAlgorithm;

  // The algorithm to use to generate the encryption key from the encryption
  // password.
  @NotNull private PKCS5AlgorithmIdentifier keyFactoryPRFAlgorithm;



  /**
   * Creates a set of PKCS #8 encryption properties with the default settings.
   */
  public PKCS8EncryptionProperties()
  {
    keyFactoryIterationCount = DEFAULT_KEY_FACTORY_ITERATION_COUNT;
    keyFactorySaltLengthBytes = DEFAULT_KEY_FACTORY_SALT_LENGTH_BYTES;
    cipherTransformationAlgorithm = DEFAULT_CIPHER_TRANSFORMATION;
    keyFactoryPRFAlgorithm = DEFAULT_KEY_FACTORY_PRF;
  }



  /**
   * Retrieves the algorithm identifier for the pseudorandom function to use for
   * the key factory when generating the encryption key from the provided
   * password.
   *
   * @return  The algorithm identifier for the pseudorandom function to use for
   *          the key factory when generating the encryption key from the
   *          provided password.
   */
  @NotNull()
  public PKCS5AlgorithmIdentifier getKeyFactoryPRFAlgorithm()
  {
    return keyFactoryPRFAlgorithm;
  }



  /**
   * Specifies the algorithm identifier for the pseudorandom function to use
   * when generating the encryption key from the provided password.
   *
   * @param  keyFactoryPRFAlgorithm  The algorithm identifier for the
   *                                 pseudorandom function to use when
   *                                 generating the encryption key from the
   *                                 provided password.  It must not be
   *                                 {@code null}, and it must represent a valid
   *                                 pseudorandom function.
   *
   * @throws  CertException  If the provided algorithm identifier does not
   *                         represent a valid pseudorandom function.
   */
  public void setKeyFactoryPRFAlgorithm(
       @NotNull final PKCS5AlgorithmIdentifier keyFactoryPRFAlgorithm)
       throws CertException
  {
    if (! PKCS5AlgorithmIdentifier.getPseudorandomFunctions().contains(
         keyFactoryPRFAlgorithm))
    {
      throw new CertException(
           ERR_PKCS8_ENC_PROPS_INVALID_KEY_FACTORY_PRF_ALG.get(
                keyFactoryPRFAlgorithm.getName(),
                keyFactoryPRFAlgorithm.getDescription()));
    }

    this.keyFactoryPRFAlgorithm = keyFactoryPRFAlgorithm;
  }



  /**
   * Retrieves the iteration count to use when generating the encryption key
   * from the provided password.
   *
   * @return  The iteration count to use when generating the encryption key from
   *          the provided password.
   */
  public int getKeyFactoryIterationCount()
  {
    return keyFactoryIterationCount;
  }



  /**
   * Specifies the iteration count to use when generating the encryption key
   * from the provided password.
   *
   * @param  keyFactoryIterationCount  The iteration count to use when
   *                                   generating the encryption key from the
   *                                   provided password.  It must be greater
   *                                   than zero.
   */
  public void setKeyFactoryIterationCount(final int keyFactoryIterationCount)
  {
    Validator.ensureTrue((keyFactoryIterationCount > 0),
         "The key factory iteration count must be greater than zero.");
    this.keyFactoryIterationCount = keyFactoryIterationCount;
  }



  /**
   * Retrieves the length in bytes to use for the key factory salt when
   * generating the encryption key from the provided password.
   *
   * @return  The length in bytes to use for the key factory salt when
   *          generating the encryption key from the provided password.
   */
  public int getKeyFactorySaltLengthBytes()
  {
    return keyFactorySaltLengthBytes;
  }



  /**
   * Specifies the length in bytes to use for the key factory salt when
   * generating the encryption key from the provided password.
   *
   * @param  keyFactorySaltLengthBytes  The length in bytes to use for the key
   *                                    factory salt when generating the
   *                                    encryption key from the provided
   *                                    password.  It must be greater than zero.
   */
  public void setKeyFactorySaltLengthBytes(final int keyFactorySaltLengthBytes)
  {
    Validator.ensureTrue((keyFactorySaltLengthBytes > 0),
         "The key factory salt length must be greater than zero bytes.");
    this.keyFactorySaltLengthBytes = keyFactorySaltLengthBytes;
  }



  /**
   * Retrieves the algorithm identifier for the cipher transformation to use
   * when encrypting a PKCS #8 private key.
   *
   * @return  The algorithm identifier for the cipher transformation to use when
   *          encrypting a PKCS #8 private key.
   */
  @NotNull()
  public PKCS5AlgorithmIdentifier getCipherTransformationAlgorithm()
  {
    return cipherTransformationAlgorithm;
  }



  /**
   * Specifies  the algorithm identifier for the cipher transformation to use
   * when encrypting a PKCS #8 private key.
   *
   * @param  cipherTransformationAlgorithm  The algorithm identifier for the
   *                                        cipher transformation to use when
   *                                        encrypting a PKCS #8 private key.
   *                                        It must not be {@code null}, and it
   *                                        must represent a valid cipher
   *                                        transformation.
   *
   * @throws  CertException  If the provided algorithm identifier does not
   *                         represent a valid cipher transformation.
   */
  public void setCipherTransformationAlgorithm(
       @NotNull final PKCS5AlgorithmIdentifier cipherTransformationAlgorithm)
       throws CertException
  {
    if (! PKCS5AlgorithmIdentifier.getCipherTransformations().contains(
         cipherTransformationAlgorithm))
    {
      throw new CertException(
           ERR_PKCS8_ENC_PROPS_INVALID_CIPHER_TRANSFORMATION_ALG.get(
                cipherTransformationAlgorithm.getName(),
                cipherTransformationAlgorithm.getDescription()));
    }

    this.cipherTransformationAlgorithm = cipherTransformationAlgorithm;
  }



  /**
   * Retrieves a string representation of the PKCS #8 encryption properties.
   *
   * @return  A string representation of the PKCS #8 encryption properties.
   */
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of the PKCS #8 encryption properties to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.  It
   *                 must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PKCS8EncryptionProperties(keyFactoryPRFAlgorithm='");
    buffer.append(keyFactoryPRFAlgorithm.getName());
    buffer.append("', keyFactoryIterationCount=");
    buffer.append(keyFactoryIterationCount);
    buffer.append(", keyFactorySaltLengthBytes=");
    buffer.append(keyFactorySaltLengthBytes);
    buffer.append(", cipherTransformation='");
    buffer.append(cipherTransformationAlgorithm.getName());
    buffer.append("')");
  }
}
