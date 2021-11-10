/*
 * Copyright 2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2021 Ping Identity Corporation
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
 * Copyright (C) 2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides a {@link ReplaceCertificateKeyStoreContent}
 * implementation to indicate that the server should use a certificate key store
 * whose content (that is, the bytes that comprise the key store file) is
 * provided directly in the extended request.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class KeyStoreDataReplaceCertificateKeyStoreContent
       extends ReplaceCertificateKeyStoreContent
{
  /**
   * The BER type to use for the ASN.1 element containing an encoded
   * representation of this key store content object.
   */
  static final byte TYPE_KEY_STORE_CONTENT = (byte) 0xA1;



  /**
   * The BER type to use for the ASN.1 element that holds the raw data that
   * comprises the key store.
   */
  private static final byte TYPE_KEY_STORE_DATA = (byte) 0x88;



  /**
   * The BER type to use for the ASN.1 element that holds raw data that
   * comprises the key store.
   */
  private static final byte TYPE_KEY_STORE_PIN = (byte) 0x89;



  /**
   * The BER type to use for the ASN.1 element that holds the PIN needed to
   * access the private key in the key store.
   */
  private static final byte TYPE_PRIVATE_KEY_PIN = (byte) 0x8A;



  /**
   * The BER type to use for the ASN.1 element that holds the key store type.
   */
  private static final byte TYPE_KEY_STORE_TYPE = (byte) 0x8B;



  /**
   * The BER type to use for the ASN.1 element that holds the source certificate
   * alias.
   */
  private static final byte TYPE_SOURCE_CERTIFICATE_ALIAS = (byte) 0x8C;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8068834762688653001L;



  // The raw data that comprises the key store.
  @NotNull private final byte[] keyStoreData;

  // The PIN needed to access the contents of the key store.
  @NotNull private final String keyStorePIN;

  // The key store type for the key store.
  @Nullable private final String keyStoreType;

  // The PIN needed to access the private key.
  @Nullable private final String privateKeyPIN;

  // The alias of the certificate to use in the key store.
  @Nullable private final String sourceCertificateAlias;



  /**
   * Creates a new instance of this key store content object with the provided
   * information.
   *
   * @param  keyStoreData            The raw bytes that comprises the key store
   *                                 with the new certificate to use.  It must
   *                                 not be {@code null} or empty.
   * @param  keyStorePIN             The PIN needed to access protected content
   *                                 in the key store.  It must not be
   *                                 {@code null} or empty.
   * @param  privateKeyPIN           The PIN needed to access private key
   *                                 information in the key store.  It may be
   *                                 {@code null} if the key store PIN should
   *                                 also be used as the private key PIN.
   * @param  keyStoreType            The key store type for the target key
   *                                 store.  If provided, its value will likely
   *                                 be one of JKS, PKCS12, or BCFKS.  If this
   *                                 is {@code null}, then the server will
   *                                 attempt to automatically determine the
   *                                 appropriate key store type.
   * @param  sourceCertificateAlias  The alias of the private key entry in the
   *                                 key store that contains the new certificate
   *                                 chain to be used.  It may optionally be
   *                                 {@code null} if and only if the key store
   *                                 has only a single private key entry.
   */
  public KeyStoreDataReplaceCertificateKeyStoreContent(
              @NotNull final byte[] keyStoreData,
              @NotNull final String keyStorePIN,
              @Nullable final String privateKeyPIN,
              @Nullable final String keyStoreType,
              @Nullable final String sourceCertificateAlias)
  {
    Validator.ensureNotNullOrEmpty(keyStoreData,
         "KeyStoreDataReplaceCertificateKeyStoreContent.keyStoreData must " +
              "not be null or empty.");
    Validator.ensureNotNullOrEmpty(keyStorePIN,
         "KeyStoreDataReplaceCertificateKeyStoreContent.keyStorePIN must " +
              "not be null or empty.");

    this.keyStoreData = keyStoreData;
    this.keyStorePIN = keyStorePIN;
    this.privateKeyPIN = privateKeyPIN;
    this.keyStoreType = keyStoreType;
    this.sourceCertificateAlias = sourceCertificateAlias;
  }



  /**
   * Creates a new instance of this key store content object with the provided
   * information.
   *
   * @param  keyStoreFile            The local (client-side) file from which the
   *                                 certificate data should be read.  It must
   *                                 not be {@code null}. and the file must
   *                                 exist.
   * @param  keyStorePIN             The PIN needed to access protected content
   *                                 in the key store.  It must not be
   *                                 {@code null} or empty.
   * @param  privateKeyPIN           The PIN needed to access private key
   *                                 information in the key store.  It may be
   *                                 {@code null} if the key store PIN should
   *                                 also be used as the private key PIN.
   * @param  keyStoreType            The key store type for the target key
   *                                 store.  If provided, its value will likely
   *                                 be one of JKS, PKCS12, or BCFKS.  If this
   *                                 is {@code null}, then the server will
   *                                 attempt to automatically determine the
   *                                 appropriate key store type.
   * @param  sourceCertificateAlias  The alias of the private key entry in the
   *                                 key store that contains the new certificate
   *                                 chain to be used.  It may optionally be
   *                                 {@code null} if and only if the key store
   *                                 has only a single private key entry.
   *
   * @throws  IOException  If a problem occurs while attempting to read from the
   *                       key store file.
   */
  public KeyStoreDataReplaceCertificateKeyStoreContent(
              @NotNull final File keyStoreFile,
              @NotNull final String keyStorePIN,
              @Nullable final String privateKeyPIN,
              @Nullable final String keyStoreType,
              @Nullable final String sourceCertificateAlias)
         throws IOException
  {
    this(StaticUtils.readFileBytes(keyStoreFile), keyStorePIN, privateKeyPIN,
         keyStoreType, sourceCertificateAlias);
  }



  /**
   * Retrieves the raw data that comprises the key store with the new
   * certificate to use.
   *
   * @return  The raw data that comprises the key store with the new certificate
   *          to use.
   */
  @NotNull()
  public byte[] getKeyStoreData()
  {
    return keyStoreData;
  }



  /**
   * Retrieves the PIN needed to access protected content in the key store.
   *
   * @return  The PIN needed to access protected content in the key store.
   */
  @NotNull()
  public String getKeyStorePIN()
  {
    return keyStorePIN;
  }



  /**
   * Retrieves the PIN needed to access private key information in the key
   * store, if available.
   *
   * @return  The PIN needed to access private key information in the key store,
   *          or {@code null} if the key store PIN should also be used as the
   *          private key PIN.
   */
  @Nullable()
  public String getPrivateKeyPIN()
  {
    return privateKeyPIN;
  }



  /**
   * Retrieves the key store type for the target key store, if available.
   *
   * @return  The key store type for the target key store, or {@code null} if
   *          the key store type is not available and the server should attempt
   *          to automatically determine the appropriate key store type.
   */
  @Nullable()
  public String getKeyStoreType()
  {
    return keyStoreType;
  }



  /**
   * Retrieves the alias of the private key entry in the key store that contains
   * the new certificate chain to be used, if available.
   *
   * @return  The alias of the private key entry in the key store that contains
   *          the new certificate chain to be used, or {@code null} if no source
   *          certificate alias was provided and the key store is expected to
   *          have only a single private key entry.
   */
  @Nullable()
  public String getSourceCertificateAlias()
  {
    return sourceCertificateAlias;
  }



  /**
   * Decodes a key store file replace certificate key store content object from
   * the provided ASN.1 element.
   *
   * @param  element  The ASN.1 element containing the encoded representation of
   *                  the key store file replace certificate key store content
   *                  object.  It must not be {@code null}.
   *
   * @return  The decoded key store content object.
   *
   * @throws  LDAPException  If the provided ASN.1 element cannot be decoded as
   *                         a key store file replace certificate key store
   *                         content object.
   */
  @NotNull()
  static KeyStoreDataReplaceCertificateKeyStoreContent decodeInternal(
              @NotNull final ASN1Element element)
         throws LDAPException
  {
    try
    {
      final ASN1Element[] elements = element.decodeAsSequence().elements();
      final byte[] keyStoreData =
           elements[0].decodeAsOctetString().getValue();
      final String keyStorePIN =
           elements[1].decodeAsOctetString().stringValue();

      String privateKeyPIN = null;
      String keyStoreType = null;
      String sourceCertificateAlias = null;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_PRIVATE_KEY_PIN:
            privateKeyPIN = elements[i].decodeAsOctetString().stringValue();
            break;
          case TYPE_KEY_STORE_TYPE:
            keyStoreType = elements[i].decodeAsOctetString().stringValue();
            break;
          case TYPE_SOURCE_CERTIFICATE_ALIAS:
            sourceCertificateAlias =
                 elements[i].decodeAsOctetString().stringValue();
            break;
        }
      }

      return new KeyStoreDataReplaceCertificateKeyStoreContent(keyStoreData,
           keyStorePIN, privateKeyPIN, keyStoreType, sourceCertificateAlias);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_KSD_KSC_DECODE_ERROR.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encode()
  {
    final List<ASN1Element> elements = new ArrayList<>(5);
    elements.add(new ASN1OctetString(TYPE_KEY_STORE_DATA, keyStoreData));
    elements.add(new ASN1OctetString(TYPE_KEY_STORE_PIN, keyStorePIN));

    if (privateKeyPIN != null)
    {
      elements.add(new ASN1OctetString(TYPE_PRIVATE_KEY_PIN, privateKeyPIN));
    }

    if (keyStoreType != null)
    {
      elements.add(new ASN1OctetString(TYPE_KEY_STORE_TYPE, keyStoreType));
    }

    if (sourceCertificateAlias != null)
    {
      elements.add(new ASN1OctetString(TYPE_SOURCE_CERTIFICATE_ALIAS,
           sourceCertificateAlias));
    }

    return new ASN1Sequence(TYPE_KEY_STORE_CONTENT, elements);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("KeyStoreDataReplaceCertificateKeyStoreContent(" +
         "keyStoreDataSizeBytes=");
    buffer.append(keyStoreData.length);
    buffer.append(", privateKeyPINProvided=");
    buffer.append(privateKeyPIN != null);

    if (keyStoreType != null)
    {
      buffer.append(", keyStoreType='");
      buffer.append(keyStoreType);
      buffer.append('\'');
    }

    if (sourceCertificateAlias != null)
    {
      buffer.append(", sourceCertificateAlias='");
      buffer.append(sourceCertificateAlias);
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
