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



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
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
 * This class defines an extended request that may be used to request that a
 * Ping Identity Directory Server instance (or related Ping Identity server
 * product) replace its listener certificate.  The new certificate data may be
 * contained in a key store file on the server filesystem or included in the
 * extended request itself.
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
 * <BR>
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.68 and a value with
 * the following encoding:
 * <PRE>
 *   ReplaceListenerCertificateValue ::= SEQUENCE {
 *     keyStoreContent                         CHOICE {
 *       keyStoreFile                            [0]  KeyStoreFileSequence,
 *       keyStoreData                            [1]  KeyStoreDataSequence,
 *       certificateData                         [2]  CertificateDataSequence,
 *       ... },
 *    keyManagerProvider                       [3]  OCTET STRING,
 *    trustBehavior                            CHOICE {
 *      trustManagerProvider                     [4] OCTET STRING,
 *      useJVMDefaultTrustManagerProvider        [5] NULL,
 *      ... },
 *    targetCertificateAlias                   [6]  OCTET STRING OPTIONAL,
 *    reloadHTTPConnectionHandlerCertificates  [7]  BOOLEAN DEFAULT FALSE,
 *    skipCertificateValidation                [16] BOOLEAN DEFAULT FALSE,
 *    ... }
 *
 *   KeyStoreFileSequence ::= SEQUENCE {
 *     path                    [8]  OCTET STRING,
 *     keyStorePIN             [9]  OCTET STRING,
 *     privateKeyPIN           [10] OCTET STRING OPTIONAL,
 *     keyStoreType            [11] OCTET STRING OPTIONAL,
 *     sourceCertificateAlias  [12] OCTET STRING OPTIONAL,
 *     ... }
 *
 *   KeyStoreDataSequence ::= SEQUENCE {
 *     keyStoreData            [13] OCTET STRING,
 *     keyStorePIN             [9]  OCTET STRING,
 *     privateKeyPIN           [10]  OCTET STRING OPTIONAL,
 *     keyStoreType            [11] OCTET STRING OPTIONAL,
 *     sourceCertificateAlias  [12] OCTET STRING OPTIONAL,
 *     ... }
 *
 *   CertificateDataSequence ::= SEQUENCE {
 *     certificateChain  [14] SEQUENCE SIZE (1..MAX) OF OCTET STRING,
 *     privateKey        [15] OCTET STRING OPTIONAL,
 *     ... }
 * </PRE>
 * <BR><BR>
 * The server will return a generic extended result in response to this request,
 * with neither an OID nor a value.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReplaceListenerCertificateExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.68) for the replace listener certificate
   * extended request.
   */
  @NotNull public static final String REPLACE_LISTENER_CERT_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.68";



  /**
   * The BER type for the request value element that holds the name of the
   * file-based key manager provider in which the listener certificate should be
   * updated.
   */
  private static final byte TYPE_KEY_MANAGER_PROVIDER = (byte) 0x83;



  /**
   * The BER type for the request value element that holds the alias to use for
   * the new certificate chain in the key manager.
   */
  private static final byte TYPE_TARGET_CERT_ALIAS = (byte) 0x86;



  /**
   * The BER type for the request value element that indicates whether to
   * trigger a certificate reload in any configured HTTP connection handlers.
   */
  private static final byte TYPE_RELOAD_HTTP_CONNECTION_HANDLER_CERTS =
       (byte) 0x87;



  /**
   * The BER type for the request value element that indicates whether to
   * skip validation for the new certificate chain.
   */
  private static final byte TYPE_SKIP_CERT_VALIDATION = (byte) 0x90;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3947876247774857671L;



  // Indicates whether to trigger a certificate reload in any configured HTTP
  // connection handlers.
  private final boolean reloadHTTPConnectionHandlerCertificates;

  // Indicates whether to skip validation for the new certificate chain.
  private final boolean skipCertificateValidation;

  // The object providing information about how the server should obtain the new
  // listener certificate data.
  @NotNull private final ReplaceCertificateKeyStoreContent keyStoreContent;

  // The object providing information about how the server should handle
  // updating trust information for the new listener certificate.
  @NotNull private final ReplaceCertificateTrustBehavior trustBehavior;

  // The name of the file-based key manager provider with information about the
  // key store in which the new listener certificate should be stored.
  @NotNull private final String keyManagerProvider;

  // The name of the alias to use for the new listener certificate in the target
  // key store.
  @Nullable private final String targetCertificateAlias;



  /**
   * Creates a new replace listener certificate extended request with the
   * provided information.
   *
   * @param  keyStoreContent
   *              An object with information about how the server should obtain
   *              the new listener certificate data.  It must not be
   *              {@code null}.
   * @param  keyManagerProvider
   *              The name of the file-based key manager provider with
   *              information about the key store in which the new listener
   *              certificate should be stored.  It must not be {@code null}.
   * @param  trustBehavior
   *              An object with information about how the server should handle
   *              updating trust information for the new listener certificate.
   *              It must not be {@code null}.
   * @param  targetCertificateAlias
   *              The alias that should be used for the new listener certificate
   *              in the target key store.  It may be {@code null} if the server
   *              should use a default alias.
   * @param  reloadHTTPConnectionHandlerCertificates
   *              Indicates whether to trigger a certificate reload in any
   *              configured HTTP connection handlers after updating the
   *              listener certificate information.  While LDAP and JMX
   *              connection handlers will automatically start using the new
   *              listener certificate when negotiating new TLS sessions, HTTP
   *              connection handlers will only do so if they are explicitly
   *              told to reload certificate data.  However, there is a chance
   *              that this could potentially cause issues with resuming TLS
   *              sessions for HTTPS clients that were negotiated before the
   *              listener certificate was updated.
   * @param  skipCertificateValidation
   *              Indicates whether to skip validation for the new certificate
   *              chain.
   * @param  requestControls
   *              The set of controls to include in the extended request.  It
   *              may be {@code null} or empty if no request controls should be
   *              included.
   */
  public ReplaceListenerCertificateExtendedRequest(
              @NotNull final ReplaceCertificateKeyStoreContent keyStoreContent,
              @NotNull final String keyManagerProvider,
              @NotNull final ReplaceCertificateTrustBehavior trustBehavior,
              @Nullable final String targetCertificateAlias,
              final boolean reloadHTTPConnectionHandlerCertificates,
              final boolean skipCertificateValidation,
              @Nullable final Control... requestControls)
  {
    super(REPLACE_LISTENER_CERT_REQUEST_OID,
         encodeValue(keyStoreContent, keyManagerProvider, trustBehavior,
              targetCertificateAlias, reloadHTTPConnectionHandlerCertificates,
              skipCertificateValidation),
         requestControls);

    this.keyStoreContent = keyStoreContent;
    this.keyManagerProvider = keyManagerProvider;
    this.trustBehavior = trustBehavior;
    this.targetCertificateAlias = targetCertificateAlias;
    this.reloadHTTPConnectionHandlerCertificates =
         reloadHTTPConnectionHandlerCertificates;
    this.skipCertificateValidation = skipCertificateValidation;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the encoded value for a replace listener certificate extended
   * request.
   *
   * @param  keyStoreContent
   *              An object with information about how the server should obtain
   *              the new listener certificate data.  It must not be
   *              {@code null}.
   * @param  keyManagerProvider
   *              The name of the file-based key manager provider with
   *              information about the key store in which the new listener
   *              certificate should be stored.  It must not be {@code null}.
   * @param  trustBehavior
   *              An object with information about how the server should handle
   *              updating trust information for the new listener certificate.
   *              It must not be {@code null}.
   * @param  targetCertificateAlias
   *              The alias that should be used for the new listener certificate
   *              in the target key store.  It may be {@code null} if the server
   *              should use a default alias.
   * @param  reloadHTTPConnectionHandlerCertificates
   *              Indicates whether to trigger a certificate reload in any
   *              configured HTTP connection handlers after updating the
   *              listener certificate information.  While LDAP and JMX
   *              connection handlers will automatically start using the new
   *              listener certificate when negotiating new TLS sessions, HTTP
   *              connection handlers will only do so if they are explicitly
   *              told to reload certificate data.  However, there is a chance
   *              that this could potentially cause issues with resuming TLS
   *              sessions for HTTPS clients that were negotiated before the
   *              listener certificate was updated.
   * @param  skipCertificateValidation
   *              Indicates whether to skip validation for the new certificate
   *              chain.
   *
   * @return  An ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @NotNull final ReplaceCertificateKeyStoreContent keyStoreContent,
               @NotNull final String keyManagerProvider,
               @NotNull final ReplaceCertificateTrustBehavior trustBehavior,
               @Nullable final String targetCertificateAlias,
               final boolean reloadHTTPConnectionHandlerCertificates,
               final boolean skipCertificateValidation)
  {
    Validator.ensureNotNullWithMessage(keyStoreContent,
         "ReplaceListenerCertificateExtendedRequest.keyStoreContent must not " +
              "be null.");
    Validator.ensureNotNullOrEmpty(keyManagerProvider,
         "ReplaceListenerCertificateExtendedRequest.keyManagerProvider must " +
              "not be null or empty.");
    Validator.ensureNotNullWithMessage(trustBehavior,
         "ReplaceListenerCertificateExtendedRequest.trustBehavior must not " +
              "be null.");

    final List<ASN1Element> valueElements = new ArrayList<>(6);
    valueElements.add(keyStoreContent.encode());
    valueElements.add(new ASN1OctetString(TYPE_KEY_MANAGER_PROVIDER,
         keyManagerProvider));
    valueElements.add(trustBehavior.encode());

    if (targetCertificateAlias != null)
    {
      valueElements.add(new ASN1OctetString(TYPE_TARGET_CERT_ALIAS,
           targetCertificateAlias));
    }

    if (reloadHTTPConnectionHandlerCertificates)
    {
      valueElements.add(new ASN1Boolean(
           TYPE_RELOAD_HTTP_CONNECTION_HANDLER_CERTS, true));
    }

    if (skipCertificateValidation)
    {
      valueElements.add(new ASN1Boolean(TYPE_SKIP_CERT_VALIDATION, true));
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Creates a new replace listener certificate extended request that is decoded
   * from the provided generic extended request.
   *
   * @param  request  The generic extended request to be decoded as a replace
   *                  listener certificate extended request.  It must not be
   *                  {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended request as a replace listener
   *                         certificate request.
   */
  public ReplaceListenerCertificateExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_REPLACE_LISTENER_CERT_REQ_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      keyStoreContent = ReplaceCertificateKeyStoreContent.decode(elements[0]);
      keyManagerProvider =
           ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      trustBehavior = ReplaceCertificateTrustBehavior.decode(elements[2]);

      String targetAlias = null;
      boolean reloadHTTPCerts = false;
      boolean skipValidation = false;
      for (int i=3; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_TARGET_CERT_ALIAS:
            targetAlias = elements[i].decodeAsOctetString().stringValue();
            break;
          case TYPE_RELOAD_HTTP_CONNECTION_HANDLER_CERTS:
            reloadHTTPCerts = elements[i].decodeAsBoolean().booleanValue();
            break;
          case TYPE_SKIP_CERT_VALIDATION:
            skipValidation = elements[i].decodeAsBoolean().booleanValue();
            break;
        }
      }

      targetCertificateAlias = targetAlias;
      reloadHTTPConnectionHandlerCertificates = reloadHTTPCerts;
      skipCertificateValidation = skipValidation;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
         ERR_REPLACE_LISTENER_CERT_DECODE_ERROR.get(
              StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves an object with information about how the server should obtain the
   * new listener certificate data.
   *
   * @return  An object with information about how the server should obtain the
   *          new listener certificate data.
   */
  @NotNull()
  public ReplaceCertificateKeyStoreContent getKeyStoreContent()
  {
    return keyStoreContent;
  }



  /**
   * Retrieves the name of the file-based key manager provider with information
   * about the key store in which thew new listener certificate should be
   * stored.
   *
   * @return  The name of the file-based key manager provider with information
   *          about the key store in which the new listener certificate should
   *          be stored.
   */
  @NotNull()
  public String getKeyManagerProvider()
  {
    return keyManagerProvider;
  }



  /**
   * Retrieves an object with information about how the server should handle
   * updating trust information for the new listener certificate.
   *
   * @return  An object with information about how the server should handle
   *          updating trust information for the new listener certificate.
   */
  @NotNull()
  public ReplaceCertificateTrustBehavior getTrustBehavior()
  {
    return trustBehavior;
  }



  /**
   * Retrieves the alias that should be used for the new listener certificate in
   * the target key store, if provided.
   *
   * @return  The alias that should be used for the new listener certificate in
   *          the target key store, or {@code null} if the server should use a
   *          default alias.
   */
  @Nullable()
  public String getTargetCertificateAlias()
  {
    return targetCertificateAlias;
  }



  /**
   * Indicates whether to trigger a certificate reload in any configured HTTP
   * connection handlers after updating the listener certificate information.
   * While LDAP and JMX connection handlers will automatically start using the
   * new listener certificate when negotiating new TLS sessions, HTTP connection
   * handlers will only do so if they are explicitly told to reload certificate
   * data.  However, there is a chance that this could potentially cause issues
   * with resuming TLS sessions for HTTPS clients that were negotiated before
   * the listener certificate was updated.
   *
   * @return  {@code true} if the server should reload certificates in any
   *          configured HTTP connection handlers after updating the listener
   *          certificates information, or {@code false} if not.
   */
  public boolean reloadHTTPConnectionHandlerCertificates()
  {
    return reloadHTTPConnectionHandlerCertificates;
  }



  /**
   * Indicates whether the server should skip validation processing for the
   * new certificate chain.
   *
   * @return  {@code true} if the server should skip validation processing for
   *          the new certificate chain, or {@code false} if not.
   */
  public boolean skipCertificateValidation()
  {
    return skipCertificateValidation;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_REPLACE_LISTENER_CERT_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReplaceListenerCertificateExtendedRequest(oid='");
    buffer.append(getOID());
    buffer.append("', keyStoreContent=");
    keyStoreContent.toString(buffer);
    buffer.append(", keyManagerProvider='");
    buffer.append(keyManagerProvider);
    buffer.append("', trustBehavior=");
    trustBehavior.toString(buffer);

    if (targetCertificateAlias != null)
    {
      buffer.append(", targetCertificateAlias='");
      buffer.append(targetCertificateAlias);
      buffer.append('\'');
    }

    buffer.append(", reloadHTTPConnectionHandlerCertificates=");
    buffer.append(reloadHTTPConnectionHandlerCertificates);
    buffer.append(", skipCertificateValidation=");
    buffer.append(skipCertificateValidation);

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      buffer.append(", controls={");
      for (int i=0; i < controls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(controls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
