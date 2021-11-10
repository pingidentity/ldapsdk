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
 * product) replace its inter-server certificate.  The new certificate data may
 * be contained in a key store file on the server filesystem or included in the
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
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.69 and a value with
 * the following encoding:
 * <PRE>
 *   ReplaceInterServerCertificateValue ::= SEQUENCE {
 *     keyStoreContent                         CHOICE {
 *       keyStoreFile                            [0] KeyStoreFileSequence,
 *       keyStoreData                            [1] KeyStoreDataSequence,
 *       certificateData                         [2] CertificateDataSequence,
 *       ... },
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
public final class ReplaceInterServerCertificateExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.69) for the replace inter-server certificate
   * extended request.
   */
  @NotNull public static final String REPLACE_INTER_SERVER_CERT_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.69";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2244751901271649579L;



  // The object providing information about how the server should obtain the new
  // inter-server certificate data.
  @NotNull private final ReplaceCertificateKeyStoreContent keyStoreContent;



  /**
   * Creates a new replace inter-server certificate extended request with the
   * provided information.
   *
   * @param  keyStoreContent  An object with information about how the server
   *                          should obtain the new inter-server certificate
   *                          data.  It must not be {@code null}.
   * @param  requestControls  The set of controls to include in the extended
   *                          request.  It may be {@code null} or empty if no
   *                          request controls should be included.
   */
  public ReplaceInterServerCertificateExtendedRequest(
              @NotNull final ReplaceCertificateKeyStoreContent keyStoreContent,
              @Nullable final Control... requestControls)
  {
    super(REPLACE_INTER_SERVER_CERT_REQUEST_OID, encodeValue(keyStoreContent),
         requestControls);

    this.keyStoreContent = keyStoreContent;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the encoded value for a replace inter-server certificate extended
   * request.
   *
   * @param  keyStoreContent  An object with information about how the server
   *                          should obtain the new inter-server certificate
   *                          data.  It must not be {@code null}.
   *
   * @return  An ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
              @NotNull final ReplaceCertificateKeyStoreContent keyStoreContent)
  {
    Validator.ensureNotNullWithMessage(keyStoreContent,
         "ReplaceInterServerCertificateExtendedRequest.keyStoreContent must " +
              "not be null.");

    return new ASN1OctetString(
         new ASN1Sequence(keyStoreContent.encode()).encode());
  }



  /**
   * Creates a new replace inter-server certificate extended request that is
   * decoded from the provided generic extended request.
   *
   * @param  request  The generic extended request to be decoded as a replace
   *                  inter-server certificate extended request.  It must not be
   *                  {@code null}.
   *
   * @throws  LDAPException  If a problem occurs while attempting to decode the
   *                         provided extended request as a replace inter-server
   *                         certificate request.
   */
  public ReplaceInterServerCertificateExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_REPLACE_INTER_SERVER_CERT_REQ_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      keyStoreContent = ReplaceCertificateKeyStoreContent.decode(elements[0]);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
         ERR_REPLACE_INTER_SERVER_CERT_DECODE_ERROR.get(
              StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves an object with information about how the server should obtain the
   * new inter-server certificate data.
   *
   * @return  An object with information about how the server should obtain the
   *          new inter-server certificate data.
   */
  @NotNull()
  public ReplaceCertificateKeyStoreContent getKeyStoreContent()
  {
    return keyStoreContent;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_REPLACE_INTER_SERVER_CERT_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ReplaceInterServerCertificateExtendedRequest(oid='");
    buffer.append(getOID());
    buffer.append("', keyStoreContent=");
    keyStoreContent.toString(buffer);

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
