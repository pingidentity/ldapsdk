/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.io.Serializable;
import java.util.Date;

import com.unboundid.ldap.sdk.unboundidds.logs.v2.LogField;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that contains information about a
 * JSON-formatted certificate.
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
public final class JSONCertificate
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -765694943228378726L;



  // The JSON object with an encoded representation of this certificate.
  @NotNull private final JSONObject certificateObject;

  // The ntoAfter time for this certificate.
  @Nullable private final Long notAfterTime;

  // The notBefore time for this certificate.
  @Nullable private final Long notBeforeTime;

  // The certificate type for this certificate.
  @Nullable private final String certificateType;

  // The issuer subject DN for this certificate.
  @Nullable private final String issuerSubjectDN;

  // The serial number for this certificate.
  @Nullable private final String serialNumber;

  // The signature algorithm for this certificate.
  @Nullable private final String signatureAlgorithm;

  // The subject DN for this certificate.
  @Nullable private final String subjectDN;



  /**
   * Creates a new JSON certificate that is decoded from the provided JSON
   * object.
   *
   * @param  certificateObject  The JSON object containing an encoded
   *                            representation of this certificate.
   */
  public JSONCertificate(@NotNull final JSONObject certificateObject)
  {
    this.certificateObject = certificateObject;

    subjectDN = certificateObject.getFieldAsString(
         JSONFormattedAccessLogFields.PEER_CERTIFICATE_CHAIN_SUBJECT_DN.
              getFieldName());
    issuerSubjectDN = certificateObject.getFieldAsString(
         JSONFormattedAccessLogFields.PEER_CERTIFICATE_CHAIN_ISSUER_SUBJECT_DN.
              getFieldName());
    certificateType = certificateObject.getFieldAsString(
         JSONFormattedAccessLogFields.PEER_CERTIFICATE_CHAIN_CERTIFICATE_TYPE.
              getFieldName());
    notBeforeTime = decodeTime(certificateObject,
         JSONFormattedAccessLogFields.PEER_CERTIFICATE_CHAIN_NOT_BEFORE);
    notAfterTime = decodeTime(certificateObject,
         JSONFormattedAccessLogFields.PEER_CERTIFICATE_CHAIN_NOT_AFTER);
    serialNumber = certificateObject.getFieldAsString(
         JSONFormattedAccessLogFields.PEER_CERTIFICATE_CHAIN_SERIAL_NUMBER.
              getFieldName());
    signatureAlgorithm = certificateObject.getFieldAsString(
         JSONFormattedAccessLogFields.
              PEER_CERTIFICATE_CHAIN_SIGNATURE_ALGORITHM.getFieldName());
  }



  /**
   * Decodes the time contained in the specified field of the given JSON object.
   *
   * @param  certificateObject  The JSON object containing an encoded
   *                            representation of this certificate.  It must not
   *                            be {@code null}.
   * @param  logField           The field containing the time value to decode.
   *                            It must not be {@code null}.
   *
   * @return  The decoded time, or {@code null} if the object did not contain
   *          the specified field or if its value could not be parsed as a
   *          timestamp in the ISO 8601 format described in RFC 3339.
   */
  @Nullable()
  private static Long decodeTime(@NotNull final JSONObject certificateObject,
                                 @NotNull final LogField logField)
  {
    final String timeString =
         certificateObject.getFieldAsString(logField.getFieldName());
    if (timeString == null)
    {
      return null;
    }

    try
    {
      return StaticUtils.decodeRFC3339Time(timeString).getTime();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves the JSON object containing an encoded representation of this
   * certificate.
   *
   * @return  The JSON object containing an encoded representation of this
   *          certificate.
   */
  @NotNull()
  public JSONObject getCertificateObject()
  {
    return certificateObject;
  }



  /**
   * Retrieves a string representation of the subject DN for this certificate.
   *
   * @return  A string representation of the subject DN for this certificate, or
   *          {@code null} if it is not included in the certificate object.
   */
  @Nullable()
  public String getSubjectDN()
  {
    return subjectDN;
  }



  /**
   * Retrieves a string representation of the subject DN of the issuer for this
   * certificate.
   *
   * @return  A string representation of the subject DN of the issuer for this
   *          certificate, or {@code null} if it is not included in the
   *          certificate object.
   */
  @Nullable()
  public String getIssuerSubjectDN()
  {
    return issuerSubjectDN;
  }



  /**
   * Retrieves the certificate type for this certificate.
   *
   * @return  The certificate type for this certificate, or {@code null} if it
   *          is not included in the certificate object.
   */
  @Nullable()
  public String getCertificateType()
  {
    return certificateType;
  }



  /**
   * Retrieves the notBefore time for this certificate.
   *
   * @return  The notBefore time for this certificate, or {@code null} if it is
   *          not included in the certificate object or if its value cannot be
   *          parsed.
   */
  @Nullable()
  public Date getNotBeforeTime()
  {
    if (notBeforeTime == null)
    {
      return null;
    }
    else
    {
      return new Date(notBeforeTime);
    }
  }



  /**
   * Retrieves the notAfter time for this certificate.
   *
   * @return  The notAfter time for this certificate, or {@code null} if it is
   *          not included in the certificate object or if its value cannot be
   *          parsed.
   */
  @Nullable()
  public Date getNotAfterTime()
  {
    if (notAfterTime == null)
    {
      return null;
    }
    else
    {
      return new Date(notAfterTime);
    }
  }



  /**
   * Retrieves a string representation of the serial number for this
   * certificate.
   *
   * @return  A string representation of the serial number for this certificate,
   *          or {@code null} if it is not included in the certificate object.
   */
  @Nullable()
  public String getSerialNumber()
  {
    return serialNumber;
  }



  /**
   * Retrieves the signature algorithm for this certificate.
   *
   * @return  The signature algorithm for this certificate, or {@code null} if
   *          it is not included in the certificate object.
   */
  @Nullable()
  public String getSignatureAlgorithm()
  {
    return signatureAlgorithm;
  }



  /**
   * Retrieves a string representation of this JSON certificate.
   *
   * @return  A string representation of this JSON certificate.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return certificateObject.toSingleLineString();
  }
}
