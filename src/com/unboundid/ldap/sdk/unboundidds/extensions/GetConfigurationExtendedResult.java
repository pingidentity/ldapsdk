/*
 * Copyright 2013-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2013-2021 Ping Identity Corporation
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
 * Copyright (C) 2013-2021 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.InputStream;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that can be used
 * to retrieve a version of the server configuration.
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
 * The OID for this extended result is 1.3.6.1.4.1.30221.2.6.29.  If the request
 * was processed successfully, then the response will have a value with the
 * following encoding:
 * <PRE>
 *   GetConfigurationResult ::= SEQUENCE {
 *        configurationType         [0] ENUMERATED {
 *             active       (0),
 *             baseline     (1),
 *             archived     (2),
 *             ... },
 *        fileName                  [1] OCTET STRING,
 *        configurationFileData     [2] OCTET STRING,
 *        ... }
 * </PRE>
 *
 * @see  GetConfigurationExtendedRequest
 * @see  ListConfigurationsExtendedRequest
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetConfigurationExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.29) for the get configuration extended
   * result.
   */
  @NotNull public static final String GET_CONFIG_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.29";



  /**
   * The BER type for the element holding the type of configuration that has
   * been returned.
   */
  private static final byte TYPE_CONFIG_TYPE = (byte) 0x80;



  /**
   * The BER type for the element holding the name of the configuration file
   * that has been returned.
   */
  private static final byte TYPE_FILE_NAME = (byte) 0x81;



  /**
   * The BER type for the element holding the raw LDIF data that comprises the
   * configuration file that has been returned.
   */
  private static final byte TYPE_FILE_DATA = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 6042324433827773678L;



  // The raw data for the configuration file that has been returned.
  @Nullable private final byte[] fileData;

  // The type of configuration that has been returned.
  @Nullable private final GetConfigurationType configurationType;

  // The name of the configuration file that has been returned.
  @Nullable private final String fileName;



  /**
   * Creates a new get configuration extended result from the provided generic
   * extended result.
   *
   * @param  result  The generic extended result to be decoded as a get
   *                 configuration extended result.
   *
   * @throws LDAPException  If the provided extended result cannot be parsed as
   *                         a valid get configuration extended result.
   */
  public GetConfigurationExtendedResult(@NotNull final ExtendedResult result)
       throws LDAPException
  {
    super(result);

    final ASN1OctetString value = result.getValue();
    if (value == null)
    {
      configurationType = null;
      fileName = null;
      fileData = null;
      return;
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      final int configType =
           ASN1Enumerated.decodeAsEnumerated(elements[0]).intValue();
      configurationType = GetConfigurationType.forIntValue(configType);
      if (configurationType == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GET_CONFIG_RESULT_INVALID_CONFIG_TYPE.get(configType));
      }

      fileName = ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();
      fileData = ASN1OctetString.decodeAsOctetString(elements[2]).getValue();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_CONFIG_RESULT_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new get configuration extended result with the provided
   * information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  configurationType  The type of configuration that has been
   *                            returned.
   * @param  fileName           The name of the configuration file that has been
   *                            returned.
   * @param  fileData           The raw data for the configuration file that has
   *                            been returned.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public GetConfigurationExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final GetConfigurationType configurationType,
              @Nullable final String fileName,
              @Nullable final byte[] fileData,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((configurationType == null) ? null : GET_CONFIG_RESULT_OID),
         encodeValue(configurationType, fileName, fileData), responseControls);

    this.configurationType = configurationType;
    this.fileName          = fileName;
    this.fileData          = fileData;
  }



  /**
   * Creates an ASN.1 octet string containing an encoded representation of the
   * value for a get configuration extended result with the provided
   * information.
   *
   * @param  configurationType  The type of configuration that has been
   *                            returned.
   * @param  fileName           The name of the configuration file that has been
   *                            returned.
   * @param  fileData           The raw data for the configuration file that has
   *                            been returned.
   *
   * @return  An ASN.1 octet string containing an encoded representation of the
   *          value for a get configuration extended result, or {@code null} if
   *          a result with the provided information should not have a value.
   */
  @Nullable()
  public static ASN1OctetString encodeValue(
                     @Nullable final GetConfigurationType configurationType,
                     @Nullable final String fileName,
                     @Nullable final byte[] fileData)
  {
    if (configurationType == null)
    {
      Validator.ensureTrue((fileName == null),
           "The configuration file name must be null if the configuration " +
                "type is null.");
      Validator.ensureTrue((fileData == null),
           "The configuration file data must be null if the configuration " +
                "type is null.");
      return null;
    }

    Validator.ensureTrue((fileName != null),
         "The configuration file name must not be null if the configuration " +
              "type is not null.");
    Validator.ensureTrue((fileData != null),
         "The configuration file data must not be null if the configuration " +
              "type is not null.");

    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Enumerated(TYPE_CONFIG_TYPE, configurationType.getIntValue()),
         new ASN1OctetString(TYPE_FILE_NAME, fileName),
         new ASN1OctetString(TYPE_FILE_DATA, fileData));
    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Retrieves the type of configuration that has been returned, if available.
   *
   * @return  The type of configuration that has been returned, or {@code null}
   *          if this is not available.
   */
  @Nullable()
  public GetConfigurationType getConfigurationType()
  {
    return configurationType;
  }



  /**
   * Retrieves the name of the configuration file that has been returned, if
   * available.
   *
   * @return  The name of the configuration file that has been returned, or
   *          {@code null} if this is not available.
   */
  @Nullable()
  public String getFileName()
  {
    return fileName;
  }



  /**
   * Retrieves the raw data for the configuration file that has been returned,
   * if available.
   *
   * @return  The raw data for the configuration file that has been returned,
   *          or {@code null} if this is not available.
   */
  @Nullable()
  public byte[] getFileData()
  {
    return fileData;
  }



  /**
   * Retrieves an input stream that may be used to read the file data that has
   * been returned, if available.
   *
   * @return  An input stream that may be used to read the file data that has
   *          been returned, or {@code null} if this is not available.
   */
  @Nullable()
  public InputStream getFileDataInputStream()
  {
    if (fileData == null)
    {
      return null;
    }
    else
    {
      return new ByteArrayInputStream(fileData);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_GET_CONFIG.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetConfigurationExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (configurationType != null)
    {
      buffer.append(", configType=");
      buffer.append(configurationType.name());
    }

    if (fileName != null)
    {
      buffer.append(", fileName='");
      buffer.append(fileName);
      buffer.append('\'');
    }

    if (fileData != null)
    {
      buffer.append(", fileLength=");
      buffer.append(fileData.length);
    }

    final String diagnosticMessage = getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      buffer.append(", diagnosticMessage='");
      buffer.append(diagnosticMessage);
      buffer.append('\'');
    }

    final String matchedDN = getMatchedDN();
    if (matchedDN != null)
    {
      buffer.append(", matchedDN='");
      buffer.append(matchedDN);
      buffer.append('\'');
    }

    final String[] referralURLs = getReferralURLs();
    if (referralURLs.length > 0)
    {
      buffer.append(", referralURLs={");
      for (int i=0; i < referralURLs.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append('\'');
        buffer.append(referralURLs[i]);
        buffer.append('\'');
      }
      buffer.append('}');
    }

    final Control[] responseControls = getResponseControls();
    if (responseControls.length > 0)
    {
      buffer.append(", responseControls={");
      for (int i=0; i < responseControls.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        buffer.append(responseControls[i]);
      }
      buffer.append('}');
    }

    buffer.append(')');
  }
}
