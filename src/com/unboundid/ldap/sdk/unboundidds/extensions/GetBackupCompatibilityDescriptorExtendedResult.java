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



import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
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
 * to retrieve backup compatibility data for a Directory Server backend.
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
 * The OID for this extended result is 1.3.6.1.4.1.30221.2.6.31.  If the request
 * was processed successfully, then the response will have a value with the
 * following encoding:
 * <PRE>
 *   GetBackupCompatibilityDescriptorResult ::= SEQUENCE {
 *        descriptor     [0] OCTET STRING,
 *        properties     [1] SEQUENCE OF OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  GetBackupCompatibilityDescriptorExtendedRequest
 * @see  IdentifyBackupCompatibilityProblemsExtendedRequest
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetBackupCompatibilityDescriptorExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.31) for the get backup compatibility
   * descriptor extended result.
   */
  @NotNull public static final String
       GET_BACKUP_COMPATIBILITY_DESCRIPTOR_RESULT_OID =
            "1.3.6.1.4.1.30221.2.6.31";



  /**
   * The BER type for the descriptor element in the value sequence.
   */
  private static final byte TYPE_DESCRIPTOR = (byte) 0x80;



  /**
   * The BER type for the properties element in the value sequence.
   */
  private static final byte TYPE_PROPERTIES = (byte) 0xA1;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2493658329210480765L;



  // The backup compatibility descriptor token.
  @Nullable private final ASN1OctetString descriptor;

  // A list of properties providing information about the backup compatibility
  // descriptor.
  @NotNull private final List<String> properties;



  /**
   * Creates a new get backup compatibility descriptor extended result from the
   * provided generic extended result.
   *
   * @param  result  The generic extended result to be decoded as a get backup
   *                 compatibility descriptor extended result.
   *
   * @throws LDAPException  If the provided extended result cannot be parsed as
   *                        a valid get backup compatibility descriptor
   *                        extended result.
   */
  public GetBackupCompatibilityDescriptorExtendedResult(
              @NotNull final ExtendedResult result)
         throws LDAPException
  {
    super(result);

    final ASN1OctetString value = result.getValue();
    if (value == null)
    {
      descriptor = null;
      properties = Collections.emptyList();
      return;
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      descriptor = elements[0].decodeAsOctetString();

      if (elements.length > 1)
      {
        final ASN1Element[] propElements =
             ASN1Sequence.decodeAsSequence(elements[1]).elements();
        final ArrayList<String> propList = new ArrayList<>(propElements.length);
        for (final ASN1Element e : propElements)
        {
          propList.add(ASN1OctetString.decodeAsOctetString(e).stringValue());
        }
        properties = Collections.unmodifiableList(propList);
      }
      else
      {
        properties = Collections.emptyList();
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_BACKUP_COMPAT_RESULT_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a new get backup compatibility descriptor extended result with the
   * provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  descriptor         The backup compatibility descriptor value.  It
   *                            may be {@code null} for an unsuccessful result.
   * @param  properties         A list of properties that provide information
   *                            about the way the descriptor may be used.  It
   *                            may be {@code null} or empty for an unsuccessful
   *                            result, or if there are no properties.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public GetBackupCompatibilityDescriptorExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final ASN1OctetString descriptor,
              @Nullable final Collection<String> properties,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((descriptor == null) ? null :
              GET_BACKUP_COMPATIBILITY_DESCRIPTOR_RESULT_OID),
         encodeValue(descriptor, properties), responseControls);

    if (descriptor == null)
    {
      this.descriptor = null;
    }
    else
    {
      this.descriptor =
           new ASN1OctetString(TYPE_DESCRIPTOR, descriptor.getValue());
    }

    if (properties == null)
    {
      this.properties = Collections.emptyList();
    }
    else
    {
      this.properties =
           Collections.unmodifiableList(new ArrayList<>(properties));
    }
  }



  /**
   * Creates an ASN.1 octet string containing an encoded representation of the
   * value for a get backup compatibility descriptor extended result with the
   * provided information.
   *
   * @param  descriptor  The backup compatibility descriptor value.  It may be
   *                     {@code null} for an unsuccessful result.
   * @param  properties  A list of properties that provide information about the
   *                     way the descriptor may be used.  It may be {@code null}
   *                     or empty for an unsuccessful result, or if there are no
   *                     properties.
   *
   * @return  An ASN.1 octet string containing an encoded representation of the
   *          value for a get backup compatibility descriptor extended result,
   *          or {@code null} if a result with the provided information should
   *          not have a value.
   */
  @Nullable()
  public static ASN1OctetString encodeValue(
              @Nullable final ASN1OctetString descriptor,
              @Nullable final Collection<String> properties)
  {
    if (descriptor == null)
    {
      Validator.ensureTrue(((properties == null) || properties.isEmpty()),
           "The properties must be null or empty if the descriptor is null.");
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(2);
    elements.add(new ASN1OctetString(TYPE_DESCRIPTOR, descriptor.getValue()));

    if ((properties != null) && (! properties.isEmpty()))
    {
      final ArrayList<ASN1Element> propElements =
           new ArrayList<>(properties.size());
      for (final String property : properties)
      {
        propElements.add(new ASN1OctetString(property));
      }
      elements.add(new ASN1Sequence(TYPE_PROPERTIES, propElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the backup compatibility descriptor value, if available.
   *
   * @return  The backup compatibility descriptor value, or {@code null} if none
   *          was provided.
   */
  @Nullable()
  public ASN1OctetString getDescriptor()
  {
    return descriptor;
  }



  /**
   * Retrieves a list of properties that provide information about the way the
   * descriptor may be used.
   *
   * @return  A list of properties that provide information about the way the
   *          descriptor may be used, or an empty list if no properties were
   *          provided.
   */
  @NotNull()
  public List<String> getProperties()
  {
    return properties;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_GET_BACKUP_COMPAT.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetBackupCompatibilityDescriptorExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (descriptor != null)
    {
      buffer.append(", descriptorLength=");
      buffer.append(descriptor.getValueLength());
    }

    if (! properties.isEmpty())
    {
      buffer.append(", descriptorProperties={");

      final Iterator<String> iterator = properties.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }

      buffer.append('}');
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
