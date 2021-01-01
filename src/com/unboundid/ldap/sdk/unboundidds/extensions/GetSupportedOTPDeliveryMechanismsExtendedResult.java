/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that may be used
 * to provide information about which one-time password delivery mechanisms are
 * supported for a user.
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
 * If the request was processed successfully, then the extended result will have
 * an OID of 1.3.6.1.4.1.30221.2.6.48 and a value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   GetSupportedOTPDeliveryMechanismsResult ::= SEQUENCE OF SEQUENCE {
 *        deliveryMechanism     [0] OCTET STRING,
 *        isSupported           [1] BOOLEAN OPTIONAL,
 *        recipientID           [2] OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  GetSupportedOTPDeliveryMechanismsExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetSupportedOTPDeliveryMechanismsExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.48) for the get supported one-time password
   * delivery mechanisms extended result.
   */
  @NotNull public static final String
       GET_SUPPORTED_OTP_DELIVERY_MECHANISMS_RESULT_OID =
            "1.3.6.1.4.1.30221.2.6.48";



  /**
   * The BER type for the delivery mechanism element.
   */
  private static final byte TYPE_DELIVERY_MECHANISM = (byte) 0x80;



  /**
   * The BER type for the is supported element.
   */
  private static final byte TYPE_IS_SUPPORTED = (byte) 0x81;



  /**
   * The BER type for the recipient ID element.
   */
  private static final byte TYPE_RECIPIENT_ID = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1811121368502797059L;



  // The list of supported delivery mechanism information for this result.
  @NotNull private final List<SupportedOTPDeliveryMechanismInfo>
       deliveryMechanismInfo;



  /**
   * Decodes the provided extended result as a get supported OTP delivery
   * mechanisms result.
   *
   * @param  result  The extended result to decode as a get supported OTP
   *                 delivery mechanisms result.
   *
   * @throws  LDAPException  If the provided extended result cannot be decoded
   *                         as a get supported OTP delivery mechanisms result.
   */
  public GetSupportedOTPDeliveryMechanismsExtendedResult(
              @NotNull final ExtendedResult result)
         throws LDAPException
  {
    super(result);

    final ASN1OctetString value = result.getValue();
    if (value == null)
    {
      deliveryMechanismInfo = Collections.emptyList();
    }
    else
    {
      try
      {
        final ASN1Element[] elements =
             ASN1Sequence.decodeAsSequence(value.getValue()).elements();
        final ArrayList<SupportedOTPDeliveryMechanismInfo> mechInfo =
             new ArrayList<>(elements.length);
        for (final ASN1Element e : elements)
        {
          final ASN1Element[] infoElements =
               ASN1Sequence.decodeAsSequence(e).elements();
          final String name = ASN1OctetString.decodeAsOctetString(
               infoElements[0]).stringValue();

          Boolean isSupported = null;
          String recipientID = null;
          for (int i=1; i < infoElements.length; i++)
          {
            switch (infoElements[i].getType())
            {
              case TYPE_IS_SUPPORTED:
                isSupported = ASN1Boolean.decodeAsBoolean(
                     infoElements[i]).booleanValue();
                break;

              case TYPE_RECIPIENT_ID:
                recipientID = ASN1OctetString.decodeAsOctetString(
                     infoElements[i]).stringValue();
                break;

              default:
                throw new LDAPException(ResultCode.DECODING_ERROR,
                     ERR_GET_SUPPORTED_OTP_MECH_RESULT_UNKNOWN_ELEMENT.get(
                          StaticUtils.toHex(infoElements[i].getType())));
            }
          }

          mechInfo.add(new SupportedOTPDeliveryMechanismInfo(name, isSupported,
               recipientID));
        }

        deliveryMechanismInfo = Collections.unmodifiableList(mechInfo);
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
             ERR_GET_SUPPORTED_OTP_MECH_RESULT_CANNOT_DECODE.get(
                  StaticUtils.getExceptionMessage(e)),
             e);
      }
    }
  }



  /**
   * Creates a new get supported OTP delivery mechanisms extended result object
   * with the provided information.
   *
   * @param  messageID              The message ID for the LDAP message that is
   *                                associated with this LDAP result.
   * @param  resultCode             The result code from the response.  It must
   *                                not be {@code null}.
   * @param  diagnosticMessage      The diagnostic message from the response, if
   *                                available.
   * @param  matchedDN              The matched DN from the response, if
   *                                available.
   * @param  referralURLs           The set of referral URLs from the response,
   *                                if available.
   * @param  deliveryMechanismInfo  The set of supported delivery mechanism info
   *                                for the result, if appropriate.  It should
   *                                be {@code null} or empty for non-success
   *                                results.
   * @param  controls               The set of controls for the response.  It
   *                                may be {@code null} or empty if no controls
   *                                are needed.
   */
  public GetSupportedOTPDeliveryMechanismsExtendedResult(final int messageID,
       @NotNull final ResultCode resultCode,
       @Nullable final String diagnosticMessage,
       @Nullable final String matchedDN,
       @Nullable final String[] referralURLs,
       @Nullable final Collection<SupportedOTPDeliveryMechanismInfo>
            deliveryMechanismInfo,
       @Nullable final Control... controls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         (resultCode == ResultCode.SUCCESS ?
              GET_SUPPORTED_OTP_DELIVERY_MECHANISMS_RESULT_OID : null),
         encodeValue(resultCode, deliveryMechanismInfo), controls);

    if ((deliveryMechanismInfo == null) || deliveryMechanismInfo.isEmpty())
    {
      this.deliveryMechanismInfo = Collections.emptyList();
    }
    else
    {
      this.deliveryMechanismInfo = Collections.unmodifiableList(
           new ArrayList<>(deliveryMechanismInfo));
    }
  }



  /**
   * Encodes the provided information into an appropriate format for the value
   * of this extended operation.
   *
   * @param  resultCode             The result code from the response.  It must
   *                                not be {@code null}.
   * @param  deliveryMechanismInfo  The set of supported delivery mechanism info
   *                                for the result, if appropriate.  It should
   *                                be {@code null} or empty for non-success
   *                                results.
   *
   * @return  The ASN.1 octet string containing the encoded value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
               @NotNull final ResultCode resultCode,
               @Nullable final Collection<SupportedOTPDeliveryMechanismInfo>
                    deliveryMechanismInfo)

  {
    if (resultCode != ResultCode.SUCCESS)
    {
      return null;
    }

    if ((deliveryMechanismInfo == null) || deliveryMechanismInfo.isEmpty())
    {
      return new ASN1OctetString(new ASN1Sequence().encode());
    }

    final ArrayList<ASN1Element> elements =
         new ArrayList<>(deliveryMechanismInfo.size());
    for (final SupportedOTPDeliveryMechanismInfo i : deliveryMechanismInfo)
    {
      final ArrayList<ASN1Element> infoElements = new ArrayList<>(3);
      infoElements.add(new ASN1OctetString(TYPE_DELIVERY_MECHANISM,
           i.getDeliveryMechanism()));

      if (i.isSupported() != null)
      {
        infoElements.add(new ASN1Boolean(TYPE_IS_SUPPORTED, i.isSupported()));
      }

      if (i.getRecipientID() != null)
      {
        infoElements.add(new ASN1OctetString(TYPE_RECIPIENT_ID,
             i.getRecipientID()));
      }

      elements.add(new ASN1Sequence(infoElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves a list containing information about the OTP delivery mechanisms
   * supported by the server and which are available for use by the target user,
   * if available.  Note that it is possible for the same OTP delivery mechanism
   * to appear in the list multiple times if that mechanism is supported for the
   * user with multiple recipient IDs (e.g., if the server provides an "Email"
   * delivery mechanism and a user has multiple email addresses, then the list
   * may include a separate "Email" delivery mechanism info object for each
   * of the user's email addresses).
   *
   * @return  A list containing information about the OTP delivery mechanisms
   *          supported by the server and which are available for the target
   *          user, or an empty list if the server doesn't support any OTP
   *          delivery mechanisms or if the request was not processed
   *          successfully.
   */
  @NotNull()
  public List<SupportedOTPDeliveryMechanismInfo> getDeliveryMechanismInfo()
  {
    return deliveryMechanismInfo;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_GET_SUPPORTED_OTP_MECH_RES_NAME.get();
  }



  /**
   * Appends a string representation of this extended result to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which a string representation of this
   *                 extended result will be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetSupportedOTPDeliveryMechanismsExtendedResult(" +
         "resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    buffer.append("mechanismInfo={");
    final Iterator<SupportedOTPDeliveryMechanismInfo> mechIterator =
         deliveryMechanismInfo.iterator();
    while (mechIterator.hasNext())
    {
      mechIterator.next().toString(buffer);
      if (mechIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append('}');

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
