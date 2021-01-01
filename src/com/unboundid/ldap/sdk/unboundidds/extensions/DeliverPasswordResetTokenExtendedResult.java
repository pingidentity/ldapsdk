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
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended result that may be used
 * to provide information about the result of processing for a deliver password
 * reset token extended request.  If the token was delivered successfully, then
 * this result will include information about the mechanism through which the
 * token was delivered.
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
 * an OID of 1.3.6.1.4.1.30221.2.6.46 and a value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   DeliverPasswordResetTokenResult ::= SEQUENCE {
 *        deliveryMechanism     OCTET STRING,
 *        recipientID           [0] OCTET STRING OPTIONAL,
 *        message               [1] OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  DeliverPasswordResetTokenExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DeliverPasswordResetTokenExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.46) for the deliver password reset token
   * extended result.
   */
  @NotNull public static final String DELIVER_PW_RESET_TOKEN_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.46";



  /**
   * The BER type for the recipient ID element of the value sequence.
   */
  private static final byte RECIPIENT_ID_BER_TYPE = (byte) 0x80;



  /**
   * The BER type for the message element of the value sequence.
   */
  private static final byte DELIVERY_MESSAGE_BER_TYPE = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 576599499447071902L;



  // The name of the mechanism by which the password reset token was delivered.
  @Nullable private final String deliveryMechanism;

  // An message providing additional information about the delivery of the
  // password reset token.
  @Nullable private final String deliveryMessage;

  // An identifier for the recipient of the password reset token.
  @Nullable private final String recipientID;



  /**
   * Creates a new deliver password reset token extended result with the
   * provided information.
   *
   * @param  messageID          The message ID for the LDAP message that is
   *                            associated with this LDAP result.
   * @param  resultCode         The result code from the response.  It must not
   *                            be {@code null}.
   * @param  diagnosticMessage  The diagnostic message from the response, if
   *                            available.
   * @param  matchedDN          The matched DN from the response, if available.
   * @param  referralURLs       The set of referral URLs from the response, if
   *                            available.
   * @param  deliveryMechanism  The name of the mechanism by which the password
   *                            reset token was delivered, if available.  This
   *                            should be non-{@code null} for a success result.
   * @param  recipientID        An identifier for the user to whom the password
   *                            reset token was delivered.  It may be
   *                            {@code null} if no token was delivered or there
   *                            is no appropriate identifier, but if a value is
   *                            provided then it should appropriate for the
   *                            delivery mechanism (e.g., the user's e-mail
   *                            address if delivered via e-mail, a phone number
   *                            if delivered via SMS or voice call, etc.).
   * @param  deliveryMessage    An optional message providing additional
   *                            information about the password reset token
   *                            delivery, if available.  If this is
   *                            non-{@code null}, then the delivery mechanism
   *                            must also be non-null.
   * @param  responseControls   The set of controls for the response, if
   *                            available.
   */
  public DeliverPasswordResetTokenExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final String deliveryMechanism,
              @Nullable final String recipientID,
              @Nullable final String deliveryMessage,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((deliveryMechanism == null)
              ? null : DELIVER_PW_RESET_TOKEN_RESULT_OID),
         encodeValue(deliveryMechanism, recipientID, deliveryMessage),
         responseControls);

    this.deliveryMechanism = deliveryMechanism;
    this.recipientID       = recipientID;
    this.deliveryMessage   = deliveryMessage;
  }



  /**
   * Creates a new deliver password reset token result from the provided generic
   * extended result.
   *
   * @param  result  The generic extended result to be parsed as a deliver
   *                 password reset token result.
   *
   * @throws LDAPException  If the provided extended result cannot be parsed as
   *                         a deliver password reset token result.
   */
  public DeliverPasswordResetTokenExtendedResult(
              @NotNull final ExtendedResult result)
       throws LDAPException
  {
    super(result);

    final ASN1OctetString value = result.getValue();
    if (value == null)
    {
      deliveryMechanism = null;
      recipientID       = null;
      deliveryMessage   = null;
      return;
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      deliveryMechanism =
           ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      String id = null;
      String msg = null;
      for (int i=1; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case RECIPIENT_ID_BER_TYPE:
            id = ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case DELIVERY_MESSAGE_BER_TYPE:
            msg = ASN1OctetString.decodeAsOctetString(
                 elements[i]).stringValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DELIVER_PW_RESET_TOKEN_RESULT_UNEXPECTED_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      recipientID = id;
      deliveryMessage = msg;
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
           ERR_DELIVER_PW_RESET_TOKEN_RESULT_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended result.
   *
   * @param  deliveryMechanism  The name of the mechanism by which the password
   *                            reset token was delivered, if available.  This
   *                            should be non-{@code null} for a success result.
   * @param  recipientID        An identifier for the user to whom the password
   *                            reset token was delivered.  It may be
   *                            {@code null} if no token was delivered or there
   *                            is no appropriate identifier, but if a value is
   *                            provided then it should appropriate for the
   *                            delivery mechanism (e.g., the user's e-mail
   *                            address if delivered via e-mail, a phone number
   *                            if delivered via SMS or voice call, etc.).
   * @param  deliveryMessage    An optional message providing additional
   *                            information about the password reset token
   *                            delivery, if available.  If this is
   *                            non-{@code null}, then the delivery mechanism
   *                            must also be non-null.
   *
   * @return  An ASN.1 octet string containing the encoded value, or
   *          {@code null} if the extended result should not have a value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
               @Nullable final String deliveryMechanism,
               @Nullable final String recipientID,
               @Nullable final String deliveryMessage)
  {
    if (deliveryMechanism == null)
    {
      Validator.ensureTrue((recipientID == null),
           "The delivery mechanism must be non-null if the recipient ID " +
                "is non-null.");
      Validator.ensureTrue((deliveryMessage == null),
           "The delivery mechanism must be non-null if the delivery message " +
                "is non-null.");
      return null;
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    elements.add(new ASN1OctetString(deliveryMechanism));

    if (recipientID != null)
    {
      elements.add(new ASN1OctetString(RECIPIENT_ID_BER_TYPE, recipientID));
    }

    if (deliveryMessage != null)
    {
      elements.add(new ASN1OctetString(DELIVERY_MESSAGE_BER_TYPE,
           deliveryMessage));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the name of the mechanism by which the password reset token was
   * delivered to the user, if available.
   *
   * @return  The name of the mechanism by which the password reset token was
   *          delivered to the user, or {@code null} if this is not available.
   */
  @Nullable()
  public String getDeliveryMechanism()
  {
    return deliveryMechanism;
  }



  /**
   * Retrieves an identifier for the user to whom the password reset token was
   * delivered, if available.  If a recipient ID is provided, then it should be
   * in a form appropriate to the delivery mechanism (e.g., an e-mail address
   * if the token was delivered by e-mail, a phone number if it was delivered
   * by SMS or a voice call, etc.).
   *
   * @return  An identifier for the user to whom the password reset token was
   *          delivered, or {@code null} if this is not available.
   */
  @Nullable()
  public String getRecipientID()
  {
    return recipientID;
  }



  /**
   * Retrieves a message providing additional information about the password
   * reset token delivery, if available.
   *
   * @return  A message providing additional information about the password
   *          reset token delivery, or {@code null} if this is not available.
   */
  @Nullable()
  public String getDeliveryMessage()
  {
    return deliveryMessage;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getExtendedResultName()
  {
    return INFO_EXTENDED_RESULT_NAME_DELIVER_PW_RESET_TOKEN.get();
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
    buffer.append("DeliverPasswordResetTokenExtendedResult(resultCode=");
    buffer.append(getResultCode());

    final int messageID = getMessageID();
    if (messageID >= 0)
    {
      buffer.append(", messageID=");
      buffer.append(messageID);
    }

    if (deliveryMechanism != null)
    {
      buffer.append(", deliveryMechanism='");
      buffer.append(deliveryMechanism);
      buffer.append('\'');
    }

    if (recipientID != null)
    {
      buffer.append(", recipientID='");
      buffer.append(recipientID);
      buffer.append('\'');
    }

    if (deliveryMessage != null)
    {
      buffer.append(", deliveryMessage='");
      buffer.append(deliveryMessage);
      buffer.append('\'');
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
