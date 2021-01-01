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
 * to provide information about the result of processing for a deliver one-time
 * password extended request.  If the one-time password was delivered
 * successfully, then this result will include information about the mechanism
 * through which that message was delivered.
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
 * an OID of 1.3.6.1.4.1.30221.2.6.25 and a value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   DeliverOTPResult ::= SEQUENCE {
 *        deliveryMechanism     [0] OCTET STRING,
 *        recipientDN           [1] LDAPDN,
 *        recipientID           [2] OCTET STRING OPTIONAL,
 *        message               [3] OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  com.unboundid.ldap.sdk.unboundidds.UnboundIDDeliveredOTPBindRequest
 * @see  DeliverOneTimePasswordExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DeliverOneTimePasswordExtendedResult
       extends ExtendedResult
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.25) for the deliver one-time password
   * extended result.
   */
  @NotNull public static final String DELIVER_OTP_RESULT_OID =
       "1.3.6.1.4.1.30221.2.6.25";



  /**
   * The BER type for the delivery mechanism element.
   */
  private static final byte TYPE_MECH = (byte) 0x80;



  /**
   * The BER type for the recipient DN element.
   */
  private static final byte TYPE_RECIPIENT_DN = (byte) 0x81;



  /**
   * The BER type for the recipient ID element.
   */
  private static final byte TYPE_RECIPIENT_ID = (byte) 0x82;



  /**
   * The BER type for the delivery message element.
   */
  private static final byte TYPE_MESSAGE = (byte) 0x83;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5077693879184160485L;



  // The name of the mechanism by which the one-time password was delivered.
  @Nullable private final String deliveryMechanism;

  // An message providing additional information about the delivery of the
  // one-time password.
  @Nullable private final String deliveryMessage;

  // An the DN of the user to whom the one-time password was sent.
  @Nullable private final String recipientDN;

  // An identifier for the recipient of the one-time password.
  @Nullable private final String recipientID;



  /**
   * Creates a new deliver one-time password extended result from the provided
   * generic extended result.
   *
   * @param  extendedResult  The generic extended result to be parsed as a
   *                         deliver one-time password result.
   *
   * @throws LDAPException  If the provided extended result cannot be parsed as
   *                         a deliver one-time password result.
   */
  public DeliverOneTimePasswordExtendedResult(
              @NotNull final ExtendedResult extendedResult)
       throws LDAPException
  {
    super(extendedResult);

    final ASN1OctetString value = extendedResult.getValue();
    if (value == null)
    {
      deliveryMechanism = null;
      recipientDN = null;
      recipientID = null;
      deliveryMessage = null;
      return;
    }

    String mech = null;
    String dn = null;
    String id = null;
    String message = null;
    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_MECH:
            mech = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_RECIPIENT_DN:
            dn = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_RECIPIENT_ID:
            id = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_MESSAGE:
            message = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DELIVER_OTP_RES_UNEXPECTED_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }
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
           ERR_DELIVER_OTP_RES_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }


    if (mech == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELIVER_OTP_RES_NO_MECH.get());
    }
    else
    {
      deliveryMechanism = mech;
    }

    if (dn == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELIVER_OTP_RES_NO_RECIPIENT_DN.get());
    }
    else
    {
      recipientDN = dn;
    }

    recipientID = id;
    deliveryMessage = message;
  }



  /**
   * Creates a new deliver one-time password extended result with the provided
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
   * @param  deliveryMechanism  The name of the mechanism by which the one-time
   *                            password was delivered, if available.  This
   *                            should be non-{@code null} for a success result.
   * @param  recipientDN        The DN of the user to whom the one-time password
   *                            was sent.  This should be non-{@code null} for a
   *                            success result.
   * @param  recipientID        An identifier for the user to whom the one-time
   *                            password was delivered.  It may be {@code null}
   *                            if no password was delivered or there is no
   *                            appropriate identifier, but if a value is
   *                            provided then it should appropriate for the
   *                            delivery mechanism (e.g., the user's e-mail
   *                            address if delivered via e-mail, a phone number
   *                            if delivered via SMS or voice call, etc.).
   * @param  deliveryMessage    A message providing additional information about
   *                            the one-time password delivery, if available.
   *                            If this is non-{@code null}, then the delivery
   *                            mechanism must also be non-null.
   * @param  responseControls   The set of controls from the response, if
   *                            available.
   */
  public DeliverOneTimePasswordExtendedResult(final int messageID,
              @NotNull final ResultCode resultCode,
              @Nullable final String diagnosticMessage,
              @Nullable final String matchedDN,
              @Nullable final String[] referralURLs,
              @Nullable final String deliveryMechanism,
              @Nullable final String recipientDN,
              @Nullable final String recipientID,
              @Nullable final String deliveryMessage,
              @Nullable final Control... responseControls)
  {
    super(messageID, resultCode, diagnosticMessage, matchedDN, referralURLs,
         ((deliveryMechanism == null) ? null : DELIVER_OTP_RESULT_OID),
         encodeValue(deliveryMechanism, recipientDN, recipientID,
              deliveryMessage),
         responseControls);

    this.deliveryMechanism = deliveryMechanism;
    this.recipientDN       = recipientDN;
    this.recipientID       = recipientID;
    this.deliveryMessage   = deliveryMessage;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended result.
   *
   * @param  deliveryMechanism  The name of the mechanism by which the one-time
   *                            password was delivered, if available.  This
   *                            should be non-{@code null} for a success result.
   * @param  recipientDN        The DN of the user to whom the one-time password
   *                            was sent.  This should be non-{@code null} for a
   *                            success result.
   * @param  recipientID        An identifier for the user to whom the one-time
   *                            password was delivered.  It may be {@code null}
   *                            if no password was delivered or there is no
   *                            appropriate identifier, but if a value is
   *                            provided then it should appropriate for the
   *                            delivery mechanism (e.g., the user's e-mail
   *                            address if delivered via e-mail, a phone number
   *                            if delivered via SMS or voice call, etc.).
   * @param  deliveryMessage    A message providing additional information about
   *                            the one-time password delivery, if available.
   *                            If this is non-{@code null}, then the delivery
   *                            mechanism must also be non-null.
   *
   * @return  An ASN.1 octet string containing the encoded value, or
   *          {@code null} if the extended result should not have a value.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
               @Nullable final String deliveryMechanism,
               @Nullable final String recipientDN,
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

    Validator.ensureTrue((recipientDN != null),
         "If a delivery mechanism is provided, then a recipient DN must also " +
              "be provided.");

    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    elements.add(new ASN1OctetString(TYPE_MECH, deliveryMechanism));
    elements.add(new ASN1OctetString(TYPE_RECIPIENT_DN, recipientDN));

    if (recipientID != null)
    {
      elements.add(new ASN1OctetString(TYPE_RECIPIENT_ID, recipientID));
    }

    if (deliveryMessage != null)
    {
      elements.add(new ASN1OctetString(TYPE_MESSAGE, deliveryMessage));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the name of the mechanism by which the one-time password was
   * delivered to the end user, if available.
   *
   * @return  The name of the mechanism by which the one-time password was
   *          delivered to the end user, or {@code null} if this is not
   *          available.
   */
  @Nullable()
  public String getDeliveryMechanism()
  {
    return deliveryMechanism;
  }



  /**
   * Retrieves the DN of the user to whom the one-time password was delivered,
   * if available.
   *
   * @return  The DN of the user to whom the one-time password was delivered, or
   *          {@code null} if this is not available.
   */
  @Nullable()
  public String getRecipientDN()
  {
    return recipientDN;
  }



  /**
   * Retrieves an identifier for the user to whom the one-time password was
   * delivered, if available.  If a recipient ID is provided, then it should be
   * in a form appropriate to the delivery mechanism (e.g., an e-mail address
   * if the password was delivered by e-mail, a phone number if it was delivered
   * by SMS or a voice call, etc.).
   *
   * @return  An identifier for the user to whom the one-time password was
   *          delivered, or {@code null} if this is not available.
   */
  @Nullable()
  public String getRecipientID()
  {
    return recipientID;
  }



  /**
   * Retrieves a message providing additional information about the one-time
   * password delivery, if available.
   *
   * @return  A message providing additional information about the one-time
   *          password delivery, or {@code null} if this is not available.
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
  @NotNull()
  public String getExtendedResultName()
  {
    return INFO_DELIVER_OTP_RES_NAME.get();
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
    buffer.append("DeliverOneTimePasswordExtendedResult(resultCode=");
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

    if (recipientDN != null)
    {
      buffer.append(", recipientDN='");
      buffer.append(recipientDN);
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
