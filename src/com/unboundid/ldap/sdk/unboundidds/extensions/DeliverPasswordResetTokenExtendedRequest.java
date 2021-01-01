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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedRequest;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that can be used
 * to trigger the delivery of a temporary one-time password reset token to a
 * specified user.  This token can be provided to the password modify extended
 * request in lieu of the current password for the purpose of performing a self
 * change and setting a new password.  This token cannot be used to authenticate
 * to the server in any other way, and it can only be used once.  The token will
 * expire after a short period of time, and any attempt to use it after its
 * expiration will fail.  In addition, because this token is only intended for
 * use in the event that the current password cannot be used (e.g., because it
 * has been forgotten or the account is locked), a successful bind with the
 * current password will cause the server to invalidate any password reset token
 * for that user.
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
 * The server will use the same mechanisms for delivering password reset tokens
 * as it uses for delivering one-time passwords via the
 * {@link DeliverOneTimePasswordExtendedRequest}.  See the
 * ds-supported-otp-delivery-mechanism attribute in the root DSE for a list of
 * the one-time password delivery mechanisms that are configured for use in the
 * server.
 * <BR><BR>
 * This extended request is expected to be used to help applications provide a
 * secure, automated password reset feature.  In the event that a user has
 * forgotten his/her password, has allowed the password to expire, or has
 * allowed the account to become locked, the application can collect a
 * sufficient set of information to identify the user and request that the
 * server generate and deliver the password reset token to the end user.
 * <BR><BR>
 * The OID for this extended request is 1.3.6.1.4.1.30221.2.6.45.  It must have
 * a value with the following encoding:
 * <PRE>
 *   DeliverPasswordResetTokenRequestValue ::= SEQUENCE {
 *        userDN                         LDAPDN,
 *        messageSubject                 [0] OCTET STRING OPTIONAL,
 *        fullTextBeforeToken            [1] OCTET STRING OPTIONAL,
 *        fullTextAfterToken             [2] OCTET STRING OPTIONAL,
 *        compactTextBeforeToken         [3] OCTET STRING OPTIONAL,
 *        compactTextAfterToken          [4] OCTET STRING OPTIONAL,
 *        preferredDeliveryMechanism     [5] SEQUENCE OF SEQUENCE {
 *             mechanismName     OCTET STRING,
 *             recipientID       OCTET STRING OPTIONAL },
 *        ... }
 * </PRE>
 *
 * @see  DeliverPasswordResetTokenExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DeliverPasswordResetTokenExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.45) for the deliver password reset token
   * extended request.
   */
  @NotNull public static final String DELIVER_PW_RESET_TOKEN_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.45";



  /**
   * The BER type for the "message subject" element of the value sequence.
   */
  private static final byte MESSAGE_SUBJECT_BER_TYPE = (byte) 0x80;



  /**
   * The BER type for the "full text before token" element of the value
   * sequence.
   */
  private static final byte FULL_TEXT_BEFORE_TOKEN_BER_TYPE = (byte) 0x81;



  /**
   * The BER type for the "full text after token" element of the value
   * sequence.
   */
  private static final byte FULL_TEXT_AFTER_TOKEN_BER_TYPE = (byte) 0x82;



  /**
   * The BER type for the "compact text before token" element of the value
   * sequence.
   */
  private static final byte COMPACT_TEXT_BEFORE_TOKEN_BER_TYPE = (byte) 0x83;



  /**
   * The BER type for the "compact text after token" element of the value
   * sequence.
   */
  private static final byte COMPACT_TEXT_AFTER_TOKEN_BER_TYPE = (byte) 0x84;



  /**
   * The BER type for the "preferred delivery mechanism" element of the value
   * sequence.
   */
  private static final byte PREFERRED_DELIVERY_MECHANISM_BER_TYPE = (byte) 0xA5;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7608072810737347230L;



  // An ordered list of the preferred delivery mechanisms for the token,
  // paired with an optional recipient ID for each mechanism.
  @NotNull private final List<ObjectPair<String, String>>
       preferredDeliveryMechanisms;

  // The text to include after the token in a compact message.
  @Nullable private final String compactTextAfterToken;

  // The text to include before the token in a compact message.
  @Nullable private final String compactTextBeforeToken;

  // The text to include after the token in a message without size constraints.
  @Nullable private final String fullTextAfterToken;

  // The text to include before the token in a message without size constraints.
  @Nullable private final String fullTextBeforeToken;

  // The text to use as the message subject.
  @Nullable private final String messageSubject;

  // The DN of the user to whom the password reset token should be delivered.
  @NotNull private final String userDN;



  /**
   * Creates a new deliver password reset token extended request with the
   * provided information.
   *
   * @param  userDN                       The DN of the user to whom the
   *                                      password reset token should be
   *                                      generated.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the token to the user.
   *                                      It may be {@code null} or empty to
   *                                      allow the server to select an
   *                                      appropriate delivery mechanism.  If it
   *                                      is non-{@code null} and non-empty,
   *                                      then only the listed mechanisms will
   *                                      be considered for use, even if the
   *                                      server supports alternate mechanisms
   *                                      not included in this list.
   */
  public DeliverPasswordResetTokenExtendedRequest(@NotNull final String userDN,
              @Nullable final String... preferredDeliveryMechanisms)
  {
    this(userDN, preferredMechanismsToList(preferredDeliveryMechanisms));
  }



  /**
   * Creates a new deliver password reset token extended request with the
   * provided information.
   *
   * @param  userDN                       The DN of the user to whom the
   *                                      password reset token should be
   *                                      generated.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the token to the user.
   *                                      It may be {@code null} or empty to
   *                                      allow the server to select an
   *                                      appropriate delivery mechanism.  If it
   *                                      is non-{@code null} and non-empty,
   *                                      then only the listed mechanisms will
   *                                      be considered for use, even if the
   *                                      server supports alternate mechanisms
   *                                      not included in this list.  Each
   *                                      {@code ObjectPair} item must have
   *                                      a non-{@code null} value for the first
   *                                      element, which is the name of the
   *                                      target delivery mechanism.  It may
   *                                      optionally have a non-{@code null}
   *                                      value for the second element, which is
   *                                      a recipient ID to use for that
   *                                      mechanism (e.g., the target  mobile
   *                                      phone number for SMS delivery, an
   *                                      email address for email delivery,
   *                                      etc.).  If no recipient ID is provided
   *                                      for a mechanism, then the server will
   *                                      attempt to select a value for the
   *                                      user.
   * @param  controls                     An optional set of controls to include
   *                                      in the request.  It may be
   *                                      {@code null} or empty if no controls
   *                                      should be included in the request.
   */
  public DeliverPasswordResetTokenExtendedRequest(@NotNull final String userDN,
       @Nullable final List<ObjectPair<String,String>>
            preferredDeliveryMechanisms,
       @Nullable final Control... controls)
  {
    this(userDN, null, null, null, null, null, preferredDeliveryMechanisms,
         controls);
  }



  /**
   * Creates a new deliver password reset token extended request with the
   * provided information.
   *
   * @param  userDN                       The DN of the user to whom the
   *                                      password reset token should be
   *                                      generated.
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeToken          The text (if any) that should appear
   *                                      before the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      does not impose significant
   *                                      constraints on message size.  This may
   *                                      be {@code null} if no text is required
   *                                      before the token.
   * @param  fullTextAfterToken           The text (if any) that should appear
   *                                      after the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      does not impose significant
   *                                      constraints on message size.  This may
   *                                      be {@code null} if no text is required
   *                                      after the token.
   * @param  compactTextBeforeToken       The text (if any) that should appear
   *                                      before the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      imposes significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the token.
   * @param  compactTextAfterToken        The text (if any) that should appear
   *                                      after the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      imposes significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the token.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the token to the user.
   *                                      It may be {@code null} or empty to
   *                                      allow the server to select an
   *                                      appropriate delivery mechanism.  If it
   *                                      is non-{@code null} and non-empty,
   *                                      then only the listed mechanisms will
   *                                      be considered for use, even if the
   *                                      server supports alternate mechanisms
   *                                      not included in this list.  Each
   *                                      {@code ObjectPair} item must have
   *                                      a non-{@code null} value for the first
   *                                      element, which is the name of the
   *                                      target delivery mechanism.  It may
   *                                      optionally have a non-{@code null}
   *                                      value for the second element, which is
   *                                      a recipient ID to use for that
   *                                      mechanism (e.g., the target  mobile
   *                                      phone number for SMS delivery, an
   *                                      email address for email delivery,
   *                                      etc.).  If no recipient ID is provided
   *                                      for a mechanism, then the server will
   *                                      attempt to select a value for the
   *                                      user.
   * @param  controls                     An optional set of controls to include
   *                                      in the request.  It may be
   *                                      {@code null} or empty if no controls
   *                                      should be included in the request.
   */
  public DeliverPasswordResetTokenExtendedRequest(@NotNull final String userDN,
       @Nullable final String messageSubject,
       @Nullable final String fullTextBeforeToken,
       @Nullable final String fullTextAfterToken,
       @Nullable final String compactTextBeforeToken,
       @Nullable final String compactTextAfterToken,
       @Nullable final List<ObjectPair<String,String>>
            preferredDeliveryMechanisms,
       @Nullable final Control... controls)
  {
    super(DELIVER_PW_RESET_TOKEN_REQUEST_OID,
         encodeValue(userDN, messageSubject, fullTextBeforeToken,
              fullTextAfterToken, compactTextBeforeToken, compactTextAfterToken,
              preferredDeliveryMechanisms), controls);

    this.userDN                 = userDN;
    this.messageSubject         = messageSubject;
    this.fullTextBeforeToken    = fullTextBeforeToken;
    this.fullTextAfterToken     = fullTextAfterToken;
    this.compactTextBeforeToken = compactTextBeforeToken;
    this.compactTextAfterToken  = compactTextAfterToken;

    if (preferredDeliveryMechanisms == null)
    {
      this.preferredDeliveryMechanisms = Collections.emptyList();
    }
    else
    {
      this.preferredDeliveryMechanisms = Collections.unmodifiableList(
           new ArrayList<>(preferredDeliveryMechanisms));
    }
  }



  /**
   * Creates a new deliver password reset token extended request that is decoded
   * from the provided extended request.
   *
   * @param  request  The generic extended request to decode as a deliver
   *                  password reset token request.  It must not be
   *                  {@code null}.
   *
   * @throws  LDAPException  If an unexpected problem occurs.
   */
  public DeliverPasswordResetTokenExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELIVER_PW_RESET_TOKEN_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

      String subject = null;
      String fullBefore = null;
      String fullAfter = null;
      String compactBefore = null;
      String compactAfter = null;
      final ArrayList<ObjectPair<String,String>> pdmList = new ArrayList<>(10);
      for (int i=1; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case MESSAGE_SUBJECT_BER_TYPE:
            subject =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case FULL_TEXT_BEFORE_TOKEN_BER_TYPE:
            fullBefore =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case FULL_TEXT_AFTER_TOKEN_BER_TYPE:
            fullAfter =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case COMPACT_TEXT_BEFORE_TOKEN_BER_TYPE:
            compactBefore =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case COMPACT_TEXT_AFTER_TOKEN_BER_TYPE:
            compactAfter =
                 ASN1OctetString.decodeAsOctetString(elements[i]).stringValue();
            break;

          case PREFERRED_DELIVERY_MECHANISM_BER_TYPE:
            final ASN1Element[] pdmElements =
                 ASN1Sequence.decodeAsSequence(elements[i]).elements();
            for (final ASN1Element e : pdmElements)
            {
              final ASN1Element[] mechElements =
                   ASN1Sequence.decodeAsSequence(e).elements();
              final String mech = ASN1OctetString.decodeAsOctetString(
                   mechElements[0]).stringValue();

              final String recipientID;
              if (mechElements.length > 1)
              {
                recipientID = ASN1OctetString.decodeAsOctetString(
                     mechElements[1]).stringValue();
              }
              else
              {
                recipientID = null;
              }

              pdmList.add(new ObjectPair<>(mech, recipientID));
            }
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DELIVER_PW_RESET_TOKEN_REQUEST_UNEXPECTED_TYPE.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      preferredDeliveryMechanisms = Collections.unmodifiableList(pdmList);
      messageSubject              = subject;
      fullTextBeforeToken         = fullBefore;
      fullTextAfterToken          = fullAfter;
      compactTextBeforeToken      = compactBefore;
      compactTextAfterToken       = compactAfter;
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
           ERR_DELIVER_PW_RESET_TOKEN_REQUEST_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided set of preferred delivery mechanisms into a form
   * acceptable to the constructor that expects an object pair.  All of the
   * recipient IDs will be {@code null}.
   *
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the token to the user.
   *                                      It may be {@code null} or empty to
   *                                      allow the server to select an
   *                                      appropriate delivery mechanism.  If it
   *                                      is non-{@code null} and non-empty,
   *                                      then only the listed mechanisms will
   *                                      be considered for use, even if the
   *                                      server supports alternate mechanisms
   *                                      not included in this list.
   *
   * @return  The resulting list of preferred delivery mechanisms with
   *          {@code null} recipient IDs.
   */
  @Nullable()
  private static List<ObjectPair<String,String>> preferredMechanismsToList(
                      @Nullable final String... preferredDeliveryMechanisms)
  {
    if (preferredDeliveryMechanisms == null)
    {
      return null;
    }

    final ArrayList<ObjectPair<String,String>> l =
         new ArrayList<>(preferredDeliveryMechanisms.length);
    for (final String s : preferredDeliveryMechanisms)
    {
      l.add(new ObjectPair<String,String>(s, null));
    }
    return l;
  }



  /**
   * Creates an ASN.1 octet string suitable for use as the value of this
   * extended request.
   *
   * @param  userDN                       The DN of the user to whom the
   *                                      password reset token should be
   *                                      generated.
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeToken          The text (if any) that should appear
   *                                      before the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      does not impose significant
   *                                      constraints on message size.  This may
   *                                      be {@code null} if no text is required
   *                                      before the token.
   * @param  fullTextAfterToken           The text (if any) that should appear
   *                                      after the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      does not impose significant
   *                                      constraints on message size.  This may
   *                                      be {@code null} if no text is required
   *                                      after the token.
   * @param  compactTextBeforeToken       The text (if any) that should appear
   *                                      before the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      imposes significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the token.
   * @param  compactTextAfterToken        The text (if any) that should appear
   *                                      after the generated password reset
   *                                      token in the message delivered to the
   *                                      user via a delivery mechanism that
   *                                      imposes significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the token.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the token to the user.
   *                                      It may be {@code null} or empty to
   *                                      allow the server to select an
   *                                      appropriate delivery mechanism.  If it
   *                                      is non-{@code null} and non-empty,
   *                                      then only the listed mechanisms will
   *                                      be considered for use, even if the
   *                                      server supports alternate mechanisms
   *                                      not included in this list.  Each
   *                                      {@code ObjectPair} item must have
   *                                      a non-{@code null} value for the first
   *                                      element, which is the name of the
   *                                      target delivery mechanism.  It may
   *                                      optionally have a non-{@code null}
   *                                      value for the second element, which is
   *                                      a recipient ID to use for that
   *                                      mechanism (e.g., the target  mobile
   *                                      phone number for SMS delivery, an
   *                                      email address for email delivery,
   *                                      etc.).  If no recipient ID is provided
   *                                      for a mechanism, then the server will
   *                                      attempt to select a value for the
   *                                      user.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String userDN,
       @Nullable final String messageSubject,
       @Nullable final String fullTextBeforeToken,
       @Nullable final String fullTextAfterToken,
       @Nullable final String compactTextBeforeToken,
       @Nullable final String compactTextAfterToken,
       @Nullable final List<ObjectPair<String,String>>
            preferredDeliveryMechanisms)
  {
    Validator.ensureNotNull(userDN);

    final ArrayList<ASN1Element> elements = new ArrayList<>(7);
    elements.add(new ASN1OctetString(userDN));

    if (messageSubject != null)
    {
      elements.add(new ASN1OctetString(MESSAGE_SUBJECT_BER_TYPE,
           messageSubject));
    }

    if (fullTextBeforeToken != null)
    {
      elements.add(new ASN1OctetString(FULL_TEXT_BEFORE_TOKEN_BER_TYPE,
           fullTextBeforeToken));
    }

    if (fullTextAfterToken != null)
    {
      elements.add(new ASN1OctetString(FULL_TEXT_AFTER_TOKEN_BER_TYPE,
           fullTextAfterToken));
    }

    if (compactTextBeforeToken != null)
    {
      elements.add(new ASN1OctetString(COMPACT_TEXT_BEFORE_TOKEN_BER_TYPE,
           compactTextBeforeToken));
    }

    if (compactTextAfterToken != null)
    {
      elements.add(new ASN1OctetString(COMPACT_TEXT_AFTER_TOKEN_BER_TYPE,
           compactTextAfterToken));
    }

    if ((preferredDeliveryMechanisms != null) &&
        (! preferredDeliveryMechanisms.isEmpty()))
    {
      final ArrayList<ASN1Element> pdmElements =
           new ArrayList<>(preferredDeliveryMechanisms.size());
      for (final ObjectPair<String,String> p : preferredDeliveryMechanisms)
      {
        if (p.getSecond() == null)
        {
          pdmElements.add(new ASN1Sequence(
               new ASN1OctetString(p.getFirst())));
        }
        else
        {
          pdmElements.add(new ASN1Sequence(
               new ASN1OctetString(p.getFirst()),
               new ASN1OctetString(p.getSecond())));
        }
      }

      elements.add(new ASN1Sequence(PREFERRED_DELIVERY_MECHANISM_BER_TYPE,
           pdmElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the DN of the user to whom the password reset token should be
   * delivered.
   *
   * @return  The DN of the user to whom the password reset token should be
   *          delivered.
   */
  @NotNull()
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * Retrieves the text (if any) that should be used as the message subject for
   * delivery mechanisms that can make use of a subject.
   *
   * @return  The text that should be used as the message subject for delivery
   *          mechanisms that can make use of a subject, or {@code null} if no
   *          subject should be used, or if the delivery mechanism should
   *          attempt to automatically determine a subject.
   */
  @Nullable()
  public String getMessageSubject()
  {
    return messageSubject;
  }



  /**
   * Retrieves the text (if any) that should appear before the single-use token
   * in the message delivered to the user via a mechanism that does not impose
   * significant constraints on message size.
   *
   * @return  The text that should appear before the single-use token in the
   *          message delivered to the user via a mechanism that does not impose
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text before the token.
   */
  @Nullable()
  public String getFullTextBeforeToken()
  {
    return fullTextBeforeToken;
  }



  /**
   * Retrieves the text (if any) that should appear after the single-use token
   * in the message delivered to the user via a mechanism that does not impose
   * significant constraints on message size.
   *
   * @return  The text that should appear after the single-use token in the
   *          message delivered to the user via a mechanism that does not impose
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text after the token.
   */
  @Nullable()
  public String getFullTextAfterToken()
  {
    return fullTextAfterToken;
  }



  /**
   * Retrieves the text (if any) that should appear before the single-use token
   * in the message delivered to the user via a mechanism that imposes
   * significant constraints on message size.
   *
   * @return  The text that should appear before the single-use token in the
   *          message delivered to the user via a mechanism that imposes
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text before the token.
   */
  @Nullable()
  public String getCompactTextBeforeToken()
  {
    return compactTextBeforeToken;
  }



  /**
   * Retrieves the text (if any) that should appear after the single-use token
   * in the message delivered to the user via a mechanism that imposes
   * significant constraints on message size.
   *
   * @return  The text that should appear after the single-use token in the
   *          message delivered to the user via a mechanism that imposes
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text after the token.
   */
  @Nullable()
  public String getCompactTextAfterToken()
  {
    return compactTextAfterToken;
  }



  /**
   * Retrieves an ordered list of the preferred delivery mechanisms that should
   * be used to provide the password reset token to the user, optionally paired
   * with a mechanism-specific recipient ID (e.g., a mobile phone number for SMS
   * delivery, or an email address for email delivery) that can be used in the
   * delivery.  If this list is non-empty, then the server will use the first
   * mechanism in the list that the server supports and is available for the
   * target user, and the server will only consider mechanisms in the provided
   * list even if the server supports alternate mechanisms that are not
   * included.  If this list is empty, then the server will attempt to select an
   * appropriate delivery mechanism for the user.
   *
   * @return  An ordered list of the preferred delivery mechanisms for the
   *          password reset token, or an empty list if none were provided.
   */
  @NotNull()
  public List<ObjectPair<String,String>> getPreferredDeliveryMechanisms()
  {
    return preferredDeliveryMechanisms;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DeliverPasswordResetTokenExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new DeliverPasswordResetTokenExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public DeliverPasswordResetTokenExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public DeliverPasswordResetTokenExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final DeliverPasswordResetTokenExtendedRequest r =
         new DeliverPasswordResetTokenExtendedRequest(userDN,
              messageSubject, fullTextBeforeToken, fullTextAfterToken,
              compactTextBeforeToken, compactTextAfterToken,
              preferredDeliveryMechanisms, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getExtendedRequestName()
  {
    return INFO_EXTENDED_REQUEST_NAME_DELIVER_PW_RESET_TOKEN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DeliverPasswordResetTokenExtendedRequest(userDN='");
    buffer.append(userDN);
    buffer.append('\'');

    if (messageSubject != null)
    {
      buffer.append(", messageSubject='");
      buffer.append(messageSubject);
      buffer.append('\'');
    }

    if (fullTextBeforeToken != null)
    {
      buffer.append(", fullTextBeforeToken='");
      buffer.append(fullTextBeforeToken);
      buffer.append('\'');
    }

    if (fullTextAfterToken != null)
    {
      buffer.append(", fullTextAfterToken='");
      buffer.append(fullTextAfterToken);
      buffer.append('\'');
    }

    if (compactTextBeforeToken != null)
    {
      buffer.append(", compactTextBeforeToken='");
      buffer.append(compactTextBeforeToken);
      buffer.append('\'');
    }

    if (compactTextAfterToken != null)
    {
      buffer.append(", compactTextAfterToken='");
      buffer.append(compactTextAfterToken);
      buffer.append('\'');
    }

    if (preferredDeliveryMechanisms != null)
    {
      buffer.append(", preferredDeliveryMechanisms={");

      final Iterator<ObjectPair<String,String>> iterator =
           preferredDeliveryMechanisms.iterator();
      while (iterator.hasNext())
      {
        final ObjectPair<String,String> p = iterator.next();
        buffer.append('\'');
        buffer.append(p.getFirst());
        if (p.getSecond() != null)
        {
          buffer.append('(');
          buffer.append(p.getSecond());
          buffer.append(')');
        }
        buffer.append('\'');
        if (iterator.hasNext())
        {
          buffer.append(',');
        }
      }
    }

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
