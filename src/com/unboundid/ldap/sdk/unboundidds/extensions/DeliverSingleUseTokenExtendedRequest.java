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

import com.unboundid.asn1.ASN1Boolean;
import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Long;
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
 * to trigger the delivery of a temporary single-use token to a specified user
 * via some out-of-band mechanism.  It can be used for security purposes
 * (e.g., as part of step-up authentication), for data validation purposes
 * (e.g., to verify that a user can receive e-mail messages at a given address
 * or SMS messages at a given phone number), or for other purposes in which it
 * could be useful to deliver and consume a token through some out-of-band
 * mechanism.
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
 * This extended request has an OID of "1.3.6.1.4.1.30221.2.6.49" and it must
 * have a value with the following encoding:
 * <PRE>
 *   DeliverSingleUseTokenRequestValue ::= SEQUENCE {
 *        userDN                         LDAPDN,
 *        tokenID                        OCTET STRING,
 *        validityDurationMillis         [0] INTEGER OPTIONAL,
 *        messageSubject                 [1] OCTET STRING OPTIONAL,
 *        fullTextBeforeToken            [2] OCTET STRING OPTIONAL,
 *        fullTextAfterToken             [3] OCTET STRING OPTIONAL,
 *        compactTextBeforeToken         [4] OCTET STRING OPTIONAL,
 *        compactTextAfterToken          [5] OCTET STRING OPTIONAL,
 *        preferredDeliveryMechanism     [6] SEQUENCE OF SEQUENCE {
 *             mechanismName     OCTET STRING,
 *             recipientID       OCTET STRING OPTIONAL },
 *        deliverIfPasswordExpired       [7] BOOLEAN DEFAULT FALSE,
 *        deliverIfAccountLocked         [8] BOOLEAN DEFAULT FALSE,
 *        deliverIfAccountDisabled       [9] BOOLEAN DEFAULT FALSE,
 *        deliverIfAccountExpired        [10] BOOLEAN DEFAULT FALSE,
 *        ... }
 * </PRE>
 *
 * @see  DeliverSingleUseTokenExtendedResult
 * @see  ConsumeSingleUseTokenExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DeliverSingleUseTokenExtendedRequest
     extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.49) for the deliver single-use token
   * extended request.
   */
  @NotNull public static final String DELIVER_SINGLE_USE_TOKEN_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.49";



  /**
   * The BER type for the "validity duration millis" element of the value
   * sequence.
   */
  private static final byte VALIDITY_DURATION_MILLIS_BER_TYPE = (byte) 0x80;



  /**
   * The BER type for the "message subject" element of the value sequence.
   */
  private static final byte MESSAGE_SUBJECT_BER_TYPE = (byte) 0x81;



  /**
   * The BER type for the "full text before token" element of the value
   * sequence.
   */
  private static final byte FULL_TEXT_BEFORE_TOKEN_BER_TYPE = (byte) 0x82;



  /**
   * The BER type for the "full text after token" element of the value
   * sequence.
   */
  private static final byte FULL_TEXT_AFTER_TOKEN_BER_TYPE = (byte) 0x83;



  /**
   * The BER type for the "compact text before token" element of the value
   * sequence.
   */
  private static final byte COMPACT_TEXT_BEFORE_TOKEN_BER_TYPE = (byte) 0x84;



  /**
   * The BER type for the "compact text after token" element of the value
   * sequence.
   */
  private static final byte COMPACT_TEXT_AFTER_TOKEN_BER_TYPE = (byte) 0x85;



  /**
   * The BER type for the "preferred delivery mechanism" element of the value
   * sequence.
   */
  private static final byte PREFERRED_DELIVERY_MECHANISM_BER_TYPE = (byte) 0xA6;



  /**
   * The BER type for the "deliver if password expired" element of the value
   * sequence.
   */
  private static final byte DELIVER_IF_PASSWORD_EXPIRED_TYPE = (byte) 0x87;



  /**
   * The BER type for the "deliver if account locked" element of the value
   * sequence.
   */
  private static final byte DELIVER_IF_ACCOUNT_LOCKED_TYPE = (byte) 0x88;



  /**
   * The BER type for the "deliver if account disabled" element of the value
   * sequence.
   */
  private static final byte DELIVER_IF_ACCOUNT_DISABLED_TYPE = (byte) 0x89;



  /**
   * The BER type for the "deliver if account expired" element of the value
   * sequence.
   */
  private static final byte DELIVER_IF_ACCOUNT_EXPIRED_TYPE = (byte) 0x8A;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4158226639899928825L;



  // Indicates whether the server should attempt to deliver the token if the
  // target user's account has been administratively disabled.
  private final boolean deliverIfAccountDisabled;

  // Indicates whether the server should attempt to deliver the token if the
  // target user's account has expired.
  private final boolean deliverIfAccountExpired;

  // Indicates whether the server should attempt to deliver the token if the
  // target user's account has been locked for some reason.
  private final boolean deliverIfAccountLocked;

  // Indicates whether the server should attempt to deliver the token if the
  // target user's password is expired.
  private final boolean deliverIfPasswordExpired;

  // An optional list of the preferred delivery mechanisms that should be used.
  @NotNull private final List<ObjectPair<String,String>>
       preferredDeliveryMechanisms;

  // The maximum length of time, in milliseconds, that the token should be
  // considered valid.
  @Nullable private final Long validityDurationMillis;

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

  // The identifier that will be used when consuming this token.
  @NotNull private final String tokenID;

  // The DN of the user for whom the token should be generated and delivered.
  @NotNull private final String userDN;



  /**
   * Creates a new deliver single-use token extended request with the provided
   * information.
   *
   * @param  userDN                       The DN of the user for whom the token
   *                                      should be generated and delivered.  It
   *                                      must not be {@code null}.
   * @param  tokenID                      An identifier for the token, which can
   *                                      differentiate between separate uses of
   *                                      this extended operation for different
   *                                      purposes.  This token ID should be
   *                                      provided in the request to consume the
   *                                      token that has been delivered.  It
   *                                      must not be {@code null}.
   * @param  validityDurationMillis       The maximum length of time in
   *                                      milliseconds that the generated token
   *                                      should be considered valid.  It may be
   *                                      {@code null} if the server should
   *                                      determine the token validity duration.
   *                                      If it is non-{@code null}, then the
   *                                      value must be greater than zero.
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeToken          The text (if any) that should appear
   *                                      before the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the token.
   * @param  fullTextAfterToken           The text (if any) that should appear
   *                                      after the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the token.
   * @param  compactTextBeforeToken       The text (if any) that should appear
   *                                      before the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required before the token.
   * @param  compactTextAfterToken        The text (if any) that should appear
   *                                      after the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required after the token.
   * @param  preferredDeliveryMechanisms  An optional list of the preferred
   *                                      delivery mechanisms that should be
   *                                      used to convey the token to the target
   *                                      user.  It may be {@code null} or empty
   *                                      if the server should determine the
   *                                      delivery mechanisms to attempt.  If
   *                                      a list of preferred delivery
   *                                      mechanisms is provided, the server
   *                                      will only attempt to deliver the token
   *                                      through these mechanisms, with
   *                                      attempts made in the order specified
   *                                      in this list.
   * @param  deliverIfPasswordExpired     Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      password is expired.
   * @param  deliverIfAccountLocked       Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      account is locked for some reason
   *                                      (e.g., too many failed authentication
   *                                      attempts, the account has been idle
   *                                      for too long, the user failed to
   *                                      change his/her password in a timely
   *                                      manner after an administrative reset,
   *                                      etc.).
   * @param  deliverIfAccountDisabled     Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      account has been disabled by an
   *                                      administrator.
   * @param  deliverIfAccountExpired      Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      account has expired.
   * @param  controls                     An optional set of controls to include
   *                                      in the request.  It may be
   *                                      {@code null} or empty if no controls
   *                                      are required.
   */
  public DeliverSingleUseTokenExtendedRequest(@NotNull final String userDN,
       @NotNull final String tokenID,
       @Nullable final Long validityDurationMillis,
       @Nullable final String messageSubject,
       @Nullable final String fullTextBeforeToken,
       @Nullable final String fullTextAfterToken,
       @Nullable final String compactTextBeforeToken,
       @Nullable final String compactTextAfterToken,
       @Nullable final List<ObjectPair<String,String>>
            preferredDeliveryMechanisms,
       final boolean deliverIfPasswordExpired,
       final boolean deliverIfAccountLocked,
       final boolean deliverIfAccountDisabled,
       final boolean deliverIfAccountExpired,
       @Nullable final Control... controls)
  {
    super(DELIVER_SINGLE_USE_TOKEN_REQUEST_OID,
         encodeValue(userDN, tokenID, validityDurationMillis, messageSubject,
              fullTextBeforeToken, fullTextAfterToken, compactTextBeforeToken,
              compactTextAfterToken, preferredDeliveryMechanisms,
              deliverIfPasswordExpired, deliverIfAccountLocked,
              deliverIfAccountDisabled, deliverIfAccountExpired),
         controls);

    this.userDN                   = userDN;
    this.tokenID                  = tokenID;
    this.validityDurationMillis   = validityDurationMillis;
    this.messageSubject           = messageSubject;
    this.fullTextBeforeToken      = fullTextBeforeToken;
    this.fullTextAfterToken       = fullTextAfterToken;
    this.compactTextBeforeToken   = compactTextBeforeToken;
    this.compactTextAfterToken    = compactTextAfterToken;
    this.deliverIfPasswordExpired = deliverIfPasswordExpired;
    this.deliverIfAccountLocked   = deliverIfAccountLocked;
    this.deliverIfAccountDisabled = deliverIfAccountDisabled;
    this.deliverIfAccountExpired  = deliverIfAccountExpired;

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
   * Decodes the provided extended request as a deliver single-use token
   * extended request.
   *
   * @param  request  The extended request to decode as a deliver single-use
   *                  token extended request.
   *
   * @throws  LDAPException  If the provided extended request cannot be decoded
   *                         as a deliver single-use token request.
   */
  public DeliverSingleUseTokenExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELIVER_SINGLE_USE_TOKEN_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();
      userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();
      tokenID = ASN1OctetString.decodeAsOctetString(elements[1]).stringValue();

      Long validityDuration = null;
      String subject = null;
      String fullBefore = null;
      String fullAfter = null;
      String compactBefore = null;
      String compactAfter = null;
      final ArrayList<ObjectPair<String,String>> pdmList = new ArrayList<>(10);
      boolean ifPasswordExpired = false;
      boolean ifAccountLocked = false;
      boolean ifAccountDisabled = false;
      boolean ifAccountExpired = false;
      for (int i=2; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case VALIDITY_DURATION_MILLIS_BER_TYPE:
            validityDuration = ASN1Long.decodeAsLong(elements[i]).longValue();
            break;

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
            for (final ASN1Element pdmElement :
                 ASN1Sequence.decodeAsSequence(elements[i]).elements())
            {
              final ASN1Element[] dmElements =
                   ASN1Sequence.decodeAsSequence(pdmElement).elements();
              final String name = ASN1OctetString.decodeAsOctetString(
                   dmElements[0]).stringValue();

              final String recipientID;
              if (dmElements.length > 1)
              {
                recipientID = ASN1OctetString.decodeAsOctetString(
                     dmElements[1]).stringValue();
              }
              else
              {
                recipientID = null;
              }
              pdmList.add(new ObjectPair<>(name, recipientID));
            }
            break;

          case DELIVER_IF_PASSWORD_EXPIRED_TYPE:
            ifPasswordExpired =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case DELIVER_IF_ACCOUNT_LOCKED_TYPE:
            ifAccountLocked =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case DELIVER_IF_ACCOUNT_DISABLED_TYPE:
            ifAccountDisabled =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          case DELIVER_IF_ACCOUNT_EXPIRED_TYPE:
            ifAccountExpired =
                 ASN1Boolean.decodeAsBoolean(elements[i]).booleanValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DELIVER_SINGLE_USE_TOKEN_REQUEST_UNKNOWN_ELEMENT.get(
                      StaticUtils.toHex(elements[i].getType())));
        }
      }

      validityDurationMillis      = validityDuration;
      messageSubject              = subject;
      fullTextBeforeToken         = fullBefore;
      fullTextAfterToken          = fullAfter;
      compactTextBeforeToken      = compactBefore;
      compactTextAfterToken       = compactAfter;
      preferredDeliveryMechanisms = Collections.unmodifiableList(pdmList);
      deliverIfPasswordExpired    = ifPasswordExpired;
      deliverIfAccountLocked      = ifAccountLocked;
      deliverIfAccountDisabled    = ifAccountDisabled;
      deliverIfAccountExpired     = ifAccountExpired;
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
           ERR_DELIVER_SINGLE_USE_TOKEN_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of the extended request.
   *
   * @param  userDN                       The DN of the user for whom the token
   *                                      should be generated and delivered.  It
   *                                      must not be {@code null}.
   * @param  tokenID                      An identifier for the token, which can
   *                                      differentiate between separate uses of
   *                                      this extended operation for different
   *                                      purposes.  This token ID should be
   *                                      provided in the request to consume the
   *                                      token that has been delivered.  It
   *                                      must not be {@code null}.
   * @param  validityDurationMillis       The maximum length of time in
   *                                      milliseconds that the generated token
   *                                      should be considered valid.  It may be
   *                                      {@code null} if the server should
   *                                      determine the token validity duration.
   *                                      If it is non-{@code null}, then the
   *                                      value must be greater than zero.
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeToken          The text (if any) that should appear
   *                                      before the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the token.
   * @param  fullTextAfterToken           The text (if any) that should appear
   *                                      after the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the token.
   * @param  compactTextBeforeToken       The text (if any) that should appear
   *                                      before the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required before the token.
   * @param  compactTextAfterToken        The text (if any) that should appear
   *                                      after the generated single-use token
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required after the token.
   * @param  preferredDeliveryMechanisms  An optional list of the preferred
   *                                      delivery mechanisms that should be
   *                                      used to convey the token to the target
   *                                      user.  It may be {@code null} or empty
   *                                      if the server should determine the
   *                                      delivery mechanisms to attempt.  If
   *                                      a list of preferred delivery
   *                                      mechanisms is provided, the server
   *                                      will only attempt to deliver the token
   *                                      through these mechanisms, with
   *                                      attempts made in the order specified
   *                                      in this list.
   * @param  deliverIfPasswordExpired     Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      password is expired.
   * @param  deliverIfAccountLocked       Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      account is locked for some reason
   *                                      (e.g., too many failed authentication
   *                                      attempts, the account has been idle
   *                                      for too long, the user failed to
   *                                      change his/her password in a timely
   *                                      manner after an administrative reset,
   *                                      etc.).
   * @param  deliverIfAccountDisabled     Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      account has been disabled by an
   *                                      administrator.
   * @param  deliverIfAccountExpired      Indicates whether to generate and
   *                                      deliver a token if the target user's
   *                                      account has expired.
   *
   * @return  An ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String userDN,
       @NotNull final String tokenID,
       @Nullable final Long validityDurationMillis,
       @Nullable final String messageSubject,
       @Nullable final String fullTextBeforeToken,
       @Nullable final String fullTextAfterToken,
       @Nullable final String compactTextBeforeToken,
       @Nullable final String compactTextAfterToken,
       @Nullable final List<ObjectPair<String,String>>
            preferredDeliveryMechanisms,
       final boolean deliverIfPasswordExpired,
       final boolean deliverIfAccountLocked,
       final boolean deliverIfAccountDisabled,
       final boolean deliverIfAccountExpired)
  {
    Validator.ensureNotNull(userDN);
    Validator.ensureNotNull(tokenID);

    if (validityDurationMillis != null)
    {
      Validator.ensureTrue(validityDurationMillis > 0L);
    }


    final ArrayList<ASN1Element> elements = new ArrayList<>(13);
    elements.add(new ASN1OctetString(userDN));
    elements.add(new ASN1OctetString(tokenID));

    if (validityDurationMillis != null)
    {
      elements.add(new ASN1Long(VALIDITY_DURATION_MILLIS_BER_TYPE,
           validityDurationMillis));
    }

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
        final ArrayList<ASN1Element> l = new ArrayList<>(2);
        l.add(new ASN1OctetString(p.getFirst()));
        if (p.getSecond() != null)
        {
          l.add(new ASN1OctetString(p.getSecond()));
        }
        pdmElements.add(new ASN1Sequence(l));
      }
      elements.add(new ASN1Sequence(PREFERRED_DELIVERY_MECHANISM_BER_TYPE,
           pdmElements));
    }

    if (deliverIfPasswordExpired)
    {
      elements.add(new ASN1Boolean(DELIVER_IF_PASSWORD_EXPIRED_TYPE, true));
    }

    if (deliverIfAccountLocked)
    {
      elements.add(new ASN1Boolean(DELIVER_IF_ACCOUNT_LOCKED_TYPE, true));
    }

    if (deliverIfAccountDisabled)
    {
      elements.add(new ASN1Boolean(DELIVER_IF_ACCOUNT_DISABLED_TYPE, true));
    }

    if (deliverIfAccountExpired)
    {
      elements.add(new ASN1Boolean(DELIVER_IF_ACCOUNT_EXPIRED_TYPE, true));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the DN of the user for whom the token should be generated and
   * delivered.
   *
   * @return  The DN of the user for whom the token should be generated and
   *          delivered.
   */
  @NotNull()
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * Retrieves an identifier for the token, which can differentiate between
   * separate uses of this extended operation for different purposes, and should
   * be provided when consuming the token via the
   * {@link ConsumeSingleUseTokenExtendedRequest}.
   *
   * @return  An identifier for the token.
   */
  @NotNull()
  public String getTokenID()
  {
    return tokenID;
  }



  /**
   * Retrieves the maximum length of time in milliseconds that the generated
   * token should be considered valid, if defined.  An attempt to consume the
   * token after this length of time has elapsed will fail.
   *
   * @return  The maximum length of time in milliseconds that the generated
   *          token should be considered valid, or {@code null} if the client
   *          did not specify a value and the token validity duration will be
   *          determined by the server.
   */
  @Nullable()
  public Long getValidityDurationMillis()
  {
    return validityDurationMillis;
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
   * Retrieves a list of the preferred delivery mechanisms that should be used
   * to provide the generated token to the target user.  If the returned list is
   * empty, then the server will attempt to determine which mechanism(s) to use
   * and in which order to try them.  If this list is not empty, then the server
   * will only attempt the specified mechanisms and in the order in which they
   * are listed.
   *
   * @return  A list of the preferred delivery mechanisms that should be used to
   *          provide the generated token to the target user, or an empty list
   *          if the server should determine the delivery mechanisms to attempt.
   */
  @NotNull()
  public List<ObjectPair<String,String>> getPreferredDeliveryMechanisms()
  {
    return preferredDeliveryMechanisms;
  }



  /**
   * Indicates whether to attempt to generate and deliver a token if the
   * target user's password is expired.
   *
   * @return  {@code true} if the server should attempt to deliver a token to a
   *          user with an expired password, or {@code false} if not.
   */
  public boolean deliverIfPasswordExpired()
  {
    return deliverIfPasswordExpired;
  }



  /**
   * Indicates whether to attempt to generate and deliver a token if the
   * target user's account is locked for some reason (e.g., because there have
   * been too many failed authentication attempts, because the account has been
   * idle for too long, or because the password was not changed soon enough
   * after an administrative reset).
   *
   * @return  {@code true} if the server should attempt to deliver a token to a
   *          user with a locked account, or {@code false} if not.
   */
  public boolean deliverIfAccountLocked()
  {
    return deliverIfAccountLocked;
  }



  /**
   * Indicates whether to attempt to generate and deliver a token if the
   * target user's account has been disabled by an administrator.
   *
   * @return  {@code true} if the server should attempt to deliver a token to a
   *          user with a disabled account, or {@code false} if not.
   */
  public boolean deliverIfAccountDisabled()
  {
    return deliverIfAccountDisabled;
  }



  /**
   * Indicates whether to attempt to generate and deliver a token if the
   * target user's account has expired.
   *
   * @return  {@code true} if the server should attempt to deliver a token to a
   *          user with an expired account, or {@code false} if not.
   */
  public boolean deliverIfAccountExpired()
  {
    return deliverIfAccountExpired;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DeliverSingleUseTokenExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new DeliverSingleUseTokenExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public DeliverSingleUseTokenExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  @NotNull()
  public DeliverSingleUseTokenExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final DeliverSingleUseTokenExtendedRequest r =
         new DeliverSingleUseTokenExtendedRequest(userDN, tokenID,
              validityDurationMillis, messageSubject, fullTextBeforeToken,
              fullTextAfterToken, compactTextBeforeToken, compactTextAfterToken,
              preferredDeliveryMechanisms, deliverIfPasswordExpired,
              deliverIfAccountLocked, deliverIfAccountDisabled,
              deliverIfAccountExpired, controls);
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
    return INFO_EXTENDED_REQUEST_NAME_DELIVER_SINGLE_USE_TOKEN.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DeliverSingleUseTokenExtendedRequest(userDN='");
    buffer.append(userDN);
    buffer.append("', tokenID='");
    buffer.append(tokenID);
    buffer.append('\'');

    if (validityDurationMillis != null)
    {
      buffer.append(", validityDurationMillis=");
      buffer.append(validityDurationMillis);
    }

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

    buffer.append(", deliverIfPasswordExpired=");
    buffer.append(deliverIfPasswordExpired);
    buffer.append(", deliverIfAccountLocked=");
    buffer.append(deliverIfAccountLocked);
    buffer.append(", deliverIfAccountDisabled=");
    buffer.append(deliverIfAccountDisabled);
    buffer.append(", deliverIfAccountExpired=");
    buffer.append(deliverIfAccountExpired);

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
