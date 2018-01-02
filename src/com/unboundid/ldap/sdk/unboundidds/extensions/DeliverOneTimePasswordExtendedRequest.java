/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
import java.util.LinkedHashSet;
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
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that may be used
 * to request that the Directory Server deliver a one-time password to an end
 * user that they may use to authenticate via an
 * {@link com.unboundid.ldap.sdk.unboundidds.UnboundIDDeliveredOTPBindRequest}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * Notes on the recommended use of this extended request:
 * <UL>
 *   <LI>Whenever possible, the user's static password should be provided.
 *       However, the server will allow the static password to be omitted if the
 *       authentication ID included in the request matches the authorization
 *       identity of the extended operation (either because that user is already
 *       authenticated on the connection, or because the request includes a
 *       proxied authorization or intermediate client control specifying that
 *       identity).  In that case, the operation will be able to act as a
 *       "step-up" mechanism, providing further proof of the identity of an
 *       already-authenticated client rather than performing the complete
 *       authentication process.</LI>
 *   <LI>The request offers two mechanisms for indicating which delivery
 *       mechanism(s) should be considered:  an option to specify just the
 *       delivery mechanism names, and an option to specify the names along with
 *       recipient IDs.  At most one of these elements must be present in the
 *       request.  If neither is present, the server will attempt to determine
 *       which delivery mechanisms and recipient IDs should be used.  If the
 *       set of preferred delivery mechanisms includes multiple items, the
 *       server will attempt them in the order provided until it is able to
 *       successfully deliver the message.  The server will not attempt to
 *       use any other delivery mechanisms that may be configured if the request
 *       includes a list of preferred delivery mechanisms.</LI>
 *   <LI>Although the message elements (message subject, and full and compact
 *       text before and after the OTP) are optional, it is recommended that
 *       they be supplied by the client.  The server will provide a generic
 *       message if no message elements are included in the request.</LI>
 * </UL>
 * <BR><BR>
 * The OID for this extended request is 1.3.6.1.4.1.30221.2.6.24.  It must have
 * a value, and that value should have the following encoding:
 * <BR><BR>
 * <PRE>
 *   DeliverOTPRequest ::= SEQUENCE {
 *        authenticationID             [0] OCTET STRING,
 *        staticPassword               [1] OCTET STRING OPTIONAL,
 *        preferredMechNames           [2] SEQUENCE OF OCTET STRING OPTIONAL,
 *        preferredMechNamesAndIDs     [3] SEQUENCE OF SEQUENCE,
 *             mechanismName     OCTET STRING,
 *             recipientID       OCTET STRING OPTIONAL } OPTIONAL,
 *        messageSubject               [4] OCTET STRING OPTIONAL,
 *        fullTextBeforeOTP            [5] OCTET STRING OPTIONAL,
 *        fullTextAfterOTP             [6] OCTET STRING OPTIONAL,
 *        compactTextBeforeOTP         [7] OCTET STRING OPTIONAL,
 *        compactTextAfterOTP          [8] OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 * @see  com.unboundid.ldap.sdk.unboundidds.UnboundIDDeliveredOTPBindRequest
 * @see  DeliverOneTimePasswordExtendedResult
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DeliverOneTimePasswordExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.24) for the deliver one-time password
   * extended request.
   */
  public static final String DELIVER_OTP_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.24";



  /**
   * The BER type for the authentication ID element.
   */
  private static final byte TYPE_AUTHN_ID = (byte) 0x80;



  /**
   * The BER type for the static password element.
   */
  private static final byte TYPE_PASSWORD = (byte) 0x81;



  /**
   * The BER type for the preferred delivery mechanism names element..
   */
  private static final byte TYPE_PREFERRED_DELIVERY_MECHANISM_NAMES =
       (byte) 0xA2;



  /**
   * The BER type for the preferred delivery mechanism names and IDs element..
   */
  private static final byte TYPE_PREFERRED_DELIVERY_MECHANISM_NAMES_AND_IDS =
       (byte) 0xA3;



  /**
   * The BER type for the "message subject" element of the value sequence.
   */
  private static final byte MESSAGE_SUBJECT_BER_TYPE = (byte) 0x84;



  /**
   * The BER type for the "full text before OTP" element of the value
   * sequence.
   */
  private static final byte FULL_TEXT_BEFORE_OTP_BER_TYPE = (byte) 0x85;



  /**
   * The BER type for the "full text after OTP" element of the value
   * sequence.
   */
  private static final byte FULL_TEXT_AFTER_OTP_BER_TYPE = (byte) 0x86;



  /**
   * The BER type for the "compact text before OTP" element of the value
   * sequence.
   */
  private static final byte COMPACT_TEXT_BEFORE_OTP_BER_TYPE = (byte) 0x87;



  /**
   * The BER type for the "compact text after OTP" element of the value
   * sequence.
   */
  private static final byte COMPACT_TEXT_AFTER_OTP_BER_TYPE = (byte) 0x88;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1259250969726758847L;



  // The static password to include in the request.
  private final ASN1OctetString staticPassword;

  // The list of preferred delivery mechanisms to include in the request.
  private final List<ObjectPair<String, String>> preferredDeliveryMechanisms;

  // The authentication ID to include in the request.
  private final String authenticationID;

  // The text to include after the OTP in a compact message.
  private final String compactTextAfterOTP;

  // The text to include before the OTP in a compact message.
  private final String compactTextBeforeOTP;

  // The text to include after the OTP in a message without size constraints.
  private final String fullTextAfterOTP;

  // The text to include before the OTP in a message without size constraints.
  private final String fullTextBeforeOTP;

  // The text to use as the message subject.
  private final String messageSubject;



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  preferredDeliveryMechanisms  The names of the preferred delivery
   *                                      mechanisms for the one-time password.
   *                                      It may be {@code null} or empty if the
   *                                      server should select an appropriate
   *                                      delivery mechanism.  If it is
   *                                      non-{@code null} and non-empty, then
   *                                      only the listed mechanisms will be
   *                                      considered for use, even if the server
   *                                      supports alternate mechanisms not
   *                                      included in this list.
   */
  public DeliverOneTimePasswordExtendedRequest(final String authenticationID,
              final String staticPassword,
              final String... preferredDeliveryMechanisms)
  {
    this(authenticationID, staticPassword,
         StaticUtils.toList(preferredDeliveryMechanisms));
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  preferredDeliveryMechanisms  The names of the preferred delivery
   *                                      mechanisms for the one-time password.
   *                                      It may be {@code null} or empty if the
   *                                      server should select an appropriate
   *                                      delivery mechanism.  If it is
   *                                      non-{@code null} and non-empty, then
   *                                      only the listed mechanisms will be
   *                                      considered for use, even if the server
   *                                      supports alternate mechanisms not
   *                                      included in this list.
   */
  public DeliverOneTimePasswordExtendedRequest(final String authenticationID,
              final byte[] staticPassword,
              final String... preferredDeliveryMechanisms)
  {
    this(authenticationID, staticPassword,
         StaticUtils.toList(preferredDeliveryMechanisms));
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  preferredDeliveryMechanisms  The names of the preferred delivery
   *                                      mechanisms for the one-time password.
   *                                      It may be {@code null} or empty if the
   *                                      server should select an appropriate
   *                                      delivery mechanism.  If it is
   *                                      non-{@code null} and non-empty, then
   *                                      only the listed mechanisms will be
   *                                      considered for use, even if the server
   *                                      supports alternate mechanisms not
   *                                      included in this list.
   * @param  controls                     The set of controls to include in the
   *                                      request.  It may be {@code null} or
   *                                      empty if no controls should be
   *                                      included.
   */
  public DeliverOneTimePasswordExtendedRequest(final String authenticationID,
              final String staticPassword,
              final List<String> preferredDeliveryMechanisms,
              final Control... controls)
  {
    this(authenticationID,
         (staticPassword == null
              ? null
              : new ASN1OctetString(TYPE_PASSWORD, staticPassword)),
         preferredDeliveryMechanisms, controls);
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  preferredDeliveryMechanisms  The names of the preferred delivery
   *                                      mechanisms for the one-time password.
   *                                      It may be {@code null} or empty if the
   *                                      server should select an appropriate
   *                                      delivery mechanism.  If it is
   *                                      non-{@code null} and non-empty, then
   *                                      only the listed mechanisms will be
   *                                      considered for use, even if the server
   *                                      supports alternate mechanisms not
   *                                      included in this list.
   * @param  controls                     The set of controls to include in the
   *                                      request.  It may be {@code null} or
   *                                      empty if no controls should be
   *                                      included.
   */
  public DeliverOneTimePasswordExtendedRequest(final String authenticationID,
              final byte[] staticPassword,
              final List<String> preferredDeliveryMechanisms,
              final Control... controls)
  {
    this(authenticationID,
         (staticPassword == null
              ? null
              : new ASN1OctetString(TYPE_PASSWORD, staticPassword)),
         preferredDeliveryMechanisms, controls);
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  preferredDeliveryMechanisms  The names of the preferred delivery
   *                                      mechanisms for the one-time password.
   *                                      It may be {@code null} or empty if the
   *                                      server should select an appropriate
   *                                      delivery mechanism.  If it is
   *                                      non-{@code null} and non-empty, then
   *                                      only the listed mechanisms will be
   *                                      considered for use, even if the server
   *                                      supports alternate mechanisms not
   *                                      included in this list.
   * @param  controls                     The set of controls to include in the
   *                                      request.  It may be {@code null} or
   *                                      empty if no controls should be
   *                                      included.
   */
  private DeliverOneTimePasswordExtendedRequest(final String authenticationID,
               final ASN1OctetString staticPassword,
               final List<String> preferredDeliveryMechanisms,
               final Control... controls)
  {
    super(DELIVER_OTP_REQUEST_OID,
         encodeValue(authenticationID, staticPassword,
              preferredDeliveryMechanisms),
         controls);

    this.authenticationID = authenticationID;
    this.staticPassword   = staticPassword;

    if ((preferredDeliveryMechanisms == null) ||
        preferredDeliveryMechanisms.isEmpty())
    {
      this.preferredDeliveryMechanisms = Collections.emptyList();
    }
    else
    {
      final ArrayList<ObjectPair<String,String>> l =
           new ArrayList<ObjectPair<String,String>>(
                preferredDeliveryMechanisms.size());
      for (final String s : preferredDeliveryMechanisms)
      {
        l.add(new ObjectPair<String,String>(s, null));
      }
      this.preferredDeliveryMechanisms = Collections.unmodifiableList(l);
    }

    messageSubject       = null;
    fullTextBeforeOTP    = null;
    fullTextAfterOTP     = null;
    compactTextBeforeOTP = null;
    compactTextAfterOTP  = null;
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeOTP            The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the one-time password.
   * @param  fullTextAfterOTP             The text (if any) that should appear
   *                                      after the one-time password in the
   *                                      message delivered to the user via a
   *                                      delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the one-time password.
   * @param  compactTextBeforeOTP         The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required before the one-time
   *                                      password.
   * @param  compactTextAfterOTP          The text (if any) that should appear
   *                                      after the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required after the one-time
   *                                      password.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the one-time password
   *                                      to the user.  It may be {@code null}
   *                                      or empty to allow the server to select
   *                                      an appropriate delivery mechanism.  If
   *                                      it is non-{@code null} and non-empty,
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
   * @param  controls                     The set of controls to include in the
   *                                      request.  It may be {@code null} or
   *                                      empty if no controls should be
   *                                      included.
   */
  public DeliverOneTimePasswordExtendedRequest(final String authenticationID,
       final String staticPassword, final String messageSubject,
       final String fullTextBeforeOTP, final String fullTextAfterOTP,
       final String compactTextBeforeOTP, final String compactTextAfterOTP,
       final List<ObjectPair<String,String>> preferredDeliveryMechanisms,
       final Control... controls)
  {
    this(authenticationID,
         (staticPassword == null
              ? null
              : new ASN1OctetString(TYPE_PASSWORD, staticPassword)),
         messageSubject, fullTextBeforeOTP, fullTextAfterOTP,
         compactTextBeforeOTP, compactTextAfterOTP, preferredDeliveryMechanisms,
         controls);
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeOTP            The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the one-time password.
   * @param  fullTextAfterOTP             The text (if any) that should appear
   *                                      after the one-time password in the
   *                                      message delivered to the user via a
   *                                      delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the one-time password.
   * @param  compactTextBeforeOTP         The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required before the one-time
   *                                      password.
   * @param  compactTextAfterOTP          The text (if any) that should appear
   *                                      after the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required after the one-time
   *                                      password.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the one-time password
   *                                      to the user.  It may be {@code null}
   *                                      or empty to allow the server to select
   *                                      an appropriate delivery mechanism.  If
   *                                      it is non-{@code null} and non-empty,
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
   * @param  controls                     The set of controls to include in the
   *                                      request.  It may be {@code null} or
   *                                      empty if no controls should be
   *                                      included.
   */
  public DeliverOneTimePasswordExtendedRequest(final String authenticationID,
       final byte[] staticPassword, final String messageSubject,
       final String fullTextBeforeOTP, final String fullTextAfterOTP,
       final String compactTextBeforeOTP, final String compactTextAfterOTP,
       final List<ObjectPair<String,String>> preferredDeliveryMechanisms,
       final Control... controls)
  {
    this(authenticationID,
         (staticPassword == null
              ? null
              : new ASN1OctetString(TYPE_PASSWORD, staticPassword)),
         messageSubject, fullTextBeforeOTP, fullTextAfterOTP,
         compactTextBeforeOTP, compactTextAfterOTP, preferredDeliveryMechanisms,
         controls);
  }



  /**
   * Creates a new deliver one-time password extended request with the provided
   * information.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeOTP            The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the one-time password.
   * @param  fullTextAfterOTP             The text (if any) that should appear
   *                                      after the one-time password in the
   *                                      message delivered to the user via a
   *                                      delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the one-time password.
   * @param  compactTextBeforeOTP         The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required before the one-time
   *                                      password.
   * @param  compactTextAfterOTP          The text (if any) that should appear
   *                                      after the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required after the one-time
   *                                      password.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the one-time password
   *                                      to the user.  It may be {@code null}
   *                                      or empty to allow the server to select
   *                                      an appropriate delivery mechanism.  If
   *                                      it is non-{@code null} and non-empty,
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
   * @param  controls                     The set of controls to include in the
   *                                      request.  It may be {@code null} or
   *                                      empty if no controls should be
   *                                      included.
   */
  private DeliverOneTimePasswordExtendedRequest(final String authenticationID,
       final ASN1OctetString staticPassword, final String messageSubject,
       final String fullTextBeforeOTP, final String fullTextAfterOTP,
       final String compactTextBeforeOTP, final String compactTextAfterOTP,
       final List<ObjectPair<String,String>> preferredDeliveryMechanisms,
       final Control... controls)
  {
    super(DELIVER_OTP_REQUEST_OID,
         encodeValue(authenticationID, staticPassword, messageSubject,
              fullTextBeforeOTP, fullTextAfterOTP, compactTextBeforeOTP,
              compactTextAfterOTP, preferredDeliveryMechanisms),
         controls);

    this.authenticationID     = authenticationID;
    this.staticPassword       = staticPassword;
    this.messageSubject       = messageSubject;
    this.fullTextBeforeOTP    = fullTextBeforeOTP;
    this.fullTextAfterOTP     = fullTextAfterOTP;
    this.compactTextBeforeOTP = compactTextBeforeOTP;
    this.compactTextAfterOTP  = compactTextAfterOTP;

    if ((preferredDeliveryMechanisms == null) ||
        preferredDeliveryMechanisms.isEmpty())
    {
      this.preferredDeliveryMechanisms = Collections.emptyList();
    }
    else
    {
      this.preferredDeliveryMechanisms =
           Collections.unmodifiableList(preferredDeliveryMechanisms);
    }
  }



  /**
   * Creates a new deliver one-time password extended request from the
   * information contained in the provided generic extended request.
   *
   * @param  request  The generic extended request to be decoded as a deliver
   *                  one-time password extended request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided generic extended request as a
   *                         deliver one-time password extended request.
   */
  public DeliverOneTimePasswordExtendedRequest(final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    // The request must have a value.
    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELIVER_OTP_REQ_NO_VALUE.get());
    }


    //  Parse the value.
    ASN1OctetString password = null;
    String authnID = null;
    String subject = null;
    String fullBefore = null;
    String fullAfter = null;
    String compactBefore = null;
    String compactAfter = null;
    final ArrayList<ObjectPair<String,String>> pdmList =
         new ArrayList<ObjectPair<String,String>>(10);
    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_AUTHN_ID:
            authnID = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case TYPE_PASSWORD:
            password = ASN1OctetString.decodeAsOctetString(e);
            break;

          case TYPE_PREFERRED_DELIVERY_MECHANISM_NAMES:
            final ASN1Element[] mechNameElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            for (final ASN1Element mechElement : mechNameElements)
            {
              pdmList.add(new ObjectPair<String, String>(
                   ASN1OctetString.decodeAsOctetString(mechElement).
                        stringValue(),
                   null));
            }
            break;

          case TYPE_PREFERRED_DELIVERY_MECHANISM_NAMES_AND_IDS:
            final ASN1Element[] pdmElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            for (final ASN1Element pdmElement : pdmElements)
            {
              final ASN1Element[] mechElements =
                   ASN1Sequence.decodeAsSequence(pdmElement).elements();
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

              pdmList.add(new ObjectPair<String,String>(mech, recipientID));
            }
            break;

          case MESSAGE_SUBJECT_BER_TYPE:
            subject =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case FULL_TEXT_BEFORE_OTP_BER_TYPE:
            fullBefore =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case FULL_TEXT_AFTER_OTP_BER_TYPE:
            fullAfter =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case COMPACT_TEXT_BEFORE_OTP_BER_TYPE:
            compactBefore =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          case COMPACT_TEXT_AFTER_OTP_BER_TYPE:
            compactAfter =
                 ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DELIVER_OTP_REQ_UNEXPECTED_ELEMENT_TYPE.get(
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
           ERR_DELIVER_OTP_REQ_ERROR_PARSING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (authnID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DELIVER_OTP_REQ_NO_AUTHN_ID.get());
    }
    else
    {
      authenticationID = authnID;
    }

    staticPassword       = password;
    messageSubject       = subject;
    fullTextBeforeOTP    = fullBefore;
    fullTextAfterOTP     = fullAfter;
    compactTextBeforeOTP = compactBefore;
    compactTextAfterOTP  = compactAfter;

    if ((pdmList == null) || pdmList.isEmpty())
    {
      preferredDeliveryMechanisms = Collections.emptyList();
    }
    else
    {
      preferredDeliveryMechanisms = Collections.unmodifiableList(pdmList);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.
   * @param  preferredDeliveryMechanisms  The names of the preferred delivery
   *                                      mechanisms for the one-time password.
   *                                      It may be {@code null} or empty if the
   *                                      server should select an appropriate
   *                                      delivery mechanism.  If it is
   *                                      non-{@code null} and non-empty, then
   *                                      only the listed mechanisms will be
   *                                      considered for use, even if the server
   *                                      supports alternate mechanisms not
   *                                      included in this list.
   *
   * @return  An ASN.1 octet string suitable for use as the value of this
   *          extended request.
   */
  private static ASN1OctetString encodeValue(final String authenticationID,
                      final ASN1OctetString staticPassword,
                      final List<String> preferredDeliveryMechanisms)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(3);

    elements.add(new ASN1OctetString(TYPE_AUTHN_ID, authenticationID));

    if (staticPassword != null)
    {
      elements.add(staticPassword);
    }

    if ((preferredDeliveryMechanisms != null) &&
        (! preferredDeliveryMechanisms.isEmpty()))
    {
      final ArrayList<ASN1Element> dmElements =
           new ArrayList<ASN1Element>(preferredDeliveryMechanisms.size());
      for (final String s : preferredDeliveryMechanisms)
      {
        dmElements.add(new ASN1OctetString(s));
      }
      elements.add(new ASN1Sequence(TYPE_PREFERRED_DELIVERY_MECHANISM_NAMES,
           dmElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  authenticationID             The authentication ID for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It must not be
   *                                      {@code null}.
   * @param  staticPassword               The static password for the user to
   *                                      whom the one-time password should be
   *                                      delivered.  It may be {@code null} if
   *                                      this request is intended to be used
   *                                      to step-up an existing authentication
   *                                      rather than perform a new
   *                                      authentication (in which case the
   *                                      provided authentication ID must match
   *                                      the operation's authorization ID).
   * @param  messageSubject               The text (if any) that should be used
   *                                      as the message subject if the delivery
   *                                      mechanism accepts a subject.  This may
   *                                      be {@code null} if no subject is
   *                                      required or a subject should be
   *                                      automatically generated.
   * @param  fullTextBeforeOTP            The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      before the one-time password.
   * @param  fullTextAfterOTP             The text (if any) that should appear
   *                                      after the one-time password in the
   *                                      message delivered to the user via a
   *                                      delivery mechanism that does not
   *                                      impose significant constraints on
   *                                      message size.  This may be
   *                                      {@code null} if no text is required
   *                                      after the one-time password.
   * @param  compactTextBeforeOTP         The text (if any) that should appear
   *                                      before the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required before the one-time
   *                                      password.
   * @param  compactTextAfterOTP          The text (if any) that should appear
   *                                      after the generated one-time password
   *                                      in the message delivered to the user
   *                                      via a delivery mechanism that imposes
   *                                      significant constraints on message
   *                                      size.  This may be {@code null} if no
   *                                      text is required after the one-time
   *                                      password.
   * @param  preferredDeliveryMechanisms  An optional ordered list of preferred
   *                                      delivery mechanisms that should be
   *                                      used to deliver the one-time password
   *                                      to the user.  It may be {@code null}
   *                                      or empty to allow the server to select
   *                                      an appropriate delivery mechanism.  If
   *                                      it is non-{@code null} and non-empty,
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
   * @return  An ASN.1 octet string suitable for use as the value of this
   *          extended request.
   */
  private static ASN1OctetString encodeValue(final String authenticationID,
       final ASN1OctetString staticPassword, final String messageSubject,
       final String fullTextBeforeOTP, final String fullTextAfterOTP,
       final String compactTextBeforeOTP, final String compactTextAfterOTP,
       final List<ObjectPair<String,String>> preferredDeliveryMechanisms)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<ASN1Element>(8);

    elements.add(new ASN1OctetString(TYPE_AUTHN_ID, authenticationID));

    if (staticPassword != null)
    {
      elements.add(staticPassword);
    }

    if (messageSubject != null)
    {
      elements.add(new ASN1OctetString(MESSAGE_SUBJECT_BER_TYPE,
           messageSubject));
    }

    if (fullTextBeforeOTP != null)
    {
      elements.add(new ASN1OctetString(FULL_TEXT_BEFORE_OTP_BER_TYPE,
           fullTextBeforeOTP));
    }

    if (fullTextAfterOTP != null)
    {
      elements.add(new ASN1OctetString(FULL_TEXT_AFTER_OTP_BER_TYPE,
           fullTextAfterOTP));
    }

    if (compactTextBeforeOTP != null)
    {
      elements.add(new ASN1OctetString(COMPACT_TEXT_BEFORE_OTP_BER_TYPE,
           compactTextBeforeOTP));
    }

    if (compactTextAfterOTP != null)
    {
      elements.add(new ASN1OctetString(COMPACT_TEXT_AFTER_OTP_BER_TYPE,
           compactTextAfterOTP));
    }

    if ((preferredDeliveryMechanisms != null) &&
        (! preferredDeliveryMechanisms.isEmpty()))
    {
      final ArrayList<ASN1Element> pdmElements =
           new ArrayList<ASN1Element>(preferredDeliveryMechanisms.size());
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

      elements.add(new ASN1Sequence(
           TYPE_PREFERRED_DELIVERY_MECHANISM_NAMES_AND_IDS, pdmElements));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the authentication ID for the user to whom the one-time password
   * should be delivered.
   *
   * @return  The authentication ID for the user to whom the one-time password
   *          should be delivered.
   */
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the static password for the user to whom the one-time password
   * should be delivered.  The returned password may be {@code null} if no
   *
   *
   * @return  The static password for the user to whom the one-time password
   *          should be delivered, or {@code null} if no static password should
   *          be included in the request.
   */
  public ASN1OctetString getStaticPassword()
  {
    return staticPassword;
  }



  /**
   * Retrieves an ordered list of the names of the preferred delivery mechanisms
   * for the one-time password, if provided.
   *
   * @return  An ordered list of the names of the preferred delivery mechanisms
   *          for the one-time password, or {@code null} if this was not
   *          provided.
   */
  public List<String> getPreferredDeliveryMechanisms()
  {
    if (preferredDeliveryMechanisms.isEmpty())
    {
      return null;
    }
    else
    {
      final LinkedHashSet<String> s =
           new LinkedHashSet<String>(preferredDeliveryMechanisms.size());
      for (final ObjectPair<String,String> p : preferredDeliveryMechanisms)
      {
        s.add(p.getFirst());
      }

      return Collections.unmodifiableList(new ArrayList<String>(s));
    }
  }



  /**
   * Retrieves an ordered list of the preferred delivery mechanisms that should
   * be used to provide the one-time password to the user, optionally paired
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
   *          one-time password, or an empty list if none were provided.
   */
  public List<ObjectPair<String,String>>
              getPreferredDeliveryMechanismNamesAndIDs()
  {
    return preferredDeliveryMechanisms;
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
  public String getMessageSubject()
  {
    return messageSubject;
  }



  /**
   * Retrieves the text (if any) that should appear before the one-time password
   * in the message delivered to the user via a mechanism that does not impose
   * significant constraints on message size.
   *
   * @return  The text that should appear before the one-time password in the
   *          message delivered to the user via a mechanism that does not impose
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text before the one-time password.
   */
  public String getFullTextBeforeOTP()
  {
    return fullTextBeforeOTP;
  }



  /**
   * Retrieves the text (if any) that should appear after the one-time password
   * in the message delivered to the user via a mechanism that does not impose
   * significant constraints on message size.
   *
   * @return  The text that should appear after the one-time password in the
   *          message delivered to the user via a mechanism that does not impose
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text after the one-time password.
   */
  public String getFullTextAfterOTP()
  {
    return fullTextAfterOTP;
  }



  /**
   * Retrieves the text (if any) that should appear before the one-time password
   * in the message delivered to the user via a mechanism that imposes
   * significant constraints on message size.
   *
   * @return  The text that should appear before the one-time password in the
   *          message delivered to the user via a mechanism that imposes
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text before the one-time password.
   */
  public String getCompactTextBeforeOTP()
  {
    return compactTextBeforeOTP;
  }



  /**
   * Retrieves the text (if any) that should appear after the one-time password
   * in the message delivered to the user via a mechanism that imposes
   * significant constraints on message size.
   *
   * @return  The text that should appear after the one-time password in the
   *          message delivered to the user via a mechanism that imposes
   *          significant constraints on message size, or {@code null} if there
   *          should not be any text after the one-time password.
   */
  public String getCompactTextAfterOTP()
  {
    return compactTextAfterOTP;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public DeliverOneTimePasswordExtendedResult process(
              final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new DeliverOneTimePasswordExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  public DeliverOneTimePasswordExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}.
   */
  @Override()
  public DeliverOneTimePasswordExtendedRequest duplicate(
                                                    final Control[] controls)
  {
    final DeliverOneTimePasswordExtendedRequest r =
         new DeliverOneTimePasswordExtendedRequest(authenticationID,
              staticPassword, messageSubject, fullTextBeforeOTP,
              fullTextAfterOTP, compactTextBeforeOTP, compactTextAfterOTP,
              preferredDeliveryMechanisms, controls);
    r.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return r;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getExtendedRequestName()
  {
    return INFO_DELIVER_OTP_REQ_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("DeliverOneTimePasswordExtendedRequest(authenticationID=");
    buffer.append(authenticationID);

    if (messageSubject != null)
    {
      buffer.append(", messageSubject='");
      buffer.append(messageSubject);
      buffer.append('\'');
    }

    if (fullTextBeforeOTP != null)
    {
      buffer.append(", fullTextBeforeOTP='");
      buffer.append(fullTextBeforeOTP);
      buffer.append('\'');
    }

    if (fullTextAfterOTP != null)
    {
      buffer.append(", fullTextAfterOTP='");
      buffer.append(fullTextAfterOTP);
      buffer.append('\'');
    }

    if (compactTextBeforeOTP != null)
    {
      buffer.append(", compactTextBeforeOTP='");
      buffer.append(compactTextBeforeOTP);
      buffer.append('\'');
    }

    if (compactTextAfterOTP != null)
    {
      buffer.append(", compactTextAfterOTP='");
      buffer.append(compactTextAfterOTP);
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
