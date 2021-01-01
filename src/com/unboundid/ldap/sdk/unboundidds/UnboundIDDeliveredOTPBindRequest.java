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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.InternalSDKHelper;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SASLBindRequest;
import com.unboundid.ldap.sdk.ToCodeArgHelper;
import com.unboundid.ldap.sdk.ToCodeHelper;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            DeliverOneTimePasswordExtendedRequest;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides support for an UnboundID-proprietary SASL mechanism that
 * allows for multifactor authentication using a one-time password that has been
 * delivered to the user via some out-of-band mechanism as triggered by the
 * {@link DeliverOneTimePasswordExtendedRequest} (which requires the user to
 * provide an authentication ID and a static password).
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
 * The name for this SASL mechanism is "UNBOUNDID-DELIVERED-OTP".  An
 * UNBOUNDID-DELIVERED-OTP SASL bind request MUST include SASL credentials with
 * the following ASN.1 encoding:
 * <BR><BR>
 * <PRE>
 *   UnboundIDDeliveredOTPCredentials ::= SEQUENCE {
 *        authenticationID     [0] OCTET STRING,
 *        authorizationID      [1] OCTET STRING OPTIONAL.
 *        oneTimePassword      [2] OCTET STRING,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class UnboundIDDeliveredOTPBindRequest
       extends SASLBindRequest
{
  /**
   * The name for the UnboundID delivered OTP SASL mechanism.
   */
  @NotNull public static final String UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME =
       "UNBOUNDID-DELIVERED-OTP";



  /**
   * The BER type for the authentication ID included in the request.
   */
  private static final byte TYPE_AUTHENTICATION_ID = (byte) 0x80;



  /**
   * The BER type for the authorization ID included in the request.
   */
  private static final byte TYPE_AUTHORIZATION_ID = (byte) 0x81;



  /**
   * The BER type for the one-time password included in the request.
   */
  private static final byte TYPE_OTP = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8148101285676071058L;



  // The message ID from the last LDAP message sent from this request.
  private volatile int messageID = -1;

  // The authentication identity for the bind.
  @NotNull private final String authenticationID;

  // The authorization identity for the bind, if provided.
  @Nullable private final String authorizationID;

  // The one-time password for the bind, if provided.
  @NotNull private final String oneTimePassword;



  /**
   * Creates a new delivered one-time password bind request with the provided
   * information.
   *
   * @param  authenticationID  The authentication identity for the bind request.
   *                           It must not be {@code null} and must in the form
   *                           "u:" followed by a username, or "dn:" followed
   *                           by a DN.
   * @param  authorizationID   The authorization identity for the bind request.
   *                           It may be {@code null} if the authorization
   *                           identity should be the same as the authentication
   *                           identity.  If an authorization identity is
   *                           specified, it must be in the form "u:" followed
   *                           by a username, or "dn:" followed by a DN.  The
   *                           value "dn:" may be used to indicate the
   *                           authorization identity of the anonymous user.
   * @param  oneTimePassword   The one-time password that has been delivered to
   *                           the user via the deliver one-time password
   *                           extended request.  It must not be {@code null}.
   * @param  controls          The set of controls to include in the bind
   *                           request.  It may be {@code null} or empty if no
   *                           controls should be included.
   */
  public UnboundIDDeliveredOTPBindRequest(
              @NotNull final String authenticationID,
              @Nullable final String authorizationID,
              @NotNull final String oneTimePassword,
              @Nullable final Control... controls)
  {
    super(controls);

    Validator.ensureNotNull(authenticationID);
    Validator.ensureNotNull(oneTimePassword);

    this.authenticationID = authenticationID;
    this.authorizationID = authorizationID;
    this.oneTimePassword  = oneTimePassword;
  }



  /**
   * Creates a new delivered one-time password bind request from the information
   * contained in the provided encoded SASL credentials.
   *
   * @param  saslCredentials  The encoded SASL credentials to be decoded in
   *                          order to create this delivered one-time password
   *                          bind request.  It must not be {@code null}.
   * @param  controls         The set of controls to include in the bind
   *                          request.  It may be {@code null} or empty if no
   *                          controls should be included.
   *
   * @return  The delivered one-time password bind request decoded from the
   *          provided credentials.
   *
   * @throws  LDAPException  If the provided credentials are not valid for an
   *                         UNBOUNDID-DELIVERED-OTP bind request.
   */
  @NotNull()
  public static UnboundIDDeliveredOTPBindRequest decodeSASLCredentials(
                     @NotNull final ASN1OctetString saslCredentials,
                     @Nullable final Control... controls)
         throws LDAPException
  {
    String          authenticationID = null;
    String          authorizationID  = null;
    String          oneTimePassword  = null;

    try
    {
      final ASN1Sequence s =
           ASN1Sequence.decodeAsSequence(saslCredentials.getValue());
      for (final ASN1Element e : s.elements())
      {
        switch (e.getType())
        {
          case TYPE_AUTHENTICATION_ID:
            authenticationID = e.decodeAsOctetString().stringValue();
            break;
          case TYPE_AUTHORIZATION_ID:
            authorizationID = e.decodeAsOctetString().stringValue();
            break;
          case TYPE_OTP:
            oneTimePassword = e.decodeAsOctetString().stringValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_DOTP_DECODE_INVALID_ELEMENT_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DOTP_DECODE_ERROR.get(StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (authenticationID == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DOTP_DECODE_MISSING_AUTHN_ID.get());
    }

    if (oneTimePassword == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_DOTP_DECODE_MISSING_OTP.get());
    }

    return new UnboundIDDeliveredOTPBindRequest(authenticationID,
         authorizationID, oneTimePassword, controls);
  }



  /**
   * Retrieves the authentication identity for the bind request.
   *
   * @return  The authentication identity for the bind request.
   */
  @NotNull()
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the authorization identity for the bind request, if available.
   *
   * @return  The authorization identity for the bind request, or {@code null}
   *          if the authorization identity should be the same as the
   *          authentication identity.
   */
  @Nullable()
  public String getAuthorizationID()
  {
    return authorizationID;
  }



  /**
   * Retrieves the one-time password for the bind request.
   *
   * @return  The one-time password for the bind request.
   */
  @NotNull()
  public String getOneTimePassword()
  {
    return oneTimePassword;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected BindResult process(@NotNull final LDAPConnection connection,
                               final int depth)
            throws LDAPException
  {
    messageID = InternalSDKHelper.nextMessageID(connection);
    return sendBindRequest(connection, "",
         encodeCredentials(authenticationID, authorizationID, oneTimePassword),
         getControls(), getResponseTimeoutMillis(connection));
  }



  /**
   * Encodes the provided information into an ASN.1 octet string that may be
   * used as the SASL credentials for an UnboundID delivered one-time password
   * bind request.
   *
   * @param  authenticationID  The authentication identity for the bind request.
   *                           It must not be {@code null} and must in the form
   *                           "u:" followed by a username, or "dn:" followed
   *                           by a DN.
   * @param  authorizationID   The authorization identity for the bind request.
   *                           It may be {@code null} if the authorization
   *                           identity should be the same as the authentication
   *                           identity.  If an authorization identity is
   *                           specified, it must be in the form "u:" followed
   *                           by a username, or "dn:" followed by a DN.  The
   *                           value "dn:" may be used to indicate the
   *                           authorization identity of the anonymous user.
   * @param  oneTimePassword   The one-time password that has been delivered to
   *                           the user via the deliver one-time password
   *                           extended request.  It must not be {@code null}.
   *
   * @return  An ASN.1 octet string that may be used as the SASL credentials for
   *          an UnboundID delivered one-time password bind request.
   */
  @NotNull()
  public static ASN1OctetString encodeCredentials(
                                     @NotNull final String authenticationID,
                                     @Nullable final String authorizationID,
                                     @NotNull final String oneTimePassword)
  {
    Validator.ensureNotNull(authenticationID);
    Validator.ensureNotNull(oneTimePassword);

    final ArrayList<ASN1Element> elements = new ArrayList<>(3);
    elements.add(new ASN1OctetString(TYPE_AUTHENTICATION_ID, authenticationID));

    if (authorizationID != null)
    {
      elements.add(new ASN1OctetString(TYPE_AUTHORIZATION_ID, authorizationID));
    }

    elements.add(new ASN1OctetString(TYPE_OTP, oneTimePassword));
    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDDeliveredOTPBindRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public UnboundIDDeliveredOTPBindRequest duplicate(
              @Nullable final Control[] controls)
  {
    final UnboundIDDeliveredOTPBindRequest bindRequest =
         new UnboundIDDeliveredOTPBindRequest(authenticationID,
              authorizationID, oneTimePassword, controls);
    bindRequest.setResponseTimeoutMillis(getResponseTimeoutMillis(null));
    return bindRequest;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSASLMechanismName()
  {
    return UNBOUNDID_DELIVERED_OTP_MECHANISM_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int getLastMessageID()
  {
    return messageID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UnboundDeliveredOTPBindRequest(authID='");
    buffer.append(authenticationID);
    buffer.append("', ");

    if (authorizationID != null)
    {
      buffer.append("authzID='");
      buffer.append(authorizationID);
      buffer.append("', ");
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



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toCode(@NotNull final List<String> lineList,
                     @NotNull final String requestID,
                     final int indentSpaces, final boolean includeProcessing)
  {
    // Create the request variable.
    final ArrayList<ToCodeArgHelper> constructorArgs = new ArrayList<>(4);
    constructorArgs.add(ToCodeArgHelper.createString(authenticationID,
         "Authentication ID"));
    constructorArgs.add(ToCodeArgHelper.createString(authorizationID,
         "Authorization ID"));
    constructorArgs.add(ToCodeArgHelper.createString("---redacted-otp---",
         "One-Time Password"));

    final Control[] controls = getControls();
    if (controls.length > 0)
    {
      constructorArgs.add(ToCodeArgHelper.createControlArray(controls,
           "Bind Controls"));
    }

    ToCodeHelper.generateMethodCall(lineList, indentSpaces,
         "UnboundIDDeliveredOTPBindRequest", requestID + "Request",
         "new UnboundIDDeliveredOTPBindRequest", constructorArgs);


    // Add lines for processing the request and obtaining the result.
    if (includeProcessing)
    {
      // Generate a string with the appropriate indent.
      final StringBuilder buffer = new StringBuilder();
      for (int i=0; i < indentSpaces; i++)
      {
        buffer.append(' ');
      }
      final String indent = buffer.toString();

      lineList.add("");
      lineList.add(indent + "try");
      lineList.add(indent + '{');
      lineList.add(indent + "  BindResult " + requestID +
           "Result = connection.bind(" + requestID + "Request);");
      lineList.add(indent + "  // The bind was processed successfully.");
      lineList.add(indent + '}');
      lineList.add(indent + "catch (LDAPException e)");
      lineList.add(indent + '{');
      lineList.add(indent + "  // The bind failed.  Maybe the following will " +
           "help explain why.");
      lineList.add(indent + "  // Note that the connection is now likely in " +
           "an unauthenticated state.");
      lineList.add(indent + "  ResultCode resultCode = e.getResultCode();");
      lineList.add(indent + "  String message = e.getMessage();");
      lineList.add(indent + "  String matchedDN = e.getMatchedDN();");
      lineList.add(indent + "  String[] referralURLs = e.getReferralURLs();");
      lineList.add(indent + "  Control[] responseControls = " +
           "e.getResponseControls();");
      lineList.add(indent + '}');
    }
  }
}
