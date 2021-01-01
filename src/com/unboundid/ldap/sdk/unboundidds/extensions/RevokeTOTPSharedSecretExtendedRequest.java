/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.ExtendedRequest;
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
 * This class provides an implementation of an extended request that may be used
 * to revoke one or all of the TOTP shared secrets for a user so that they may
 * no longer be used to authenticate.
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
 * This request may be invoked in one of following ways:
 * <BR><BR>
 * <UL>
 *   <LI>
 *     With a {@code null} authentication identity and a non-{@code null}
 *     TOTP shared secret.  In this case, the authorization identity for the
 *     operation (typically the user as whom the underlying connection is
 *     authenticated, but possibly a different user if the request also includes
 *     a control like the proxied authorization or intermediate client request
 *     control that specifies and alternate authorization identity, or if the
 *     client authenticated with a SASL mechanism that included an alternate
 *     authorization identity) will be used as the authentication identity for
 *     this request, and only the specified TOTP shared secret will be removed
 *     from the user's entry while any other shared secrets that may be present
 *     in the user's entry will be preserved.  If a static password is provided,
 *     then it will be verified, but if none is given then the provided TOTP
 *     shared secret will be considered sufficient proof of the user's identity.
 *   </LI>
 *   <LI>
 *     With a {@code null} authentication identity, a non-{@code null} static
 *     password, and a {@code null} TOTP shared secret.  In this case, the
 *     authorization identity for the operation will be used as the
 *     authentication identity for this request, and, if the provided static
 *     password is valid, then all TOTP secrets contained in the user's entry
 *     will be revoked.
 *   </LI>
 *   <LI>
 *     With a non-{@code null} authentication identity and a non-{@code null}
 *     TOTP shared secret.  In this case, only the provided TOTP shared secret
 *     will be removed from the specified user's account while any other shared
 *     secrets will be preserved.  If a static password is provided, then it
 *     will be verified, but if none is given then the provided TOTP shared
 *     secret will be considered sufficient proof of the user's identity.
 *   </LI>
 *   <LI>
 *     With a non-{@code null} authentication identity a non-{@code null}
 *     static password, and a {@code null} TOTP shared secret.  In this case,
 *     if the static password is valid for the specified user, then all TOTP
 *     shared secrets for that user will be revoked.
 *   </LI>
 *   <LI>
 *     With a non-{@code null} authentication identity a {@code null} static
 *     password, and a {@code null} TOTP shared secret.  In this case, the
 *     authentication identity from the request must be different from the
 *     authorization identity for the operation, and the authorization identity
 *     must have the password-reset privilege.  All TOTP shared secrets for
 *     the specified user will be revoked.
 *   </LI>
 * </UL>
 * <BR><BR>
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.58, and it must
 * include a request value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   RevokeTOTPSharedSecretRequest ::= SEQUENCE {
 *        authenticationID     [0] OCTET STRING OPTIONAL,
 *        staticPassword       [1] OCTET STRING OPTIONAL,
 *        totpSharedSecret     [2] OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 *
 * @see  GenerateTOTPSharedSecretExtendedRequest
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class RevokeTOTPSharedSecretExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.58) for the revoke TOTP shared secret
   * extended request.
   */
  @NotNull public static final String REVOKE_TOTP_SHARED_SECRET_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.58";



  /**
   * The BER type for the authentication ID element of the request value
   * sequence.
   */
  private static final byte TYPE_AUTHENTICATION_ID = (byte) 0x80;



  /**
   * The BER type for the static password element of the request value sequence.
   */
  private static final byte TYPE_STATIC_PASSWORD = (byte) 0x81;



  /**
   * The BER type for the TOTP shared secret element of the request value
   * sequence.
   */
  private static final byte TYPE_TOTP_SHARED_SECRET = (byte) 0x82;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1437768898568182738L;



  // The static password for the request.
  @Nullable private final ASN1OctetString staticPassword;

  // The authentication ID for the request.
  @Nullable private final String authenticationID;

  // The base32-encoded representation of the TOTP shared secret to revoke.
  @Nullable private final String totpSharedSecret;



  /**
   * Creates a new revoke TOTP shared secret extended request with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to revoke the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the
   *                           authorization identity for the operation should
   *                           be used as the authentication identity for this
   *                           request.
   * @param  staticPassword    The static password of the user for whom the TOTP
   *                           shared secrets are to be revoked.  It may be
   *                           {@code null} if the provided
   *                           {@code totpSharedSecret} is non-{@code null}, or
   *                           if the {@code authenticationID} is
   *                           non-{@code null} and the operation's
   *                           authorization identity has the password-reset
   *                           privilege.
   * @param  totpSharedSecret  The base32-encoded representation of the TOTP
   *                           shared secret to revoke.  It may be {@code null}
   *                           if all TOTP shared secrets should be purged from
   *                           the target user's entry.  If it is {@code null},
   *                           then either the {@code staticPassword} element
   *                           must be non-{@code null}, or the
   *                           {@code authenticationID} element must be
   *                           non-{@code null}, must be different from the
   *                           operation's authorization identity, and the
   *                           authorization identity must have the
   *                           password-reset privilege.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public RevokeTOTPSharedSecretExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final String staticPassword,
              @Nullable final String totpSharedSecret,
              @Nullable final Control... controls)
  {
    this(authenticationID, encodePassword(staticPassword), totpSharedSecret,
         controls);
  }



  /**
   * Creates a new revoke TOTP shared secret extended request with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to revoke the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the
   *                           authorization identity for the operation should
   *                           be used as the authentication identity for this
   *                           request.
   * @param  staticPassword    The static password of the user for whom the TOTP
   *                           shared secrets are to be revoked.  It may be
   *                           {@code null} if the provided
   *                           {@code totpSharedSecret} is non-{@code null}, or
   *                           if the {@code authenticationID} is
   *                           non-{@code null} and the operation's
   *                           authorization identity has the password-reset
   *                           privilege.
   * @param  totpSharedSecret  The base32-encoded representation of the TOTP
   *                           shared secret to revoke.  It may be {@code null}
   *                           if all TOTP shared secrets should be purged from
   *                           the target user's entry.  If it is {@code null},
   *                           then either the {@code staticPassword} element
   *                           must be non-{@code null}, or the
   *                           {@code authenticationID} element must be
   *                           non-{@code null}, must be different from the
   *                           operation's authorization identity, and the
   *                           authorization identity must have the
   *                           password-reset privilege.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public RevokeTOTPSharedSecretExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final byte[] staticPassword,
              @Nullable final String totpSharedSecret,
              @Nullable final Control... controls)
  {
    this(authenticationID, encodePassword(staticPassword), totpSharedSecret,
         controls);
  }



  /**
   * Creates a new revoke TOTP shared secret extended request with the provided
   * information.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to revoke the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the
   *                           authorization identity for the operation should
   *                           be used as the authentication identity for this
   *                           request.
   * @param  staticPassword    The static password of the user for whom the TOTP
   *                           shared secrets are to be revoked.  It may be
   *                           {@code null} if the provided
   *                           {@code totpSharedSecret} is non-{@code null}, or
   *                           if the {@code authenticationID} is
   *                           non-{@code null} and the operation's
   *                           authorization identity has the password-reset
   *                           privilege.
   * @param  totpSharedSecret  The base32-encoded representation of the TOTP
   *                           shared secret to revoke.  It may be {@code null}
   *                           if all TOTP shared secrets should be purged from
   *                           the target user's entry.  If it is {@code null},
   *                           then either the {@code staticPassword} element
   *                           must be non-{@code null}, or the
   *                           {@code authenticationID} element must be
   *                           non-{@code null}, must be different from the
   *                           operation's authorization identity, and the
   *                           authorization identity must have the
   *                           password-reset privilege.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public RevokeTOTPSharedSecretExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final ASN1OctetString staticPassword,
              @Nullable final String totpSharedSecret,
              @Nullable final Control... controls)
  {
    super(REVOKE_TOTP_SHARED_SECRET_REQUEST_OID,
         encodeValue(authenticationID, staticPassword, totpSharedSecret),
         controls);

    this.authenticationID = authenticationID;
    this.staticPassword   = staticPassword;
    this.totpSharedSecret = totpSharedSecret;
  }



  /**
   * Creates a new revoke TOTP shared secret extended request that is decoded
   * from the provided generic extended request.
   *
   * @param  request  The generic extended request to decode as a revoke TOTP
   *                  shared secret request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided request.
   */
  public RevokeTOTPSharedSecretExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_REVOKE_TOTP_SECRET_REQUEST_NO_VALUE.get());
    }

    try
    {
      String authID = null;
      ASN1OctetString staticPW = null;
      String totpSecret = null;
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_AUTHENTICATION_ID:
            authID = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          case TYPE_STATIC_PASSWORD:
            staticPW = ASN1OctetString.decodeAsOctetString(e);
            break;
          case TYPE_TOTP_SHARED_SECRET:
            totpSecret = ASN1OctetString.decodeAsOctetString(e).stringValue();
            break;
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_REVOKE_TOTP_SECRET_REQUEST_UNRECOGNIZED_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      if ((authID == null) && (staticPW == null) && (totpSecret == null))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_REVOKE_TOTP_SECRET_REQUEST_NO_AUTHN_ID_OR_PW_OR_SECRET.get());
      }

      authenticationID = authID;
      staticPassword   = staticPW;
      totpSharedSecret = totpSecret;
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
           ERR_REVOKE_TOTP_SECRET_REQUEST_ERROR_DECODING_VALUE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided password as an ASN.1 octet string suitable for
   * inclusion in the encoded request.
   *
   * @param  password  The password to be encoded.  It may be {@code null} if
   *                   no password should be included.  If it is
   *                   non-{@code null}, then it must be a string or a byte
   *                   array.
   *
   * @return  The encoded password, or {@code null} if no password was given.
   */
  @Nullable()
  private static ASN1OctetString encodePassword(
                                      @Nullable final Object password)
  {
    if (password == null)
    {
      return null;
    }
    else if (password instanceof byte[])
    {
      return new ASN1OctetString(TYPE_STATIC_PASSWORD, (byte[]) password);
    }
    else
    {
      return new ASN1OctetString(TYPE_STATIC_PASSWORD,
           String.valueOf(password));
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to revoke the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the
   *                           authorization identity for the operation should
   *                           be used as the authentication identity for this
   *                           request.
   * @param  staticPassword    The static password of the user for whom the TOTP
   *                           shared secrets are to be revoked.  It may be
   *                           {@code null} if the provided
   *                           {@code totpSharedSecret} is non-{@code null}, or
   *                           if the {@code authenticationID} is
   *                           non-{@code null} and the operation's
   *                           authorization identity has the password-reset
   *                           privilege.
   * @param  totpSharedSecret  The TOTP shared secret to revoke.  It may be
   *                           {@code null} if all TOTP shared secrets should be
   *                           purged from the target user's entry.  If it is
   *                           {@code null}, then either the
   *                           {@code staticPassword} element must be
   *                           non-{@code null}, or the {@code authenticationID}
   *                           element must be non-{@code null}, must be
   *                           different from the operation's authorization
   *                           identity, and the authorization identity must
   *                           have the password-reset privilege.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final String authenticationID,
               @Nullable final ASN1OctetString staticPassword,
               @Nullable final String totpSharedSecret)
  {
    if (totpSharedSecret == null)
    {
      Validator.ensureTrue(
           ((authenticationID != null) || (staticPassword != null)),
           "If the TOTP shared secret is null, then at least one of the " +
                "authentication ID and static password must be non-null.");
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(3);

    if (authenticationID != null)
    {
      elements.add(
           new ASN1OctetString(TYPE_AUTHENTICATION_ID, authenticationID));
    }

    if (staticPassword != null)
    {
      elements.add(staticPassword);
    }

    if (totpSharedSecret != null)
    {
      elements.add(
           new ASN1OctetString(TYPE_TOTP_SHARED_SECRET, totpSharedSecret));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the authentication ID that identifies the user for whom to revoke
   * the TOTP shared secrets, if provided.
   *
   * @return  The authentication ID that identifies the target user, or
   *          {@code null} if the shared secrets are to be revoked for the
   *          operation's authorization identity.
   */
  @Nullable()
  public String getAuthenticationID()
  {
    return authenticationID;
  }



  /**
   * Retrieves the string representation of the static password for the target
   * user, if provided.
   *
   * @return  The string representation of the static password for the target
   *          user, or {@code null} if no static password was provided.
   */
  @Nullable()
  public String getStaticPasswordString()
  {
    if (staticPassword == null)
    {
      return null;
    }
    else
    {
      return staticPassword.stringValue();
    }
  }



  /**
   * Retrieves the bytes that comprise the static password for the target user,
   * if provided.
   *
   * @return  The bytes that comprise the static password for the target user,
   *          or {@code null} if no static password was provided.
   */
  @Nullable()
  public byte[] getStaticPasswordBytes()
  {
    if (staticPassword == null)
    {
      return null;
    }
    else
    {
      return staticPassword.getValue();
    }
  }



  /**
   * Retrieves the base32-encoded representation of the TOTP shared secret to be
   * revoked, if provided.
   *
   * @return  The base32-encoded representation of the TOTP shared secret to be
   *          revoked, or {@code null} if all of the user's TOTP shared secrets
   *          should be revoked.
   */
  @Nullable()
  public String getTOTPSharedSecret()
  {
    return totpSharedSecret;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public RevokeTOTPSharedSecretExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public RevokeTOTPSharedSecretExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final RevokeTOTPSharedSecretExtendedRequest r =
         new RevokeTOTPSharedSecretExtendedRequest(authenticationID,
              staticPassword, totpSharedSecret, controls);
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
    return INFO_REVOKE_TOTP_SECRET_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("RevokeTOTPSharedSecretExtendedRequest(");

    if (authenticationID != null)
    {
      buffer.append("authenticationID='");
      buffer.append(authenticationID);
      buffer.append("', ");
    }

    buffer.append("staticPasswordProvided=");
    buffer.append(staticPassword != null);
    buffer.append(", totpSharedSecretProvided=");
    buffer.append(totpSharedSecret != null);

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
