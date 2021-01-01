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
import com.unboundid.ldap.sdk.LDAPConnection;
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
 * to generate a shared secret for use in generating TOTP authentication codes
 * (as per <A HREF="http://www.ietf.org/rfc/rfc6238.txt">RFC 6238</A>, for
 * example, using the mechanism provided in the
 * {@link com.unboundid.ldap.sdk.unboundidds.OneTimePassword} class), which can
 * be used to authenticate to the server via the
 * {@link com.unboundid.ldap.sdk.unboundidds.UnboundIDTOTPBindRequest}.
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
 *     With a {@code null} authentication identity and a non-{@code null} static
 *     password.  In this case, the authorization identity for the operation
 *     (typically the user as whom the underlying connection is authenticated,
 *     but possibly a different user if the request also includes a control like
 *     the proxied authorization or intermediate client request control that
 *     specifies and alternate authorization identity, or if the client
 *     authenticated with a SASL mechanism that included an alternate
 *     authorization identity) will be used as the authentication identity for
 *     this request, and the static password must be valid for that user.  This
 *     will be treated as a user requesting a TOTP shared secret for their own
 *     account.
 *   </LI>
 *   <LI>
 *     With a non-{@code null} authentication identity (which may or may not
 *     match the authorization identity for the operation) and a
 *     non-{@code null} static password that is valid for the provided
 *     authentication identity.  This will also be treated as a user requesting
 *     a TOTP shared secret for their own account.
 *   </LI>
 *   <LI>
 *     With a non-{@code null} authentication identity and a {@code null} static
 *     password.  In this case, the authentication identity must not match the
 *     authorization identity for the operation, and the authorization identity
 *     must have the password-reset privilege.  This will be treated as an
 *     administrator requesting a TOTP shared secret on behalf of a user and is
 *     recommended only for the case in which the identity of the user has been
 *     verified through some means other than a static password.
 *   </LI>
 * </UL>
 * <BR><BR>
 * If the request is processed successfully, the server will generate a TOTP
 * shared secret for the user, will store it in the user's entry, and will
 * return that secret back to the client via the
 * {@link GenerateTOTPSharedSecretExtendedResult}.
 * <BR><BR>
 * Note that this operation will not interfere with any other TOTP shared
 * secrets that may already exist in the user's entry; the new shared secret
 * will be merged with any existing shared secret values for the user.  If a
 * TOTP shared secret is no longer needed, the
 * {@link RevokeTOTPSharedSecretExtendedRequest} may be used to remove it from
 * the user's account.
 * <BR><BR>
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.56, and it must
 * include a request value with the following encoding:
 * <BR><BR>
 * <PRE>
 *   GenerateTOTPSharedSecretRequest ::= SEQUENCE {
 *        authenticationID     [0] OCTET STRING OPTIONAL,
 *        staticPassword       [1] OCTET STRING OPTIONAL,
 *        ... }
 * </PRE>
 *
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GenerateTOTPSharedSecretExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.56) for the generate TOTP shared secret
   * extended request.
   */
  @NotNull public static final String GENERATE_TOTP_SHARED_SECRET_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.56";



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
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1617090986047944957L;



  // The static password for the request.
  @Nullable private final ASN1OctetString staticPassword;

  // The authentication ID for the request.
  @Nullable private final String authenticationID;



  /**
   * Creates a new generate TOTP shared secret extended request with the
   * provided information.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to generate the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the TOTP
   *                           shared secret is to be generated for the
   *                           authorization identity for the operation, and
   *                           only if the {@code staticPassword} is
   *                           non-{@code null}).
   * @param  staticPassword    The static password of the user for whom to
   *                           generate the TOTP shared secret.  It may be
   *                           {@code null} only if the {@code authenticationID}
   *                           is non-{@code null}, is different from the
   *                           operation's authorization identity, and the
   *                           operation's authorization identity has the
   *                           password-reset privilege.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public GenerateTOTPSharedSecretExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final String staticPassword,
              @Nullable final Control... controls)
  {
    this(authenticationID, encodePassword(staticPassword), controls);
  }



  /**
   * Creates a new generate TOTP shared secret extended request with the
   * provided information.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to generate the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the TOTP
   *                           shared secret is to be generated for the
   *                           authorization identity for the operation, and
   *                           only if the {@code staticPassword} is
   *                           non-{@code null}).
   * @param  staticPassword    The static password of the user for whom to
   *                           generate the TOTP shared secret.  It may be
   *                           {@code null} only if the {@code authenticationID}
   *                           is non-{@code null}, is different from the
   *                           operation's authorization identity, and the
   *                           operation's authorization identity has the
   *                           password-reset privilege.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public GenerateTOTPSharedSecretExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final byte[] staticPassword,
              @Nullable final Control... controls)
  {
    this(authenticationID, encodePassword(staticPassword), controls);
  }



  /**
   * Creates a new generate TOTP shared secret extended request with the
   * provided information.
   *
   * @param  authenticationID  The authentication ID to use to identify the user
   *                           for whom to generate the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the TOTP
   *                           shared secret is to be generated for the
   *                           authorization identity for the operation, and
   *                           only if the {@code staticPassword} is
   *                           non-{@code null}).
   * @param  staticPassword    The static password of the user for whom to
   *                           generate the TOTP shared secret.  It may be
   *                           {@code null} only if the {@code authenticationID}
   *                           is non-{@code null}, is different from the
   *                           operation's authorization identity, and the
   *                           operation's authorization identity has the
   *                           password-reset privilege.
   * @param  controls          The set of controls to include in the request.
   *                           It may be {@code null} or empty if there should
   *                           not be any request controls.
   */
  public GenerateTOTPSharedSecretExtendedRequest(
              @Nullable final String authenticationID,
              @Nullable final ASN1OctetString staticPassword,
              @Nullable final Control... controls)
  {
    super(GENERATE_TOTP_SHARED_SECRET_REQUEST_OID,
         encodeValue(authenticationID, staticPassword), controls);

    this.authenticationID = authenticationID;
    this.staticPassword   = staticPassword;
  }



  /**
   * Creates a new generate TOTP shared secret extended request that is decoded
   * from the provided generic extended request.
   *
   * @param  request  The generic extended request to decode as a generate TOTP
   *                  shared secret request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the provided request.
   */
  public GenerateTOTPSharedSecretExtendedRequest(
              @NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GEN_TOTP_SECRET_REQUEST_NO_VALUE.get());
    }

    try
    {
      String authID = null;
      ASN1OctetString staticPW = null;
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
          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GEN_TOTP_SECRET_REQUEST_UNRECOGNIZED_TYPE.get(
                      StaticUtils.toHex(e.getType())));
        }
      }

      if ((authID == null) && (staticPW == null))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GEN_TOTP_SECRET_REQUEST_NEITHER_AUTHN_ID_NOR_PW.get());
      }

      authenticationID = authID;
      staticPassword   = staticPW;
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
           ERR_GEN_TOTP_SECRET_REQUEST_ERROR_DECODING_VALUE.get(
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
  private static ASN1OctetString encodePassword(@Nullable final Object password)
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
   *                           for whom to generate the TOTP shared secret.  It
   *                           should be a string in the form "dn:" followed by
   *                           the DN of the target user, or "u:" followed by
   *                           the username.  It may be {@code null} if the TOTP
   *                           shared secret is to be generated for the
   *                           authorization identity for the operation, and
   *                           only if the {@code staticPassword} is
   *                           non-{@code null}).
   * @param  staticPassword    The static password of the user for whom to
   *                           generate the TOTP shared secret.  It may be
   *                           {@code null} only if the {@code authenticationID}
   *                           is non-{@code null}, is different from the
   *                           operation's authorization identity, and the
   *                           operation's authorization identity has the
   *                           password-reset privilege.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
               @Nullable final String authenticationID,
               @Nullable final ASN1OctetString staticPassword)
  {
    if (authenticationID == null)
    {
      Validator.ensureTrue((staticPassword != null),
           "If the authentication ID is null, the static password must be " +
                "non-null.");
    }

    final ArrayList<ASN1Element> elements = new ArrayList<>(2);

    if (authenticationID != null)
    {
      elements.add(
           new ASN1OctetString(TYPE_AUTHENTICATION_ID, authenticationID));
    }

    if (staticPassword != null)
    {
      elements.add(staticPassword);
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the authentication ID that identifies the user for whom to
   * generate the TOTP shared secret, if provided.
   *
   * @return  The authentication ID that identifies the target user, or
   *          {@code null} if the shared secret is to be generated for the
   *          authorization identity associated with the extended request.
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
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected GenerateTOTPSharedSecretExtendedResult process(
                 @NotNull final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    return new GenerateTOTPSharedSecretExtendedResult(
         super.process(connection, depth));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GenerateTOTPSharedSecretExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GenerateTOTPSharedSecretExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GenerateTOTPSharedSecretExtendedRequest r =
         new GenerateTOTPSharedSecretExtendedRequest(authenticationID,
              staticPassword, controls);
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
    return INFO_GEN_TOTP_SECRET_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GenerateTOTPSharedSecretExtendedRequest(");

    if (authenticationID != null)
    {
      buffer.append("authenticationID='");
      buffer.append(authenticationID);
      buffer.append("', ");
    }

    buffer.append("staticPasswordProvided=");
    buffer.append(staticPassword != null);

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
