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



import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Null;
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
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of an extended request that may be used
 * to retrieve the set of password quality requirements that the Directory
 * Server will impose for a specified operation, which may include adding a new
 * user (including a password), a user changing his/her own password (a self
 * change), or one user changing the password for another user (an
 * administrative reset).
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
 * This extended request has an OID of 1.3.6.1.4.1.30221.2.6.43 and a value with
 * the following encoding:
 * <PRE>
 *   GetPasswordQualityRequirementsRequestValue ::= SEQUENCE {
 *        target     CHOICE {
 *             addWithDefaultPasswordPolicy           [0] NULL,
 *             addWithSpecifiedPasswordPolicy         [1] LDAPDN,
 *             selfChangeForAuthorizationIdentity     [2] NULL,
 *             selfChangeForSpecifiedUser             [3] LDAPDN,
 *             administrativeResetForUser             [4] LDAPDN,
 *             ... },
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetPasswordQualityRequirementsExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.43) for the get password quality
   * requirements extended request.
   */
  @NotNull public static final String
       OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST =
            "1.3.6.1.4.1.30221.2.6.43";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3652010872400265557L;



  // The target type for this get password quality requirements extended
  // request.
  @NotNull private final GetPasswordQualityRequirementsTargetType targetType;

  // The target DN for this get password quality requirements extended request.
  @Nullable private final String targetDN;



  /**
   * Creates a new get password quality requirements extended request with the
   * provided information.
   *
   * @param  targetType  The target type for this request.  It must not be
   *                     {@code null}.
   * @param  targetDN    The target DN for this request.  It may be {@code null}
   *                     if no target DN is required for the specified target
   *                     type.
   * @param  controls    The set of controls to include in the request.  It may
   *                     be {@code null} or empty if no controls should be
   *                     included.
   */
  private GetPasswordQualityRequirementsExtendedRequest(
       @NotNull final GetPasswordQualityRequirementsTargetType targetType,
       @Nullable final String targetDN,
       @Nullable final Control... controls)
  {
    super(OID_GET_PASSWORD_QUALITY_REQUIREMENTS_REQUEST,
         encodeValue(targetType, targetDN), controls);

    this.targetType = targetType;
    this.targetDN   = targetDN;
  }



  /**
   * Creates a new get password quality requirements extended request decoded
   * from the provided generic extended request.
   *
   * @param  r  The extended request to decode as a get password quality
   *            requirements request.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decoded the provided extended request as a
   *                         get password quality requirements request.
   */
  public GetPasswordQualityRequirementsExtendedRequest(
              @NotNull final ExtendedRequest r)
         throws LDAPException
  {
    super(r);

    final ASN1OctetString value = r.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_PW_QUALITY_REQS_REQUEST_NO_VALUE.get());
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      targetType = GetPasswordQualityRequirementsTargetType.forBERType(
           elements[0].getType());
      if (targetType == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GET_PW_QUALITY_REQS_REQUEST_UNKNOWN_TARGET_TYPE.get(
                  StaticUtils.toHex(elements[0].getType())));
      }

      switch (targetType)
      {
        case ADD_WITH_SPECIFIED_PASSWORD_POLICY:
        case SELF_CHANGE_FOR_SPECIFIED_USER:
        case ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER:
          targetDN = ASN1OctetString.decodeAsOctetString(
               elements[0]).stringValue();
          break;

        case ADD_WITH_DEFAULT_PASSWORD_POLICY:
        case SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY:
        default:
          targetDN = null;
          break;
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
           ERR_GET_PW_QUALITY_REQS_REQUEST_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this extended request.
   *
   * @param  targetType  The target type for this request.  It must not be
   *                     {@code null}.
   * @param  targetDN    The target DN for this request.  It may be {@code null}
   *                     if no target DN is required for the specified target
   *                     type.
   *
   * @return  The ASN.1 octet string containing the encoded request value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @NotNull final GetPasswordQualityRequirementsTargetType targetType,
       @Nullable final String targetDN)
  {
    final ASN1Element targetElement;
    switch (targetType)
    {
      case ADD_WITH_SPECIFIED_PASSWORD_POLICY:
      case SELF_CHANGE_FOR_SPECIFIED_USER:
      case ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER:
        targetElement = new ASN1OctetString(targetType.getBERType(), targetDN);
        break;

      case ADD_WITH_DEFAULT_PASSWORD_POLICY:
      case SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY:
      default:
        targetElement = new ASN1Null(targetType.getBERType());
        break;
    }

    final ASN1Sequence valueSequence = new ASN1Sequence(
         targetElement);

    return new ASN1OctetString(valueSequence.encode());
  }



  /**
   * Creates a new get password quality requirements extended request that will
   * retrieve the password requirements for an add operation governed by the
   * server's default password policy.
   *
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included
   *                   in the request.
   *
   * @return  A new get password quality requirements extended request that will
   *          retrieve the password requirements for an add operation governed
   *          by the server's default password policy.
   */
  @NotNull()
  public static GetPasswordQualityRequirementsExtendedRequest
                     createAddWithDefaultPasswordPolicyRequest(
                          @Nullable final Control... controls)
  {
    return new GetPasswordQualityRequirementsExtendedRequest(
         GetPasswordQualityRequirementsTargetType.
              ADD_WITH_DEFAULT_PASSWORD_POLICY,
         null, controls);
  }



  /**
   * Creates a new get password quality requirements extended request that will
   * retrieve the password requirements for an add operation governed by the
   * specified password policy.
   *
   * @param  policyDN  The DN of the entry that defines the password policy from
   *                   which to determine the password quality requirements.
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included
   *                   in the request.
   *
   * @return  A new get password quality requirements extended request that will
   *          retrieve the password requirements for an add operation governed
   *          by the specified password policy.
   */
  @NotNull()
  public static GetPasswordQualityRequirementsExtendedRequest
                     createAddWithSpecifiedPasswordPolicyRequest(
                          @NotNull final String policyDN,
                          @Nullable final Control... controls)
  {
    return new GetPasswordQualityRequirementsExtendedRequest(
         GetPasswordQualityRequirementsTargetType.
              ADD_WITH_SPECIFIED_PASSWORD_POLICY,
         policyDN, controls);
  }



  /**
   * Creates a new get password quality requirements extended request that will
   * retrieve the password requirements for a self change requested with the
   * same authorization identity as this extended request.
   *
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included
   *                   in the request.
   *
   * @return  A new get password quality requirements extended request that will
   *          retrieve the password requirements for a self change requested
   *          with the same authorization identity as this extended request.
   */
  @NotNull()
  public static GetPasswordQualityRequirementsExtendedRequest
                     createSelfChangeWithSameAuthorizationIdentityRequest(
                          @Nullable final Control... controls)
  {
    return new GetPasswordQualityRequirementsExtendedRequest(
         GetPasswordQualityRequirementsTargetType.
              SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY,
         null, controls);
  }



  /**
   * Creates a new get password quality requirements extended request that will
   * retrieve the password requirements for a self change requested by the
   * specified user.
   *
   * @param  userDN    The DN of the user for whom to retrieve the self change
   *                   password requirements.
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included
   *                   in the request.
   *
   * @return  A new get password quality requirements extended request that will
   *          retrieve the password requirements for a self change requested by
   *          the specified user.
   */
  @NotNull()
  public static GetPasswordQualityRequirementsExtendedRequest
                     createSelfChangeForSpecifiedUserRequest(
                          @NotNull final String userDN,
                          @Nullable final Control... controls)
  {
    return new GetPasswordQualityRequirementsExtendedRequest(
         GetPasswordQualityRequirementsTargetType.
              SELF_CHANGE_FOR_SPECIFIED_USER,
         userDN, controls);
  }



  /**
   * Creates a new get password quality requirements extended request that will
   * retrieve the password requirements for an administrative reset targeting
   * the specified user.
   *
   * @param  userDN    The DN of the user for whom to retrieve the
   *                   administrative reset password requirements.
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if no controls should be included
   *                   in the request.
   *
   * @return  A new get password quality requirements extended request that will
   *          retrieve the password requirements for an administrative reset
   *          targeting the specified user.
   */
  @NotNull()
  public static GetPasswordQualityRequirementsExtendedRequest
                     createAdministrativeResetForSpecifiedUserRequest(
                          @NotNull final String userDN,
                          @Nullable final Control... controls)
  {
    return new GetPasswordQualityRequirementsExtendedRequest(
         GetPasswordQualityRequirementsTargetType.
              ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER,
         userDN, controls);
  }



  /**
   * Retrieves the target type for this get password quality requirements
   * request.
   *
   * @return  The target type for this get password quality requirements
   *          request.
   */
  @NotNull()
  public GetPasswordQualityRequirementsTargetType getTargetType()
  {
    return targetType;
  }



  /**
   * Retrieves the target DN for this get password quality requirements request.
   * For a request with a target type of
   * {@code ADD_WITH_SPECIFIED_PASSWORD_POLICY}, this will be the DN of the
   * password policy from which to obtain the password quality requirements.
   * For a request with a target type of either
   * {@code SELF_CHANGE_FOR_SPECIFIED_USER} or
   * {@code ADMINISTRATIVE_RESET_FOR_SPECIFIED_USER}, this will be the DN of the
   * user for which to obtain the password quality requirements.  For a request
   * with a target type of either {@code ADD_WITH_DEFAULT_PASSWORD_POLICY} or
   * {@code SELF_CHANGE_FOR_AUTHORIZATION_IDENTITY}, no target DN is required
   * and the value returned will be {@code null}.
   *
   * @return  The target DN for this get password quality requirements request.
   */
  @Nullable()
  public String getTargetDN()
  {
    return targetDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetPasswordQualityRequirementsExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult result = super.process(connection, depth);
    return new GetPasswordQualityRequirementsExtendedResult(result);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetPasswordQualityRequirementsExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetPasswordQualityRequirementsExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GetPasswordQualityRequirementsExtendedRequest r =
         new GetPasswordQualityRequirementsExtendedRequest(targetType,
              targetDN, controls);
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
    return INFO_EXTENDED_REQUEST_NAME_GET_PW_QUALITY_REQS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetPasswordQualityRequirementsExtendedRequest(targetType=");
    buffer.append(targetType.name());

    if (targetDN != null)
    {
      buffer.append(", targetDN='");
      buffer.append(targetDN);
      buffer.append('\'');
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
