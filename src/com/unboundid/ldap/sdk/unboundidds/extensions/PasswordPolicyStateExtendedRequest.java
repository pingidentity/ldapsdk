/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.extensions.ExtOpMessages.*;



/**
 * This class provides an implementation of the password policy state extended
 * request as used in the Ping Identity, UnboundID, or Nokia/Alcatel-Lucent 8661
 * Directory Server.  It may be used to retrieve and/or alter password policy
 * properties for a user account.  See the documentation in the
 * {@link PasswordPolicyStateOperation} class for information about the types of
 * operations that can be performed.
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
 * The extended request has an OID of 1.3.6.1.4.1.30221.1.6.1 and a value with
 * the following encoding:
 * <PRE>
 *   PasswordPolicyStateValue ::= SEQUENCE {
 *        targetUser     LDAPDN
 *        operations     SEQUENCE OF PasswordPolicyStateOperation OPTIONAL }
 *
 *   PasswordPolicyStateOperation ::= SEQUENCE {
 *        opType       ENUMERATED {
 *             getPasswordPolicyDN                          (0),
 *             getAccountDisabledState                      (1),
 *             setAccountDisabledState                      (2),
 *             clearAccountDisabledState                    (3),
 *             getAccountExpirationTime                     (4),
 *             setAccountExpirationTime                     (5),
 *             clearAccountExpirationTime                   (6),
 *             getSecondsUntilAccountExpiration             (7),
 *             getPasswordChangedTime                       (8),
 *             setPasswordChangedTime                       (9),
 *             clearPasswordChangedTime                     (10),
 *             getPasswordExpirationWarnedTime              (11),
 *             setPasswordExpirationWarnedTime              (12),
 *             clearPasswordExpirationWarnedTime            (13),
 *             getSecondsUntilPasswordExpiration            (14),
 *             getSecondsUntilPasswordExpirationWarning     (15),
 *             getAuthenticationFailureTimes                (16),
 *             addAuthenticationFailureTime                 (17),
 *             setAuthenticationFailureTimes                (18),
 *             clearAuthenticationFailureTimes              (19),
 *             getSecondsUntilAuthenticationFailureUnlock   (20),
 *             getRemainingAuthenticationFailureCount       (21),
 *             getLastLoginTime                             (22),
 *             setLastLoginTime                             (23),
 *             clearLastLoginTime                           (24),
 *             getSecondsUntilIdleLockout                   (25),
 *             getPasswordResetState                        (26),
 *             setPasswordResetState                        (27),
 *             clearPasswordResetState                      (28),
 *             getSecondsUntilPasswordResetLockout          (29),
 *             getGraceLoginUseTimes                        (30),
 *             addGraceLoginUseTime                         (31),
 *             setGraceLoginUseTimes                        (32),
 *             clearGraceLoginUseTimes                      (33),
 *             getRemainingGraceLoginCount                  (34),
 *             getPasswordChangedByRequiredTime             (35),
 *             setPasswordChangedByRequiredTime             (36),
 *             clearPasswordChangedByRequiredTime           (37),
 *             getSecondsUntilRequiredChangeTime            (38),
 *             getPasswordHistory                           (39), -- Deprecated
 *             clearPasswordHistory                         (40),
 *             hasRetiredPassword                           (41),
 *             getPasswordRetiredTime                       (42),
 *             getRetiredPasswordExpirationTime             (43),
 *             purgeRetiredPassword                         (44),
 *             getAccountActivationTime                     (45),
 *             setAccountActivationTime                     (46),
 *             clearAccountActivationTime                   (47),
 *             getSecondsUntilAccountActivation             (48),
 *             getLastLoginIPAddress                        (49),
 *             setLastLoginIPAddress                        (50),
 *             clearLastLoginIPAddress                      (51),
 *             getAccountUsabilityNotices                   (52),
 *             getAccountUsabilityWarnings                  (53),
 *             getAccountUsabilityErrors                    (54),
 *             getAccountIsUsable                           (55),
 *             getAccountIsNotYetActive                     (56),
 *             getAccountIsExpired                          (57),
 *             getPasswordExpirationTime                    (58),
 *             getAccountIsFailureLocked                    (59),
 *             setAccountIsFailureLocked                    (60),
 *             getFailureLockoutTime                        (61),
 *             getAccountIsIdleLocked                       (62),
 *             getIdleLockoutTime                           (63),
 *             getAccountIsResetLocked                      (64),
 *             getResetLockoutTime                          (65),
 *             getPasswordHistoryCount                      (66),
 *             getPasswordIsExpired                         (67),
 *             getAvailableSASLMechanisms                   (68),
 *             getAvailableOTPDeliveryMechanisms            (69),
 *             getHasTOTPSharedSecret                       (70),
 *             getRegisteredYubiKeyPublicIDs                (71),
 *             addRegisteredYubiKeyPublicID                 (72),
 *             removeRegisteredYubiKeyPublicID              (73),
 *             setRegisteredYubiKeyPublicIDs                (74),
 *             clearRegisteredYubiKeyPublicIDs              (75),
 *             addTOTPSharedSecret                          (76),
 *             removeTOTPSharedSecret                       (77),
 *             setTOTPSharedSecrets                         (78),
 *             clearTOTPSharedSecrets                       (79),
 *             hasRegisteredYubiKeyPublicID                 (80),
 *             hasStaticPassword                            (81),
 *             getLastBindPasswordValidationTime            (82),
 *             getSecondsSinceLastBindPasswordValidation    (83),
 *             setLastBindPasswordValidationTime            (84),
 *             clearLastBindPasswordValidationTime          (85),
 *             getAccountIsValidationLocked                 (86),
 *             setAccountIsValidationLocked                 (87),
 *             getRecentLoginHistory                        (88),
 *             clearRecentLoginHistory                      (89),
 *             ... },
 *      opValues     SEQUENCE OF OCTET STRING OPTIONAL }
 * </PRE>
 * <BR>
 * <H2>Example</H2>
 * The following example demonstrates the use of the password policy state
 * extended operation to administratively disable a user's account:
 * <PRE>
 * PasswordPolicyStateOperation disableOp =
 *      PasswordPolicyStateOperation.createSetAccountDisabledStateOperation(
 *           true);
 * PasswordPolicyStateExtendedRequest pwpStateRequest =
 *      new PasswordPolicyStateExtendedRequest(
 *               "uid=john.doe,ou=People,dc=example,dc=com", disableOp);
 * PasswordPolicyStateExtendedResult pwpStateResult =
 *      (PasswordPolicyStateExtendedResult)
 *      connection.processExtendedOperation(pwpStateRequest);
 *
 * // NOTE:  The processExtendedOperation method will generally only throw an
 * // exception if a problem occurs while trying to send the request or read
 * // the response.  It will not throw an exception because of a non-success
 * // response.
 *
 * if (pwpStateResult.getResultCode() == ResultCode.SUCCESS)
 * {
 *   boolean isDisabled = pwpStateResult.getBooleanValue(
 *        PasswordPolicyStateOperation.OP_TYPE_GET_ACCOUNT_DISABLED_STATE);
 *   if (isDisabled)
 *   {
 *     // The user account has been disabled.
 *   }
 *   else
 *   {
 *     // The user account is not disabled.
 *   }
 * }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordPolicyStateExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.1.6.1) for the password policy state extended
   * request.
   */
  @NotNull public static final String PASSWORD_POLICY_STATE_REQUEST_OID =
       "1.3.6.1.4.1.30221.1.6.1";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1644137695182620213L;



  // The set of password policy state operations to process.
  @NotNull private final PasswordPolicyStateOperation[] operations;

  // The DN of the user account on which to operate.
  @NotNull private final String userDN;



  /**
   * Creates a new password policy state extended request with the provided user
   * DN and optional set of operations.
   *
   * @param  userDN      The DN of the user account on which to operate.
   * @param  operations  The set of password policy state operations to process.
   *                     If no operations are provided, then the effect will be
   *                     to retrieve the values of all available password policy
   *                     state properties.
   */
  public PasswordPolicyStateExtendedRequest(@NotNull final String userDN,
              @NotNull final PasswordPolicyStateOperation... operations)
  {
    this(userDN, null, operations);
  }



  /**
   * Creates a new password policy state extended request with the provided user
   * DN, optional set of operations, and optional set of controls.
   *
   * @param  userDN      The DN of the user account on which to operate.
   * @param  controls    The set of controls to include in the request.
   * @param  operations  The set of password policy state operations to process.
   *                     If no operations are provided, then the effect will be
   *                     to retrieve the values of all available password policy
   *                     state properties.
   */
  public PasswordPolicyStateExtendedRequest(@NotNull final String userDN,
              @Nullable final Control[] controls,
              @NotNull final PasswordPolicyStateOperation... operations)
  {
    super(PASSWORD_POLICY_STATE_REQUEST_OID, encodeValue(userDN, operations),
          controls);

    this.userDN     = userDN;
    this.operations = operations;
  }



  /**
   * Creates a new password policy state extended request from the provided
   * generic extended request.
   *
   * @param  extendedRequest  The generic extended request to use to create this
   *                          password policy state extended request.
   *
   * @throws  LDAPException  If a problem occurs while decoding the request.
   */
  public PasswordPolicyStateExtendedRequest(
              @NotNull final ExtendedRequest extendedRequest)
         throws LDAPException
  {
    super(extendedRequest);

    final ASN1OctetString value = extendedRequest.getValue();
    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_REQUEST_NO_VALUE.get());
    }

    final ASN1Element[] elements;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      elements = ASN1Sequence.decodeAsSequence(valueElement).elements();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_REQUEST_VALUE_NOT_SEQUENCE.get(e),
                              e);
    }

    if ((elements.length < 1) || (elements.length > 2))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_STATE_REQUEST_INVALID_ELEMENT_COUNT.get(
                                   elements.length));
    }

    userDN = ASN1OctetString.decodeAsOctetString(elements[0]).stringValue();

    if (elements.length == 1)
    {
      operations = new PasswordPolicyStateOperation[0];
    }
    else
    {
      try
      {
        final ASN1Element[] opElements =
             ASN1Sequence.decodeAsSequence(elements[1]).elements();
        operations = new PasswordPolicyStateOperation[opElements.length];
        for (int i=0; i < opElements.length; i++)
        {
          operations[i] = PasswordPolicyStateOperation.decode(opElements[i]);
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.DECODING_ERROR,
                                ERR_PWP_STATE_REQUEST_CANNOT_DECODE_OPS.get(e),
                                e);
      }
    }
  }



  /**
   * Encodes the provided information into an ASN.1 octet string that may be
   * used as the value for this extended request.
   *
   * @param  userDN      The DN of the user account on which to operate.
   * @param  operations  The set of operations to be processed.
   *
   * @return  An ASN.1 octet string containing the encoded value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(@NotNull final String userDN,
                      @Nullable final PasswordPolicyStateOperation[] operations)
  {
    final ASN1Element[] elements;
    if ((operations == null) || (operations.length == 0))
    {
      elements = new ASN1Element[]
      {
        new ASN1OctetString(userDN)
      };
    }
    else
    {
      final ASN1Element[] opElements = new ASN1Element[operations.length];
      for (int i=0; i < operations.length; i++)
      {
        opElements[i] = operations[i].encode();
      }

      elements = new ASN1Element[]
      {
        new ASN1OctetString(userDN),
        new ASN1Sequence(opElements)
      };
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Retrieves the DN of the user account on which to operate.
   *
   * @return  The DN of the user account on which to operate.
   */
  @NotNull()
  public String getUserDN()
  {
    return userDN;
  }



  /**
   * Retrieves the set of password policy state operations to be processed.
   *
   * @return  The set of password policy state operations to be processed, or
   *          an empty list if the values of all password policy state
   *          properties should be retrieved.
   */
  @NotNull()
  public PasswordPolicyStateOperation[] getOperations()
  {
    return operations;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PasswordPolicyStateExtendedResult process(
              @NotNull final LDAPConnection connection, final int depth)
         throws LDAPException
  {
    final ExtendedResult extendedResponse = super.process(connection, depth);
    return new PasswordPolicyStateExtendedResult(extendedResponse);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PasswordPolicyStateExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public PasswordPolicyStateExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final PasswordPolicyStateExtendedRequest r =
         new PasswordPolicyStateExtendedRequest(userDN, controls, operations);
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
    return INFO_EXTENDED_REQUEST_NAME_PW_POLICY_STATE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordPolicyStateExtendedRequest(userDN='");
    buffer.append(userDN);

    if (operations.length > 0)
    {
      buffer.append("', operations={");
      for (int i=0; i < operations.length; i++)
      {
        if (i > 0)
        {
          buffer.append(", ");
        }

        operations[i].toString(buffer);
      }
      buffer.append('}');
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
