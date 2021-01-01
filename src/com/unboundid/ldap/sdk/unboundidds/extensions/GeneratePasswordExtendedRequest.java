/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1Null;
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
 * to request that the server suggest one or more passwords that the client may
 * use in new entries, password changes, or administrative password resets.
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
 * This extended request has an OID of "1.3.6.1.4.1.30221.2.6.62" and a value\
 * with the following encoding:
 * <BR><BR>
 * <PRE>
 *   GeneratePasswordRequest ::= SEQUENCE {
 *        passwordPolicySelection     CHOICE {
 *             defaultPolicy        [0] NULL,
 *             passwordPolicyDN     [1] LDAPDN,
 *             targetEntryDN        [2] LDAPDN,
 *             ... },
 *        numberOfPasswords      [3] INTEGER DEFAULT 1,
 *        validationAttempts     [4] INTEGER DEFAULT 5,
 *        ... }
 * </PRE>
 * <BR><BR>
 * The "passwordPolicySelection" element allows the client to indicate which
 * password policy (along with its associated password generator and password
 * validators) should be used in the course of generating the passwords, and
 * available options include:
 * <UL>
 *   <LI>defaultPolicy -- Indicates that the server should use the default
 *       password policy as defined in the configuration.</LI>
 *   <LI>passwordPolicyDN -- Specifies the DN of the password policy that should
 *       be used.</LI>
 *   <LI>targetEntryDN -- Specifies the DN of the target entry for which the
 *       passwords are to be generated.  If this entry exists, then the password
 *       policy that governs it will be used.  If the entry does not exist, then
 *       the server will generate a stub of an entry with the provided DN and
 *       compute virtual attributes for that entry to account for the
 *       possibility that a password policy may be assigned by a virtual
 *       attribute, but will fall back to using the default password policy as
 *       defined in the configuration.
 * </UL>
 * <BR><BR>
 * The "numberOfPasswords" element indicates the number of passwords that the
 * server should generate, since it may be beneficial for the server to suggest
 * multiple passwords and allow the user to choose one.  If specified, then the
 * value must be greater than or equal to one.
 * <BR><BR>
 * The "validationAttempts" element indicates the number of attempts that the
 * server should make to generate each password in a way that will satisfy the
 * set of validators associated with the selected password policy.  A value of
 * zero indicates that no validation should be performed.  A value of one will
 * cause the server to invoke password validators on each generated password,
 * still returning that password but also including information about potential
 * reasons that generated password may not pass validation.  A value that is
 * greater than one will cause the server to re-generate each password up to
 * the specified number of times if the previous attempt resulted in a password
 * that did not satisfy all of the associated password validators.  In the event
 * that no acceptable password could be generated after exhausting all attempts,
 * the server will select the last one generated, but will provide a list of
 * reasons that the password was not considered acceptable so that they may be
 * provided to the end user as additional guidance when choosing a password.
 * <BR><BR>
 * If the generate password operation is processed successfully, then the server
 * will return a {@link GeneratePasswordExtendedResult} response with the
 * passwords that it generated and other relevant information.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GeneratePasswordExtendedRequest
       extends ExtendedRequest
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.6.62) for the generate password extended
   * request.
   */
  @NotNull public static final String GENERATE_PASSWORD_REQUEST_OID =
       "1.3.6.1.4.1.30221.2.6.62";



  /**
   * The BER type to use for the element that specifies the number of passwords
   * to generate.
   */
  private static final byte TYPE_NUMBER_OF_PASSWORDS = (byte) 0x83;



  /**
   * The default value for the number of passwords to generate.
   */
  private static final int DEFAULT_NUMBER_OF_PASSWORDS = 1;



  /**
   * The BER type to use for the element that specifies the number of validation
   * attempts to perform.
   */
  private static final byte TYPE_VALIDATION_ATTEMPTS = (byte) 0x84;



  /**
   * The default number of validation attempts to perform.
   */
  private static final int DEFAULT_VALIDATION_ATTEMPTS = 5;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4264500486902843854L;



  // The number of passwords that should be generated.
  private final int numberOfPasswords;

  // The number of validation attempts to make for each generated password.
  private final int numberOfValidationAttempts;

  // The password policy selection type for the request.
  @NotNull private final GeneratePasswordPolicySelectionType
       passwordPolicySelectionType;

  // The DN of the password policy that should be used in conjunction with the
  // PASSWORD_POLICY_DN password policy selection type.
  @Nullable private final String passwordPolicyDN;

  // The DN of the target entry that should be used in conjunction with the
  // TARGET_ENTRY_DN password policy selection type.
  @Nullable private final String targetEntryDN;



  /**
   * Creates a new generate password extended request with all the default
   * settings.
   *
   * @param  controls  The set of controls to include in the request.  It may be
   *                   {@code null} or empty if there should not be any request
   *                   controls.
   */
  public GeneratePasswordExtendedRequest(@Nullable final Control... controls)
  {
    this(GeneratePasswordPolicySelectionType.DEFAULT_POLICY, null, null,
         DEFAULT_NUMBER_OF_PASSWORDS, DEFAULT_VALIDATION_ATTEMPTS, controls);
  }



  /**
   * Creates a new generate password extended request with the provided
   * settings.
   *
   * @param  passwordPolicySelectionType
   *              The password policy selection type to use.  It must not be
   *              {@code null}.
   * @param  passwordPolicyDN
   *              The password policy DN to use in conjunction with the
   *              {@link GeneratePasswordPolicySelectionType#PASSWORD_POLICY_DN}
   *              password policy selection type.  It must be non-{@code null}
   *              when used in conjunction with that policy selection type, and
   *              it must be {@code null} for all other selection types.
   * @param  targetEntryDN
   *              The target entry DN to use in conjunction with the
   *              {@link GeneratePasswordPolicySelectionType#TARGET_ENTRY_DN}
   *              password policy selection type.  It must be non-{@code null}
   *              when used in conjunction with that policy selection type, and
   *              it must be {@code null} for all other selection types.
   * @param  numberOfPasswords
   *              The number of passwords to generate.  The value must be
   *              greater than or equal to one.
   * @param  numberOfValidationAttempts
   *              The number of attempts that should be made to generate each
   *              password in an attempt to obtain a password that satisfies the
   *              associated set of password validators.  The value must be
   *              greater than or equal to zero.
   * @param  controls
   *              The set of controls to include in the request.  It may be
   *              {@code null} or empty if there should not be any request
   *              controls.
   */
  private GeneratePasswordExtendedRequest(
       @NotNull final GeneratePasswordPolicySelectionType
            passwordPolicySelectionType,
       @Nullable final String passwordPolicyDN,
       @Nullable final String targetEntryDN,
       final int numberOfPasswords,
       final int numberOfValidationAttempts,
       @Nullable final Control... controls)
  {
    super(GENERATE_PASSWORD_REQUEST_OID,
         encodeValue(passwordPolicySelectionType, passwordPolicyDN,
              targetEntryDN, numberOfPasswords, numberOfValidationAttempts),
         controls);

    this.passwordPolicySelectionType = passwordPolicySelectionType;
    this.passwordPolicyDN = passwordPolicyDN;
    this.targetEntryDN = targetEntryDN;
    this.numberOfPasswords = numberOfPasswords;
    this.numberOfValidationAttempts = numberOfValidationAttempts;
  }



  /**
   * Uses the provided information to generate an ASN.1 octet string that may be
   * used as the value of a generate password extended request.
   *
   * @param  passwordPolicySelectionType
   *              The password policy selection type to use.  It must not be
   *              {@code null}.
   * @param  passwordPolicyDN
   *              The password policy DN to use in conjunction with the
   *              {@link GeneratePasswordPolicySelectionType#PASSWORD_POLICY_DN}
   *              password policy selection type.  It must be non-{@code null}
   *              when used in conjunction with that policy selection type, and
   *              it must be {@code null} for all other selection types.
   * @param  targetEntryDN
   *              The target entry DN to use in conjunction with the
   *              {@link GeneratePasswordPolicySelectionType#TARGET_ENTRY_DN}
   *              password policy selection type.  It must be non-{@code null}
   *              when used in conjunction with that policy selection type, and
   *              it must be {@code null} for all other selection types.
   * @param  numberOfPasswords
   *              The number of passwords to generate.  The value must be
   *              greater than or equal to one.
   * @param  numberOfValidationAttempts
   *              The number of attempts that should be made to generate each
   *              password in an attempt to obtain a password that satisfies the
   *              associated set of password validators.  The value must be
   *              greater than or equal to zero.
   *
   * @return  An ASN.1 octet string that may be used as the value of a generate
   *          password extended request with the provided information, or
   *          {@code null} if the request uses all the default settings and no
   *          value is needed.
   */
  @Nullable()
  private static ASN1OctetString encodeValue(
       @NotNull final GeneratePasswordPolicySelectionType
            passwordPolicySelectionType,
       @Nullable final String passwordPolicyDN,
       @Nullable final String targetEntryDN,
       final int numberOfPasswords, final int numberOfValidationAttempts)
  {
    Validator.ensureNotNullWithMessage(passwordPolicySelectionType,
         "GeneratePasswordExtendedRequest.passwordPolicySelectionType must " +
              "not be null.");

    final List<ASN1Element> elements = new ArrayList<>(3);
    switch (passwordPolicySelectionType)
    {
      case DEFAULT_POLICY:
        Validator.ensureTrue((passwordPolicyDN == null),
             "GeneratePasswordExtendedRequest.passwordPolicyDN must be null " +
                  "when using a password policy selection type of " +
                  passwordPolicySelectionType + '.');
        Validator.ensureTrue((targetEntryDN == null),
             "GeneratePasswordExtendedRequest.targetEntryDN must be null " +
                  "when using a password policy selection type of " +
                  passwordPolicySelectionType + '.');

        if ((numberOfPasswords == DEFAULT_NUMBER_OF_PASSWORDS) &&
             (numberOfValidationAttempts == DEFAULT_VALIDATION_ATTEMPTS))
        {
          return null;
        }

        elements.add(new ASN1Null(passwordPolicySelectionType.getBERType()));
        break;

      case PASSWORD_POLICY_DN:
        Validator.ensureNotNullWithMessage(passwordPolicyDN,
             "GeneratePasswordExtendedRequest.passwordPolicyDN must not be " +
                  "null when using a password policy selection type of " +
                  passwordPolicySelectionType + '.');
        Validator.ensureTrue((targetEntryDN == null),
             "GeneratePasswordExtendedRequest.targetEntryDN must be null " +
                  "when using a password policy selection type of " +
                  passwordPolicySelectionType + '.');

        elements.add(new ASN1OctetString(
             passwordPolicySelectionType.getBERType(), passwordPolicyDN));
        break;

      case TARGET_ENTRY_DN:
        Validator.ensureTrue((passwordPolicyDN == null),
             "GeneratePasswordExtendedRequest.passwordPolicyDN must be null " +
                  "when using a password policy selection type of " +
                  passwordPolicySelectionType + '.');
        Validator.ensureNotNullWithMessage(targetEntryDN,
             "GeneratePasswordExtendedRequest.targetEntryDN must not be null " +
                  "when using a password policy selection type of " +
                  passwordPolicySelectionType + '.');

        elements.add(new ASN1OctetString(
             passwordPolicySelectionType.getBERType(), targetEntryDN));
        break;
    }

    if (numberOfPasswords != DEFAULT_NUMBER_OF_PASSWORDS)
    {
      Validator.ensureTrue((numberOfPasswords >= 1),
           "GeneratePasswordExtendedRequest.numberOfPasswords must be " +
                "greater than or equal to one.");
      elements.add(new ASN1Integer(TYPE_NUMBER_OF_PASSWORDS,
           numberOfPasswords));
    }

    if (numberOfValidationAttempts != DEFAULT_VALIDATION_ATTEMPTS)
    {
      Validator.ensureTrue((numberOfValidationAttempts >= 0),
           "GeneratePasswordExtendedRequest.validationAttempts must be " +
                "greater than or equal to zero.");
      elements.add(new ASN1Integer(TYPE_VALIDATION_ATTEMPTS,
           numberOfValidationAttempts));
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * Creates a new generate password extended request that is decoded from the
   * provided generic request.
   *
   * @param  request  The extended request to be decoded as a generate password
   *                  extended request.  It must not be {@code null}.
   *
   * @throws  LDAPException  If the provided extended request cannot be decoded
   *                         as a generate password request.
   */
  public GeneratePasswordExtendedRequest(@NotNull final ExtendedRequest request)
         throws LDAPException
  {
    super(request);

    final ASN1OctetString value = request.getValue();
    if (value == null)
    {
      passwordPolicySelectionType =
           GeneratePasswordPolicySelectionType.DEFAULT_POLICY;
      passwordPolicyDN = null;
      targetEntryDN = null;
      numberOfPasswords = DEFAULT_NUMBER_OF_PASSWORDS;
      numberOfValidationAttempts = DEFAULT_VALIDATION_ATTEMPTS;
      return;
    }

    try
    {
      final ASN1Element[] elements =
           ASN1Sequence.decodeAsSequence(value.getValue()).elements();

      passwordPolicySelectionType =
           GeneratePasswordPolicySelectionType.forType(elements[0].getType());
      if (passwordPolicySelectionType == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GENERATE_PASSWORD_REQUEST_UNSUPPORTED_SELECTION_TYPE.get(
                  StaticUtils.toHex(elements[0].getType())));
      }

      switch (passwordPolicySelectionType)
      {
        case PASSWORD_POLICY_DN:
          passwordPolicyDN = elements[0].decodeAsOctetString().stringValue();
          targetEntryDN = null;
          break;

        case TARGET_ENTRY_DN:
          targetEntryDN = elements[0].decodeAsOctetString().stringValue();
          passwordPolicyDN = null;
          break;

        case DEFAULT_POLICY:
        default:
          passwordPolicyDN = null;
          targetEntryDN = null;
          break;
      }

      int numPasswords = DEFAULT_NUMBER_OF_PASSWORDS;
      int numAttempts = DEFAULT_VALIDATION_ATTEMPTS;
      for (int i=1; i < elements.length; i++)
      {
        switch (elements[i].getType())
        {
          case TYPE_NUMBER_OF_PASSWORDS:
            numPasswords = ASN1Integer.decodeAsInteger(elements[i]).intValue();
            if (numPasswords < 1)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_GENERATE_PASSWORD_REQUEST_INVALID_NUM_PASSWORDS.get(
                        numPasswords));
            }
            break;

          case TYPE_VALIDATION_ATTEMPTS:
            numAttempts = ASN1Integer.decodeAsInteger(elements[i]).intValue();
            if (numAttempts < 0)
            {
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_GENERATE_PASSWORD_REQUEST_INVALID_NUM_ATTEMPTS.get(
                        numAttempts));
            }
            break;
        }
      }

      numberOfPasswords = numPasswords;
      numberOfValidationAttempts = numAttempts;
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw e;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GENERATE_PASSWORD_REQUEST_DECODING_ERROR.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Creates a generate password extended request that will use the default
   * password policy (as defined in the server configuration) to determine which
   * password generator and validators should be used.
   *
   * @param  numberOfPasswords
   *              The number of passwords to generate.  The value must be
   *              greater than or equal to one.
   * @param  numberOfValidationAttempts
   *              The number of attempts that should be made to generate each
   *              password in an attempt to obtain a password that satisfies the
   *              associated set of password validators.  The value must be
   *              greater than or equal to zero.
   * @param  controls
   *              The set of controls to include in the request.  It may be
   *              {@code null} or empty if there should not be any request
   *              controls.
   *
   * @return  The generate password extended request that was created.
   */
  @NotNull()
  public static GeneratePasswordExtendedRequest createDefaultPolicyRequest(
                     final int numberOfPasswords,
                     final int numberOfValidationAttempts,
                     @Nullable final Control... controls)
  {
    return new GeneratePasswordExtendedRequest(
         GeneratePasswordPolicySelectionType.DEFAULT_POLICY, null, null,
         numberOfPasswords, numberOfValidationAttempts, controls);
  }



  /**
   * Creates a generate password extended request that will use the password
   * policy defined in the entry with the specified DN to determine which
   * password generator and validators should be used.
   *
   * @param  passwordPolicyDN
   *              The DN of the entry that defines the password policy to use to
   *              determine which password generator and validators should be
   *              used.  It must not be {@code null}.
   * @param  numberOfPasswords
   *              The number of passwords to generate.  The value must be
   *              greater than or equal to one.
   * @param  numberOfValidationAttempts
   *              The number of attempts that should be made to generate each
   *              password in an attempt to obtain a password that satisfies the
   *              associated set of password validators.  The value must be
   *              greater than or equal to zero.
   * @param  controls
   *              The set of controls to include in the request.  It may be
   *              {@code null} or empty if there should not be any request
   *              controls.
   *
   * @return  The generate password extended request that was created.
   */
  @NotNull()
  public static GeneratePasswordExtendedRequest createPasswordPolicyDNRequest(
                     @NotNull final String passwordPolicyDN,
                     final int numberOfPasswords,
                     final int numberOfValidationAttempts,
                     @Nullable final Control... controls)
  {
    return new GeneratePasswordExtendedRequest(
         GeneratePasswordPolicySelectionType.PASSWORD_POLICY_DN,
         passwordPolicyDN, null, numberOfPasswords, numberOfValidationAttempts,
         controls);
  }



  /**
   * Creates a generate password extended request that will use the password
   * policy that governs the specified entry to determine which
   * password generator and validators should be used.  If the target entry does
   * not exist, then the server will generate a stub of an entry and compute
   * virtual attributes for that entry to account for the possibility that the
   * password policy may be specified using a virtual attribute.
   *
   * @param  targetEntryDN
   *              The DN of the entry whose governing password policy should be
   *              used.  It must not be {@code null}.
   * @param  numberOfPasswords
   *              The number of passwords to generate.  The value must be
   *              greater than or equal to one.
   * @param  numberOfValidationAttempts
   *              The number of attempts that should be made to generate each
   *              password in an attempt to obtain a password that satisfies the
   *              associated set of password validators.  The value must be
   *              greater than or equal to zero.
   * @param  controls
   *              The set of controls to include in the request.  It may be
   *              {@code null} or empty if there should not be any request
   *              controls.
   *
   * @return  The generate password extended request that was created.
   */
  @NotNull()
  public static GeneratePasswordExtendedRequest createTargetEntryDNRequest(
                     @NotNull final String targetEntryDN,
                     final int numberOfPasswords,
                     final int numberOfValidationAttempts,
                     @Nullable final Control... controls)
  {
    return new GeneratePasswordExtendedRequest(
         GeneratePasswordPolicySelectionType.TARGET_ENTRY_DN, null,
         targetEntryDN, numberOfPasswords, numberOfValidationAttempts,
         controls);
  }



  /**
   * Retrieves the password policy selection type for this request.
   *
   * @return  The password policy selection type for this request.
   */
  @NotNull()
  public GeneratePasswordPolicySelectionType getPasswordPolicySelectionType()
  {
    return passwordPolicySelectionType;
  }



  /**
   * Retrieves the DN of the entry that defines the password policy that should
   * be used when generating and validating passwords.  This will only be
   * available for the
   * {@link GeneratePasswordPolicySelectionType#PASSWORD_POLICY_DN} password
   * policy selection type.
   *
   * @return  The DN of the entry that defines the password policy that should
   *          be used when generating and validating the passwords, or
   *          {@code null} if the password policy selection type is anything
   *          other than {@code PASSWORD_POLICY_DN}.
   */
  @Nullable()
  public String getPasswordPolicyDN()
  {
    return passwordPolicyDN;
  }



  /**
   * Retrieves the DN of the target entry whose governing password policy should
   * be used when generating and validating passwords.  This will only be
   * available for the
   * {@link GeneratePasswordPolicySelectionType#TARGET_ENTRY_DN} password
   * policy selection type.
   *
   * @return  The DN of the target entry whose governing password policy should
   *          be used when generating and validating the passwords, or
   *          {@code null} if the password policy selection type is anything
   *          other than {@code TARGET_ENTRY_DN}.
   */
  @Nullable()
  public String getTargetEntryDN()
  {
    return targetEntryDN;
  }



  /**
   * Retrieves the number of passwords that the client wants the server to
   * generate.  Note that the server may choose to generate fewer passwords than
   * this, based on its configuration.
   *
   * @return  The number of passwords that the client wants the server to
   *          generate.
   */
  public int getNumberOfPasswords()
  {
    return numberOfPasswords;
  }



  /**
   * Retrieves the number of maximum number of attempts that the client wants
   * the server to make when generating each password in the hope that the
   * generated password will satisfy the validation criteria specified in the
   * associated password policy.  Note that the server may choose to make fewer
   * validation attempts than this, based on its configuration.
   *
   * @return  The number maximum number of validation attempts that the client
   *          wants the server to make, or zero if the server should not attempt
   *          to validate the generated passwords.
   */
  public int getNumberOfValidationAttempts()
  {
    return numberOfValidationAttempts;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  protected GeneratePasswordExtendedResult process(
                 @NotNull final LDAPConnection connection, final int depth)
            throws LDAPException
  {
    return new GeneratePasswordExtendedResult(super.process(connection, depth));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GeneratePasswordExtendedRequest duplicate()
  {
    return duplicate(getControls());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GeneratePasswordExtendedRequest duplicate(
              @Nullable final Control[] controls)
  {
    final GeneratePasswordExtendedRequest r =
         new GeneratePasswordExtendedRequest(passwordPolicySelectionType,
              passwordPolicyDN, targetEntryDN, numberOfPasswords,
              numberOfValidationAttempts, controls);
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
    return INFO_GENERATE_PASSWORD_REQUEST_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GeneratePasswordExtendedRequest(" +
         "passwordPolicySelectionType='");
    buffer.append(passwordPolicySelectionType.name());
    buffer.append('\'');

    switch (passwordPolicySelectionType)
    {
      case PASSWORD_POLICY_DN:
        buffer.append(", passwordPolicyDN='");
        buffer.append(passwordPolicyDN);
        buffer.append('\'');
        break;
      case TARGET_ENTRY_DN:
        buffer.append(", targetEntryDN='");
        buffer.append(targetEntryDN);
        buffer.append('\'');
        break;
    }

    buffer.append(", numberOfPasswords=");
    buffer.append(numberOfPasswords);
    buffer.append(", numberOfValidationAttempts=");
    buffer.append(numberOfValidationAttempts);

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
