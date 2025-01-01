/*
 * Copyright 2015-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2025 Ping Identity Corporation
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
 * Copyright (C) 2015-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.JSONControlDecodeHelper;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONArray;
import com.unboundid.util.json.JSONField;
import com.unboundid.util.json.JSONNumber;
import com.unboundid.util.json.JSONObject;
import com.unboundid.util.json.JSONString;
import com.unboundid.util.json.JSONValue;

import static com.unboundid.ldap.sdk.unboundidds.controls.ControlMessages.*;



/**
 * This class provides an implementation of a response control that can be
 * included in a bind response with information about any password policy state
 * notices, warnings, and/or errors for the user.
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
 * This control has an OID of 1.3.6.1.4.1.30221.2.5.47, a criticality of
 * {@code false}, and a value with the following encoding:
 * <PRE>
 *   GetPasswordPolicyStateIssuesResponse ::= SEQUENCE {
 *        notices               [0] SEQUENCE OF SEQUENCE {
 *             type        INTEGER,
 *             name        OCTET STRING,
 *             message     OCTET STRING OPTIONAL } OPTIONAL,
 *        warnings              [1] SEQUENCE OF SEQUENCE {
 *             type        INTEGER,
 *             name        OCTET STRING,
 *             message     OCTET STRING OPTIONAL } OPTIONAL,
 *        errors                [2] SEQUENCE OF SEQUENCE {
 *             type        INTEGER,
 *             name        OCTET STRING,
 *             message     OCTET STRING OPTIONAL } OPTIONAL,
 *        authFailureReason     [3] SEQUENCE {
 *             type        INTEGER,
 *             name        OCTET STRING,
 *             message     OCTET STRING OPTIONAL } OPTIONAL,
 *        ... }
 * </PRE>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class GetPasswordPolicyStateIssuesResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.30221.2.5.47) for the get password policy state issues
   * response control.
   */
  @NotNull public static final String
       GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID =
            "1.3.6.1.4.1.30221.2.5.47";



  /**
   * The BER type to use for the value sequence element that holds the set of
   * account usability notices.
   */
  private static final byte TYPE_NOTICES = (byte) 0xA0;



  /**
   * The BER type to use for the value sequence element that holds the set of
   * account usability warnings.
   */
  private static final byte TYPE_WARNINGS = (byte) 0xA1;



  /**
   * The BER type to use for the value sequence element that holds the set of
   * account usability errors.
   */
  private static final byte TYPE_ERRORS = (byte) 0xA2;



  /**
   * The BER type to use for the value sequence element that holds the
   * authentication failure reason.
   */
  private static final byte TYPE_AUTH_FAILURE_REASON = (byte) 0xA3;



  /**
   * The name of the field used to represent the authentication failure reason
   * in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_AUTH_FAILURE_REASON =
       "authentication-failure-reason";



  /**
   * The name of the field used to represent the set of password policy state
   * errors in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ERRORS = "errors";



  /**
   * The name of the field used to represent the ID of a password policy state
   * issue or auth failure reason in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_ID = "id";



  /**
   * The name of the field used to represent the message for a password policy
   * state issue or auth failure reason in the JSON representation of this
   * control.
   */
  @NotNull private static final String JSON_FIELD_MESSAGE = "message";



  /**
   * The name of the field used to represent the name of a password policy state
   * issue or auth failure reason in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_NAME = "name";



  /**
   * The name of the field used to represent the set of password policy state
   * notices in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_NOTICES = "notices";



  /**
   * The name of the field used to represent the set of password policy state
   * warnings in the JSON representation of this control.
   */
  @NotNull private static final String JSON_FIELD_WARNINGS = "warnings";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7509027658735069270L;



  // The authentication failure reason for the bind operation.
  @Nullable private final AuthenticationFailureReason authFailureReason;

  // The set of account usability errors.
  @NotNull private final List<PasswordPolicyStateAccountUsabilityError> errors;

  // The set of account usability notices.
  @NotNull private final List<PasswordPolicyStateAccountUsabilityNotice>
       notices;

  // The set of account usability warnings.
  @NotNull private final List<PasswordPolicyStateAccountUsabilityWarning>
       warnings;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  GetPasswordPolicyStateIssuesResponseControl()
  {
    authFailureReason = null;
    notices = Collections.emptyList();
    warnings = Collections.emptyList();
    errors = Collections.emptyList();
  }



  /**
   * Creates a new instance of this control with the provided information.
   *
   * @param  notices   The set of password policy state usability notices to
   *                   include.  It may be {@code null} or empty if there are
   *                   no notices.
   * @param  warnings  The set of password policy state usability warnings to
   *                   include.  It may be {@code null} or empty if there are
   *                   no warnings.
   * @param  errors    The set of password policy state usability errors to
   *                   include.  It may be {@code null} or empty if there are
   *                   no errors.
   */
  public GetPasswordPolicyStateIssuesResponseControl(
       @Nullable final List<PasswordPolicyStateAccountUsabilityNotice> notices,
       @Nullable final List<PasswordPolicyStateAccountUsabilityWarning>
            warnings,
       @Nullable final List<PasswordPolicyStateAccountUsabilityError> errors)
  {
    this(notices, warnings, errors, null);
  }



  /**
   * Creates a new instance of this control with the provided information.
   *
   * @param  notices            The set of password policy state usability
   *                            notices to include.  It may be {@code null} or
   *                            empty if there are no notices.
   * @param  warnings           The set of password policy state usability
   *                            warnings to include.  It may be {@code null} or
   *                            empty if there are no warnings.
   * @param  errors             The set of password policy state usability
   *                            errors to include.  It may be {@code null} or
   *                            empty if there are no errors.
   * @param  authFailureReason  The authentication failure reason for the bind
   *                            operation.  It may be {@code null} if there is
   *                            no authentication failure reason.
   */
  public GetPasswordPolicyStateIssuesResponseControl(
       @Nullable final List<PasswordPolicyStateAccountUsabilityNotice> notices,
       @Nullable final List<PasswordPolicyStateAccountUsabilityWarning>
            warnings,
       @Nullable final List<PasswordPolicyStateAccountUsabilityError> errors,
       @Nullable final AuthenticationFailureReason authFailureReason)
  {
    super(GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID, false,
         encodeValue(notices, warnings, errors, authFailureReason));

    this.authFailureReason = authFailureReason;

    if (notices == null)
    {
      this.notices = Collections.emptyList();
    }
    else
    {
      this.notices = Collections.unmodifiableList(new ArrayList<>(notices));
    }

    if (warnings == null)
    {
      this.warnings = Collections.emptyList();
    }
    else
    {
      this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
    }

    if (errors == null)
    {
      this.errors = Collections.emptyList();
    }
    else
    {
      this.errors = Collections.unmodifiableList(new ArrayList<>(errors));
    }
  }



  /**
   * Creates a new instance of this control that is decoded from the provided
   * generic control.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether this control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.
   *
   * @throws LDAPException  If a problem is encountered while attempting to
   *                         decode the provided control as a get password
   *                         policy state issues response control.
   */
  public GetPasswordPolicyStateIssuesResponseControl(@NotNull final String oid,
              final boolean isCritical, @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_GET_PWP_STATE_ISSUES_RESPONSE_NO_VALUE.get());
    }

    AuthenticationFailureReason afr = null;
    List<PasswordPolicyStateAccountUsabilityNotice> nList =
         Collections.emptyList();
    List<PasswordPolicyStateAccountUsabilityWarning> wList =
         Collections.emptyList();
    List<PasswordPolicyStateAccountUsabilityError> eList =
         Collections.emptyList();

    try
    {
      for (final ASN1Element e :
           ASN1Sequence.decodeAsSequence(value.getValue()).elements())
      {
        switch (e.getType())
        {
          case TYPE_NOTICES:
            nList = new ArrayList<>(10);
            for (final ASN1Element ne :
                 ASN1Sequence.decodeAsSequence(e).elements())
            {
              final ASN1Element[] noticeElements =
                   ASN1Sequence.decodeAsSequence(ne).elements();
              final int type = ASN1Integer.decodeAsInteger(
                   noticeElements[0]).intValue();
              final String name = ASN1OctetString.decodeAsOctetString(
                   noticeElements[1]).stringValue();

              final String message;
              if (noticeElements.length == 3)
              {
                message = ASN1OctetString.decodeAsOctetString(
                     noticeElements[2]).stringValue();
              }
              else
              {
                message = null;
              }

              nList.add(new PasswordPolicyStateAccountUsabilityNotice(type,
                   name, message));
            }
            nList = Collections.unmodifiableList(nList);
            break;

          case TYPE_WARNINGS:
            wList =
                 new ArrayList<>(10);
            for (final ASN1Element we :
                 ASN1Sequence.decodeAsSequence(e).elements())
            {
              final ASN1Element[] warningElements =
                   ASN1Sequence.decodeAsSequence(we).elements();
              final int type = ASN1Integer.decodeAsInteger(
                   warningElements[0]).intValue();
              final String name = ASN1OctetString.decodeAsOctetString(
                   warningElements[1]).stringValue();

              final String message;
              if (warningElements.length == 3)
              {
                message = ASN1OctetString.decodeAsOctetString(
                     warningElements[2]).stringValue();
              }
              else
              {
                message = null;
              }

              wList.add(new PasswordPolicyStateAccountUsabilityWarning(type,
                   name, message));
            }
            wList = Collections.unmodifiableList(wList);
            break;

          case TYPE_ERRORS:
            eList = new ArrayList<>(10);
            for (final ASN1Element ee :
                 ASN1Sequence.decodeAsSequence(e).elements())
            {
              final ASN1Element[] errorElements =
                   ASN1Sequence.decodeAsSequence(ee).elements();
              final int type = ASN1Integer.decodeAsInteger(
                   errorElements[0]).intValue();
              final String name = ASN1OctetString.decodeAsOctetString(
                   errorElements[1]).stringValue();

              final String message;
              if (errorElements.length == 3)
              {
                message = ASN1OctetString.decodeAsOctetString(
                     errorElements[2]).stringValue();
              }
              else
              {
                message = null;
              }

              eList.add(new PasswordPolicyStateAccountUsabilityError(type,
                   name, message));
            }
            eList = Collections.unmodifiableList(eList);
            break;

          case TYPE_AUTH_FAILURE_REASON:
            final ASN1Element[] afrElements =
                 ASN1Sequence.decodeAsSequence(e).elements();
            final int afrType =
                 ASN1Integer.decodeAsInteger(afrElements[0]).intValue();
            final String afrName = ASN1OctetString.decodeAsOctetString(
                 afrElements[1]).stringValue();

            final String afrMessage;
            if (afrElements.length == 3)
            {
              afrMessage = ASN1OctetString.decodeAsOctetString(
                   afrElements[2]).stringValue();
            }
            else
            {
              afrMessage = null;
            }
            afr = new AuthenticationFailureReason(afrType, afrName, afrMessage);
            break;

          default:
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_UNEXPECTED_TYPE.get(
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
           ERR_GET_PWP_STATE_ISSUES_RESPONSE_CANNOT_DECODE.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    authFailureReason = afr;
    notices           = nList;
    warnings          = wList;
    errors            = eList;
  }



  /**
   * Encodes the provided information into an ASN.1 octet string suitable for
   * use as the value of this control.
   *
   * @param  notices            The set of password policy state usability
   *                            notices to include.  It may be {@code null} or
   *                            empty if there are no notices.
   * @param  warnings           The set of password policy state usability
   *                            warnings to include.  It may be {@code null} or
   *                            empty if there are no warnings.
   * @param  errors             The set of password policy state usability
   *                            errors to include.  It may be {@code null} or
   *                            empty if there are no errors.
   * @param  authFailureReason  The authentication failure reason for the bind
   *                            operation.  It may be {@code null} if there is
   *                            no authentication failure reason.
   *
   * @return  The ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @Nullable final List<PasswordPolicyStateAccountUsabilityNotice> notices,
       @Nullable final List<PasswordPolicyStateAccountUsabilityWarning>
            warnings,
       @Nullable final List<PasswordPolicyStateAccountUsabilityError> errors,
       @Nullable final AuthenticationFailureReason authFailureReason)
  {
    final ArrayList<ASN1Element> elements = new ArrayList<>(4);
    if ((notices != null) && (! notices.isEmpty()))
    {
      final ArrayList<ASN1Element> noticeElements =
           new ArrayList<>(notices.size());
      for (final PasswordPolicyStateAccountUsabilityNotice n : notices)
      {
        if (n.getMessage() == null)
        {
          noticeElements.add(new ASN1Sequence(
               new ASN1Integer(n.getIntValue()),
               new ASN1OctetString(n.getName())));
        }
        else
        {
          noticeElements.add(new ASN1Sequence(
               new ASN1Integer(n.getIntValue()),
               new ASN1OctetString(n.getName()),
               new ASN1OctetString(n.getMessage())));
        }
      }

      elements.add(new ASN1Sequence(TYPE_NOTICES, noticeElements));
    }

    if ((warnings != null) && (! warnings.isEmpty()))
    {
      final ArrayList<ASN1Element> warningElements =
           new ArrayList<>(warnings.size());
      for (final PasswordPolicyStateAccountUsabilityWarning w : warnings)
      {
        if (w.getMessage() == null)
        {
          warningElements.add(new ASN1Sequence(
               new ASN1Integer(w.getIntValue()),
               new ASN1OctetString(w.getName())));
        }
        else
        {
          warningElements.add(new ASN1Sequence(
               new ASN1Integer(w.getIntValue()),
               new ASN1OctetString(w.getName()),
               new ASN1OctetString(w.getMessage())));
        }
      }

      elements.add(new ASN1Sequence(TYPE_WARNINGS, warningElements));
    }

    if ((errors != null) && (! errors.isEmpty()))
    {
      final ArrayList<ASN1Element> errorElements =
           new ArrayList<>(errors.size());
      for (final PasswordPolicyStateAccountUsabilityError e : errors)
      {
        if (e.getMessage() == null)
        {
          errorElements.add(new ASN1Sequence(
               new ASN1Integer(e.getIntValue()),
               new ASN1OctetString(e.getName())));
        }
        else
        {
          errorElements.add(new ASN1Sequence(
               new ASN1Integer(e.getIntValue()),
               new ASN1OctetString(e.getName()),
               new ASN1OctetString(e.getMessage())));
        }
      }

      elements.add(new ASN1Sequence(TYPE_ERRORS, errorElements));
    }

    if (authFailureReason != null)
    {
      if (authFailureReason.getMessage() == null)
      {
        elements.add(new ASN1Sequence(TYPE_AUTH_FAILURE_REASON,
             new ASN1Integer(authFailureReason.getIntValue()),
             new ASN1OctetString(authFailureReason.getName())));
      }
      else
      {
        elements.add(new ASN1Sequence(TYPE_AUTH_FAILURE_REASON,
             new ASN1Integer(authFailureReason.getIntValue()),
             new ASN1OctetString(authFailureReason.getName()),
             new ASN1OctetString(authFailureReason.getMessage())));
      }
    }

    return new ASN1OctetString(new ASN1Sequence(elements).encode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public GetPasswordPolicyStateIssuesResponseControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
          throws LDAPException
  {
    return new GetPasswordPolicyStateIssuesResponseControl(oid, isCritical,
         value);
  }



  /**
   * Retrieves the set of account usability notices for the user.
   *
   * @return  The set of account usability notices for the user, or an empty
   *          list if there are no notices.
   */
  @NotNull()
  public List<PasswordPolicyStateAccountUsabilityNotice> getNotices()
  {
    return notices;
  }



  /**
   * Retrieves the set of account usability warnings for the user.
   *
   * @return  The set of account usability warnings for the user, or an empty
   *          list if there are no warnings.
   */
  @NotNull()
  public List<PasswordPolicyStateAccountUsabilityWarning> getWarnings()
  {
    return warnings;
  }



  /**
   * Retrieves the set of account usability errors for the user.
   *
   * @return  The set of account usability errors for the user, or an empty
   *          list if there are no errors.
   */
  @NotNull()
  public List<PasswordPolicyStateAccountUsabilityError> getErrors()
  {
    return errors;
  }



  /**
   * Retrieves the authentication failure reason for the bind operation, if
   * available.
   *
   * @return  The authentication failure reason for the bind operation, or
   *          {@code null} if none was provided.
   */
  @Nullable()
  public AuthenticationFailureReason getAuthenticationFailureReason()
  {
    return authFailureReason;
  }



  /**
   * Extracts a get password policy state issues response control from the
   * provided bind result.
   *
   * @param  bindResult  The bind result from which to retrieve the get password
   *                     policy state issues response control.
   *
   * @return  The get password policy state issues response control contained in
   *          the provided bind result, or {@code null} if the bind result did
   *          not contain a get password policy state issues response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get password policy state issues
   *                         response control contained in the provided bind
   *                         result.
   */
  @Nullable()
  public static GetPasswordPolicyStateIssuesResponseControl get(
                     @NotNull final BindResult bindResult)
         throws LDAPException
  {
    final Control c = bindResult.getResponseControl(
         GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetPasswordPolicyStateIssuesResponseControl)
    {
      return (GetPasswordPolicyStateIssuesResponseControl) c;
    }
    else
    {
      return new GetPasswordPolicyStateIssuesResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Extracts a get password policy state issues response control from the
   * provided LDAP exception.
   *
   * @param  ldapException  The LDAP exception from which to retrieve the get
   *                        password policy state issues response control.
   *
   * @return  The get password policy state issues response control contained in
   *          the provided LDAP exception, or {@code null} if the exception did
   *          not contain a get password policy state issues response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the get password policy state issues
   *                         response control contained in the provided LDAP
   *                         exception.
   */
  @Nullable()
  public static GetPasswordPolicyStateIssuesResponseControl get(
                     @NotNull final LDAPException ldapException)
         throws LDAPException
  {
    final Control c = ldapException.getResponseControl(
         GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof GetPasswordPolicyStateIssuesResponseControl)
    {
      return (GetPasswordPolicyStateIssuesResponseControl) c;
    }
    else
    {
      return new GetPasswordPolicyStateIssuesResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_GET_PWP_STATE_ISSUES_RESPONSE.get();
  }



  /**
   * Retrieves a representation of this get password policy state issues
   * response control as a JSON object.  The JSON object uses the following
   * fields:
   * <UL>
   *   <LI>
   *     {@code oid} -- A mandatory string field whose value is the object
   *     identifier for this control.  For the get password policy state issues
   *     response control, the OID is "1.3.6.1.4.1.30221.2.5.47".
   *   </LI>
   *   <LI>
   *     {@code control-name} -- An optional string field whose value is a
   *     human-readable name for this control.  This field is only intended for
   *     descriptive purposes, and when decoding a control, the {@code oid}
   *     field should be used to identify the type of control.
   *   </LI>
   *   <LI>
   *     {@code criticality} -- A mandatory Boolean field used to indicate
   *     whether this control is considered critical.
   *   </LI>
   *   <LI>
   *     {@code value-base64} -- An optional string field whose value is a
   *     base64-encoded representation of the raw value for this get password
   *     policy state issues response control.  Exactly one of the
   *     {@code value-base64} and {@code value-json} fields must be present.
   *   </LI>
   *   <LI>
   *     {@code value-json} -- An optional JSON object field whose value is a
   *     user-friendly representation of the value for this get password policy
   *     state issues response control.  Exactly one of the {@code value-base64}
   *     and {@code value-json} fields must be present, and if the
   *     {@code value-json} field is used, then it will use the following
   *     fields:
   *     <UL>
   *       <LI>
   *         {@code notices} -- An optional array field containing JSON objects
   *         with information about any
   *         {@link PasswordPolicyStateAccountUsabilityNotice} values for the
   *         user.  Each JSON object will use the following fields:
   *         <UL>
   *           <LI>
   *             {@code id} -- An integer field whose value is a numeric
   *             identifier for the account usability notice.
   *           </LI>
   *           <LI>
   *             {@code name} -- A string field whose value is the name for the
   *             account usability notice.
   *           </LI>
   *           <LI>
   *             {@code message} -- An optional string field whose value is a
   *             human-readable message with additional information about the
   *             account usability notice.
   *           </LI>
   *         </UL>
   *       </LI>
   *       <LI>
   *         {@code warnings} -- An optional array field containing JSON objects
   *         with information about any
   *         {@link PasswordPolicyStateAccountUsabilityWarning} values for the
   *         user.  Each JSON object will use the following fields:
   *         <UL>
   *           <LI>
   *             {@code id} -- An integer field whose value is a numeric
   *             identifier for the account usability warning.
   *           </LI>
   *           <LI>
   *             {@code name} -- A string field whose value is the name for the
   *             account usability warning.
   *           </LI>
   *           <LI>
   *             {@code message} -- An optional string field whose value is a
   *             human-readable message with additional information about the
   *             account usability warning.
   *           </LI>
   *         </UL>
   *       </LI>
   *       <LI>
   *         {@code errors} -- An optional array field containing JSON objects
   *         with information about any
   *         {@link PasswordPolicyStateAccountUsabilityError} values for the
   *         user.  Each JSON object will use the following fields:
   *         <UL>
   *           <LI>
   *             {@code id} -- An integer field whose value is a numeric
   *             identifier for the account usability error.
   *           </LI>
   *           <LI>
   *             {@code name} -- A string field whose value is the name for the
   *             account usability error.
   *           </LI>
   *           <LI>
   *             {@code message} -- An optional string field whose value is a
   *             human-readable message with additional information about the
   *             account usability error.
   *           </LI>
   *         </UL>
   *       </LI>
   *       <LI>
   *         {@code authentication-failure-reason} -- An optional JSON object
   *         field that represents an {@link AuthenticationFailureReason} with
   *         information about the reason that the authentication attempt
   *         failed.  If present, this JSON object will use the following
   *         fields:
   *         <UL>
   *           <LI>
   *             {@code id} -- An integer field whose value is a numeric
   *             identifier for the authentication failure reason.
   *           </LI>
   *           <LI>
   *             {@code name} -- A string field whose value is the name for the
   *             authentication failure reason.
   *           </LI>
   *           <LI>
   *             {@code message} -- An optional string field whose value is a
   *             human-readable message with additional information about the
   *             authentication failure.
   *           </LI>
   *         </UL>
   *       </LI>
   *     </UL>
   *   </LI>
   * </UL>
   *
   * @return  A JSON object that contains a representation of this control.
   */
  @Override()
  @NotNull()
  public JSONObject toJSONControl()
  {
    final Map<String,JSONValue> valueFields = new LinkedHashMap<>();

    if (! notices.isEmpty())
    {
      final List<JSONValue> arrayValues = new ArrayList<>(notices.size());
      for (final PasswordPolicyStateAccountUsabilityNotice notice : notices)
      {
        arrayValues.add(encodeItem(notice.getIntValue(), notice.getName(),
             notice.getMessage()));
      }
      valueFields.put(JSON_FIELD_NOTICES, new JSONArray(arrayValues));
    }

    if (! warnings.isEmpty())
    {
      final List<JSONValue> arrayValues = new ArrayList<>(warnings.size());
      for (final PasswordPolicyStateAccountUsabilityWarning warning : warnings)
      {
        arrayValues.add(encodeItem(warning.getIntValue(), warning.getName(),
             warning.getMessage()));
      }
      valueFields.put(JSON_FIELD_WARNINGS, new JSONArray(arrayValues));
    }

    if (! errors.isEmpty())
    {
      final List<JSONValue> arrayValues = new ArrayList<>(notices.size());
      for (final PasswordPolicyStateAccountUsabilityError error : errors)
      {
        arrayValues.add(encodeItem(error.getIntValue(), error.getName(),
             error.getMessage()));
      }
      valueFields.put(JSON_FIELD_ERRORS, new JSONArray(arrayValues));
    }

    if (authFailureReason != null)
    {
      valueFields.put(JSON_FIELD_AUTH_FAILURE_REASON,
           encodeItem(authFailureReason.getIntValue(),
                authFailureReason.getName(), authFailureReason.getMessage()));
    }

    return new JSONObject(
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_OID,
              GET_PASSWORD_POLICY_STATE_ISSUES_RESPONSE_OID),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CONTROL_NAME,
              INFO_CONTROL_NAME_GET_PWP_STATE_ISSUES_RESPONSE.get()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_CRITICALITY,
              isCritical()),
         new JSONField(JSONControlDecodeHelper.JSON_FIELD_VALUE_JSON,
              new JSONObject(valueFields)));
  }



  /**
   * Retrieves a JSON object that contains an encoded representation of a
   * password policy state issue or authentication failure reason with the
   * provided information.
   *
   * @param  id       The ID for the item.
   * @param  name     The name for the item.  It must not be {@code null}.
   * @param  message  The message for the item.  It may be {@code null} if no
   *                  message is available.
   *
   * @return  A JSON object that contains an encoded representation of the
   *          provided information.
   */
  @NotNull()
  private static JSONObject encodeItem(final int id,
                                       @NotNull final String name,
                                       @Nullable final String message)
  {
    final Map<String,JSONValue> fields = new LinkedHashMap<>();
    fields.put(JSON_FIELD_ID, new JSONNumber(id));
    fields.put(JSON_FIELD_NAME, new JSONString(name));

    if (message != null)
    {
      fields.put(JSON_FIELD_MESSAGE, new JSONString(message));
    }

    return new JSONObject(fields);
  }



  /**
   * Attempts to decode the provided object as a JSON representation of a get
   * password policy state issues response control.
   *
   * @param  controlObject  The JSON object to be decoded.  It must not be
   *                        {@code null}.
   * @param  strict         Indicates whether to use strict mode when decoding
   *                        the provided JSON object.  If this is {@code true},
   *                        then this method will throw an exception if the
   *                        provided JSON object contains any unrecognized
   *                        fields.  If this is {@code false}, then unrecognized
   *                        fields will be ignored.
   *
   * @return  The get password policy state issues response control that was
   *          decoded from the provided JSON object.
   *
   * @throws  LDAPException  If the provided JSON object cannot be parsed as a
   *                         valid get password policy state issues response
   *                         control.
   */
  @NotNull()
  public static GetPasswordPolicyStateIssuesResponseControl decodeJSONControl(
              @NotNull final JSONObject controlObject,
              final boolean strict)
         throws LDAPException
  {
    final JSONControlDecodeHelper jsonControl = new JSONControlDecodeHelper(
         controlObject, strict, true, true);

    final ASN1OctetString rawValue = jsonControl.getRawValue();
    if (rawValue != null)
    {
      return new GetPasswordPolicyStateIssuesResponseControl(
           jsonControl.getOID(), jsonControl.getCriticality(), rawValue);
    }


    final JSONObject valueObject = jsonControl.getValueObject();

    final List<PasswordPolicyStateAccountUsabilityNotice> notices =
         new ArrayList<>();
    final List<JSONValue> noticeValues =
         valueObject.getFieldAsArray(JSON_FIELD_NOTICES);
    if (noticeValues != null)
    {
      for (final JSONValue v : noticeValues)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject o = (JSONObject) v;

          final Integer id = o.getFieldAsInteger(JSON_FIELD_ID);
          if (id == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_NOTICES, JSON_FIELD_ID));
          }

          final String name = o.getFieldAsString(JSON_FIELD_NAME);
          if (name == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_NOTICES, JSON_FIELD_NAME));
          }

          final String message = o.getFieldAsString(JSON_FIELD_MESSAGE);
          notices.add(new PasswordPolicyStateAccountUsabilityNotice(id, name,
               message));
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_VALUE_NOT_OBJECT.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_NOTICES));
        }
      }
    }


    final List<PasswordPolicyStateAccountUsabilityWarning > warnings =
         new ArrayList<>();
    final List<JSONValue> warningValues =
         valueObject.getFieldAsArray(JSON_FIELD_WARNINGS);
    if (warningValues != null)
    {
      for (final JSONValue v : warningValues)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject o = (JSONObject) v;

          final Integer id = o.getFieldAsInteger(JSON_FIELD_ID);
          if (id == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_WARNINGS, JSON_FIELD_ID));
          }

          final String name = o.getFieldAsString(JSON_FIELD_NAME);
          if (name == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_WARNINGS, JSON_FIELD_NAME));
          }

          final String message = o.getFieldAsString(JSON_FIELD_MESSAGE);
          warnings.add(new PasswordPolicyStateAccountUsabilityWarning(id, name,
               message));
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_VALUE_NOT_OBJECT.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_WARNINGS));
        }
      }
    }


    final List<PasswordPolicyStateAccountUsabilityError > errors =
         new ArrayList<>();
    final List<JSONValue> errorValues =
         valueObject.getFieldAsArray(JSON_FIELD_ERRORS);
    if (errorValues != null)
    {
      for (final JSONValue v : errorValues)
      {
        if (v instanceof JSONObject)
        {
          final JSONObject o = (JSONObject) v;

          final Integer id = o.getFieldAsInteger(JSON_FIELD_ID);
          if (id == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_ERRORS, JSON_FIELD_ID));
          }

          final String name = o.getFieldAsString(JSON_FIELD_NAME);
          if (name == null)
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                      controlObject.toSingleLineString(),
                      JSON_FIELD_ERRORS, JSON_FIELD_NAME));
          }

          final String message = o.getFieldAsString(JSON_FIELD_MESSAGE);
          errors.add(new PasswordPolicyStateAccountUsabilityError(id, name,
               message));
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_VALUE_NOT_OBJECT.get(
                    controlObject.toSingleLineString(),
                    JSON_FIELD_ERRORS));
        }
      }
    }


    final AuthenticationFailureReason authFailureReason;
    final JSONObject authFailureReasonObject =
         valueObject.getFieldAsObject(JSON_FIELD_AUTH_FAILURE_REASON);
    if (authFailureReasonObject == null)
    {
      authFailureReason = null;
    }
    else
    {
      final Integer id =
           authFailureReasonObject.getFieldAsInteger(JSON_FIELD_ID);
      if (id == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_AUTH_FAILURE_REASON, JSON_FIELD_ID));
      }

      final String name =
           authFailureReasonObject.getFieldAsString(JSON_FIELD_NAME);
      if (name == null)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_MISSING_ITEM_FIELD.get(
                  controlObject.toSingleLineString(),
                  JSON_FIELD_ERRORS, JSON_FIELD_NAME));
      }

      final String message =
           authFailureReasonObject.getFieldAsString(JSON_FIELD_MESSAGE);
      authFailureReason = new AuthenticationFailureReason(id, name, message);
    }


    if (strict)
    {
      final List<String> unrecognizedFields =
           JSONControlDecodeHelper.getControlObjectUnexpectedFields(
                valueObject, JSON_FIELD_NOTICES, JSON_FIELD_WARNINGS,
                JSON_FIELD_ERRORS, JSON_FIELD_AUTH_FAILURE_REASON);
      if (! unrecognizedFields.isEmpty())
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_GET_PWP_STATE_ISSUES_RESPONSE_JSON_CONTROL_UNRECOGNIZED_FIELD.
                  get(controlObject.toSingleLineString(),
                       unrecognizedFields.get(0)));
      }
    }


    return new GetPasswordPolicyStateIssuesResponseControl(notices, warnings,
         errors, authFailureReason);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("GetPasswordPolicyStateIssuesResponseControl(notices={ ");

    final Iterator<PasswordPolicyStateAccountUsabilityNotice> noticeIterator =
         notices.iterator();
    while (noticeIterator.hasNext())
    {
      buffer.append(noticeIterator.next().toString());
      if (noticeIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append("}, warnings={ ");

    final Iterator<PasswordPolicyStateAccountUsabilityWarning> warningIterator =
         warnings.iterator();
    while (warningIterator.hasNext())
    {
      buffer.append(warningIterator.next().toString());
      if (warningIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append("}, errors={ ");

    final Iterator<PasswordPolicyStateAccountUsabilityError> errorIterator =
         errors.iterator();
    while (errorIterator.hasNext())
    {
      buffer.append(errorIterator.next().toString());
      if (errorIterator.hasNext())
      {
        buffer.append(", ");
      }
    }
    buffer.append('}');

    if (authFailureReason != null)
    {
      buffer.append(", authFailureReason=");
      buffer.append(authFailureReason.toString());
    }

    buffer.append(')');
  }
}
