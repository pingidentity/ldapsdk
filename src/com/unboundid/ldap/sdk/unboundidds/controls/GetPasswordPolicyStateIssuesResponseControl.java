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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
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
