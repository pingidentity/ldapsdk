/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import java.util.ArrayList;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1Enumerated;
import com.unboundid.asn1.ASN1Exception;
import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DecodeableControl;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class provides an implementation of the password policy response control
 * as described in draft-behera-ldap-password-policy-10.  It may be used to
 * provide information related to a user's password policy.  It may include at
 * most one warning from the set of
 * {@link DraftBeheraLDAPPasswordPolicy10WarningType} values and at most one
 * error from the set of {@link DraftBeheraLDAPPasswordPolicy10ErrorType}
 * values.  See the documentation for those classes for more information on the
 * information that may be included.  See the
 * {@link DraftBeheraLDAPPasswordPolicy10RequestControl} documentation for an
 * example that demonstrates the use of the password policy request and response
 * controls.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftBeheraLDAPPasswordPolicy10ResponseControl
       extends Control
       implements DecodeableControl
{
  /**
   * The OID (1.3.6.1.4.1.42.2.27.8.5.1) for the password policy response
   * control.
   */
  @NotNull public static final String PASSWORD_POLICY_RESPONSE_OID =
       "1.3.6.1.4.1.42.2.27.8.5.1";



  /**
   * The BER type for the password policy warning element.
   */
  private static final byte TYPE_WARNING = (byte) 0xA0;



  /**
   * The BER type for the password policy error element.
   */
  private static final byte TYPE_ERROR = (byte) 0x81;



  /**
   * The BER type for the "time before expiration" warning element.
   */
  private static final byte TYPE_TIME_BEFORE_EXPIRATION = (byte) 0x80;



  /**
   * The BER type for the "grace logins remaining" warning element.
   */
  private static final byte TYPE_GRACE_LOGINS_REMAINING = (byte) 0x81;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1835830253434331833L;



  // The password policy warning value, if applicable.
  private final int warningValue;

  // The password policy error type, if applicable.
  @Nullable private final DraftBeheraLDAPPasswordPolicy10ErrorType errorType;

  // The password policy warning type, if applicable.
  @Nullable private final DraftBeheraLDAPPasswordPolicy10WarningType
       warningType;



  /**
   * Creates a new empty control instance that is intended to be used only for
   * decoding controls via the {@code DecodeableControl} interface.
   */
  DraftBeheraLDAPPasswordPolicy10ResponseControl()
  {
    warningType  = null;
    errorType    = null;
    warningValue = -1;
  }



  /**
   * Creates a new password policy response control with the provided
   * information.  It will not be critical.
   *
   * @param  warningType   The password policy warning type for this response
   *                       control, or {@code null} if there should be no
   *                       warning type.
   * @param  warningValue  The value for the password policy warning type, or -1
   *                       if there is no warning type.
   * @param  errorType     The password policy error type for this response
   *                       control, or {@code null} if there should be no error
   *                       type.
   */
  public DraftBeheraLDAPPasswordPolicy10ResponseControl(
       @Nullable final DraftBeheraLDAPPasswordPolicy10WarningType warningType,
       final int warningValue,
       @Nullable final DraftBeheraLDAPPasswordPolicy10ErrorType errorType)
  {
    this(warningType, warningValue, errorType, false);
  }



  /**
   * Creates a new password policy response control with the provided
   * information.
   *
   * @param  oid         The OID for the control.
   * @param  isCritical  Indicates whether the control should be marked
   *                     critical.
   * @param  value       The encoded value for the control.  This may be
   *                     {@code null} if no value was provided.
   *
   * @throws  LDAPException  If the provided control cannot be decoded as a
   *                         password policy response control.
   */
  public DraftBeheraLDAPPasswordPolicy10ResponseControl(
              @NotNull final String oid,
              final boolean isCritical, @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    super(oid, isCritical, value);

    if (value == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_NO_VALUE.get());
    }

    final ASN1Sequence valueSequence;
    try
    {
      final ASN1Element valueElement = ASN1Element.decode(value.getValue());
      valueSequence = ASN1Sequence.decodeAsSequence(valueElement);
    }
    catch (final ASN1Exception ae)
    {
      Debug.debugException(ae);
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_VALUE_NOT_SEQUENCE.get(ae), ae);
    }

    final ASN1Element[] valueElements = valueSequence.elements();
    if (valueElements.length > 2)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_PWP_RESPONSE_INVALID_ELEMENT_COUNT.get(
                                   valueElements.length));
    }

    int                                        wv = -1;
    DraftBeheraLDAPPasswordPolicy10ErrorType   et = null;
    DraftBeheraLDAPPasswordPolicy10WarningType wt = null;
    for (final ASN1Element e : valueElements)
    {
      switch (e.getType())
      {
        case TYPE_WARNING:
          if (wt == null)
          {
            try
            {
              final ASN1Element warningElement =
                   ASN1Element.decode(e.getValue());
              wv = ASN1Integer.decodeAsInteger(warningElement).intValue();
              switch (warningElement.getType())
              {
                case TYPE_TIME_BEFORE_EXPIRATION:
                  wt = DraftBeheraLDAPPasswordPolicy10WarningType.
                       TIME_BEFORE_EXPIRATION;
                  break;

                case TYPE_GRACE_LOGINS_REMAINING:
                  wt = DraftBeheraLDAPPasswordPolicy10WarningType.
                       GRACE_LOGINS_REMAINING;
                  break;

                default:
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                       ERR_PWP_RESPONSE_INVALID_WARNING_TYPE.get(
                            StaticUtils.toHex(warningElement.getType())));
              }
            }
            catch (final ASN1Exception ae)
            {
              Debug.debugException(ae);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_PWP_RESPONSE_CANNOT_DECODE_WARNING.get(ae), ae);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PWP_RESPONSE_MULTIPLE_WARNING.get());
          }
          break;

        case TYPE_ERROR:
          if (et == null)
          {
            try
            {
              final ASN1Enumerated errorElement =
                   ASN1Enumerated.decodeAsEnumerated(e);
              et = DraftBeheraLDAPPasswordPolicy10ErrorType.valueOf(
                   errorElement.intValue());
              if (et == null)
              {
                  throw new LDAPException(ResultCode.DECODING_ERROR,
                                 ERR_PWP_RESPONSE_INVALID_ERROR_TYPE.get(
                                      errorElement.intValue()));
              }
            }
            catch (final ASN1Exception ae)
            {
              Debug.debugException(ae);
              throw new LDAPException(ResultCode.DECODING_ERROR,
                   ERR_PWP_RESPONSE_CANNOT_DECODE_ERROR.get(ae), ae);
            }
          }
          else
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_PWP_RESPONSE_MULTIPLE_ERROR.get());
          }
          break;

        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_PWP_RESPONSE_INVALID_TYPE.get(
                    StaticUtils.toHex(e.getType())));
      }
    }

    warningType  = wt;
    warningValue = wv;
    errorType    = et;
  }



  /**
   * Creates a new password policy response control with the provided
   * information.
   *
   * @param  warningType   The password policy warning type for this response
   *                       control, or {@code null} if there should be no
   *                       warning type.
   * @param  warningValue  The value for the password policy warning type, or -1
   *                       if there is no warning type.
   * @param  errorType     The password policy error type for this response
   *                       control, or {@code null} if there should be no error
   *                       type.
   * @param  isCritical    Indicates whether this control should be marked
   *                       critical.
   */
  public DraftBeheraLDAPPasswordPolicy10ResponseControl(
       @Nullable final DraftBeheraLDAPPasswordPolicy10WarningType warningType,
       final int warningValue,
       @Nullable final DraftBeheraLDAPPasswordPolicy10ErrorType errorType,
       final boolean isCritical)
  {
    super(PASSWORD_POLICY_RESPONSE_OID, isCritical,
         encodeValue(warningType, warningValue, errorType));

    this.warningType = warningType;
    this.errorType   = errorType;

    if (warningType == null)
    {
      this.warningValue = -1;
    }
    else
    {
      this.warningValue = warningValue;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public DraftBeheraLDAPPasswordPolicy10ResponseControl decodeControl(
              @NotNull final String oid, final boolean isCritical,
              @Nullable final ASN1OctetString value)
         throws LDAPException
  {
    return new DraftBeheraLDAPPasswordPolicy10ResponseControl(oid, isCritical,
         value);
  }



  /**
   * Extracts a password policy response control from the provided result.
   *
   * @param  result  The result from which to retrieve the password policy
   *                 response control.
   *
   * @return  The password policy response control contained in the provided
   *          result, or {@code null} if the result did not contain a password
   *          policy response control.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         decode the password policy response control
   *                         contained in the provided result.
   */
  @Nullable()
  public static DraftBeheraLDAPPasswordPolicy10ResponseControl get(
                     @NotNull final LDAPResult result)
         throws LDAPException
  {
    final Control c = result.getResponseControl(PASSWORD_POLICY_RESPONSE_OID);
    if (c == null)
    {
      return null;
    }

    if (c instanceof DraftBeheraLDAPPasswordPolicy10ResponseControl)
    {
      return (DraftBeheraLDAPPasswordPolicy10ResponseControl) c;
    }
    else
    {
      return new DraftBeheraLDAPPasswordPolicy10ResponseControl(c.getOID(),
           c.isCritical(), c.getValue());
    }
  }



  /**
   * Encodes the provided information as appropriate for use as the value of a
   * password policy response control.
   *
   * @param  warningType   The warning type to use for the warning element, or
   *                       {@code null} if there is not to be a warning element.
   * @param  warningValue  The value to use for the warning element.
   * @param  errorType     The error type to use for the error element, or
   *                       {@code null} if there is not to be an error element.
   *
   * @return  The ASN.1 octet string containing the encoded control value.
   */
  @NotNull()
  private static ASN1OctetString encodeValue(
       @Nullable final DraftBeheraLDAPPasswordPolicy10WarningType warningType,
       final int warningValue,
       @Nullable final DraftBeheraLDAPPasswordPolicy10ErrorType errorType)
  {
    final ArrayList<ASN1Element> valueElements = new ArrayList<>(2);

    if (warningType != null)
    {
      switch (warningType)
      {
        case TIME_BEFORE_EXPIRATION:
          valueElements.add(new ASN1Element(TYPE_WARNING,
               new ASN1Integer(TYPE_TIME_BEFORE_EXPIRATION,
                               warningValue).encode()));
          break;

        case GRACE_LOGINS_REMAINING:
          valueElements.add(new ASN1Element(TYPE_WARNING,
               new ASN1Integer(TYPE_GRACE_LOGINS_REMAINING,
                               warningValue).encode()));
          break;
      }
    }

    if (errorType != null)
    {
      valueElements.add(new ASN1Enumerated(TYPE_ERROR, errorType.intValue()));
    }

    return new ASN1OctetString(new ASN1Sequence(valueElements).encode());
  }



  /**
   * Retrieves the warning type for this password policy response control, if
   * available.
   *
   * @return  The warning type for this password policy response control, or
   *          {@code null} if there is no warning type.
   */
  @Nullable()
  public DraftBeheraLDAPPasswordPolicy10WarningType getWarningType()
  {
    return warningType;
  }



  /**
   * Retrieves the warning value for this password policy response control, if
   * available.
   *
   * @return  The warning value for this password policy response control, or -1
   *          if there is no warning type.
   */
  public int getWarningValue()
  {
    return warningValue;
  }



  /**
   * Retrieves the error type for this password policy response control, if
   * available.
   *
   * @return  The error type for this password policy response control, or
   *          {@code null} if there is no error type.
   */
  @Nullable()
  public DraftBeheraLDAPPasswordPolicy10ErrorType getErrorType()
  {
    return errorType;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getControlName()
  {
    return INFO_CONTROL_NAME_PW_POLICY_RESPONSE.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    boolean elementAdded = false;

    buffer.append("PasswordPolicyResponseControl(");

    if (warningType != null)
    {
      buffer.append("warningType='");
      buffer.append(warningType.getName());
      buffer.append("', warningValue=");
      buffer.append(warningValue);
      elementAdded = true;
    }

    if (errorType != null)
    {
      if (elementAdded)
      {
        buffer.append(", ");
      }

      buffer.append("errorType='");
      buffer.append(errorType.getName());
      buffer.append('\'');
      elementAdded = true;
    }

    if (elementAdded)
    {
      buffer.append(", ");
    }

    buffer.append("isCritical=");
    buffer.append(isCritical());
    buffer.append(')');
  }
}
