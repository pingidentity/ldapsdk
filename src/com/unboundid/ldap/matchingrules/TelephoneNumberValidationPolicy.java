/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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
package com.unboundid.ldap.matchingrules;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;



/**
 * This enum defines the policy that the {@link TelephoneNumberMatchingRule}
 * should use when validating values in accordance with the syntax.  Regardless
 * of the validation policy, the normalized representation of a value will be
 * the provided value, converted to lowercase, with only spaces and hyphens
 * removed.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public enum TelephoneNumberValidationPolicy
{
  /**
   * A policy that indicates that any non-empty printable string will be
   * accepted.  Neither empty strings nor strings that contain characters from
   * outside the set of printable characters will be accepted.
   */
  ALLOW_NON_EMPTY_PRINTABLE_STRING,



  /**
   * A policy that indicates that any non-empty printable string will be
   * accepted, as long as it contains at least one digit.  Neither empty
   * strings, strings nor strings that contain characters from outside the set
   * of printable characters, nor strings without any digits will be accepted.
   */
  ALLOW_NON_EMPTY_PRINTABLE_STRING_WITH_AT_LEAST_ONE_DIGIT,



  /**
   * A policy that indicates that only values that strictly adhere to the
   * X.520 specification will be accepted.  Only values that start with a
   * plus sign, contain at least one digit, and contain only digits, spaces, and
   * hyphens will be accepted.
   */
  ENFORCE_STRICT_X520_COMPLIANCE;



  /**
   * Validates the provided value to ensure that it satisfies this validation
   * policy.
   *
   * @param  value        The value to be validated.  It must not be
   *                      {@code null}.
   * @param  isSubstring  Indicates whether the provided value represents a
   *                      substring rather than a complete value.
   *
   * @throws  LDAPException  If the provided value is not acceptable as per the
   *                         constraints of this policy.
   */
  public void validateValue(@NotNull final ASN1OctetString value,
                            final boolean isSubstring)
         throws LDAPException
  {
    switch (this)
    {
      case ALLOW_NON_EMPTY_PRINTABLE_STRING:
        validateNonEmptyPrintableString(value, isSubstring, false);
        break;

      case ALLOW_NON_EMPTY_PRINTABLE_STRING_WITH_AT_LEAST_ONE_DIGIT:
        validateNonEmptyPrintableString(value, isSubstring, true);
        break;

      case ENFORCE_STRICT_X520_COMPLIANCE:
      default:
        validateX520Compliant(value, isSubstring);
        break;
    }
  }



  /**
   * Validates that the provided value is valid in accordance with a policy that
   * requires a non-empty printable string.
   *
   * @param  value                   The value to be validated.  It must not be
   *                                 {@code null}.
   * @param  isSubstring             Indicates whether the value represents a
   *                                 substring rather than a complete value.
   * @param  requireAtLeastOneDigit  Indicates whether to require the value to
   *                                 contain at least one digit.  This only
   *                                 applies if {@code isSubstring} is false.
   *
   * @throws  LDAPException  If the provided value is not valid.
   */
  private static void validateNonEmptyPrintableString(
               @NotNull final ASN1OctetString value,
               final boolean isSubstring,
               final boolean requireAtLeastOneDigit)
          throws LDAPException
  {
    // Make sure that the value is not empty.
    final byte[] valueBytes = value.getValue();
    if (valueBytes.length == 0)
    {
      if (isSubstring)
      {
        // Substring components must not be empty.
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_TELEPHONE_NUMBER_VALIDATION_EMPTY_SUBSTRING.get());
      }
      else
      {
        // Telephone number values must not be empty.
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_TELEPHONE_NUMBER_VALIDATION_EMPTY_VALUE.get());
      }
    }


    // Iterate through the bytes of the value and make sure they are all
    // printable.  Also, check to see if we find any digits.
    boolean digitFound = false;
    for (int i=0; i < valueBytes.length; i++)
    {
      final byte b = valueBytes[i];
      if ((b >= '0') && (b <= '9'))
      {
        // It's a numeric digit, which is always allowed.
        digitFound = true;
      }
      else if (((b >= 'a') && (b <= 'z')) || ((b >= 'A') && (b <= 'Z')))
      {
        // It's an alphabetic character, which is allowed as per the policy.
      }
      else
      {
        switch (b)
        {
          case '\'':
          case '(':
          case ')':
          case '+':
          case ',':
          case '-':
          case '.':
          case '=':
          case '/':
          case ':':
          case '?':
          case ' ':
            // These characters are all allowed.
            break;
          default:
            // This character is not allowed.
            if (isSubstring)
            {
              throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                   ERR_TELEPHONE_NUMBER_VALIDATION_NON_PRINTABLE_SUB_CHAR.get(
                        value.stringValue(), i));
            }
            else
            {
              throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                   ERR_TELEPHONE_NUMBER_VALIDATION_NON_PRINTABLE_CHAR.get(
                        value.stringValue(), i));
            }
        }
      }
    }


    // If we should require a digit, then make sure we found one.
    if (requireAtLeastOneDigit && (! isSubstring) && (! digitFound))
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_TELEPHONE_NUMBER_VALIDATION_NO_DIGITS.get(value.stringValue()));
    }
  }



  /**
   * Validates that the provided value is a valid telephone number using the
   * strict specification defined in X.520.
   *
   * @param  value        The value to be validated.  It must not be
   *                      {@code null}.
   * @param  isSubstring  Indicates whether the value represents a substring
   *                      rather than a complete value.
   *
   * @throws  LDAPException  If the provided value is not valid.
   */
  private static void validateX520Compliant(
               @NotNull final ASN1OctetString value,
               final boolean isSubstring)
          throws LDAPException
  {
    // Make sure that the value is not empty.
    final byte[] valueBytes = value.getValue();
    if (valueBytes.length == 0)
    {
      if (isSubstring)
      {
        // Substring components must not be empty.
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_TELEPHONE_NUMBER_VALIDATION_EMPTY_SUBSTRING.get());
      }
      else
      {
        // Telephone number values must not be empty.
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_TELEPHONE_NUMBER_VALIDATION_EMPTY_VALUE.get());
      }
    }


    // If the value is not a substring, then make sure it starts with a plus
    // sign.
    if ((! isSubstring) && (valueBytes[0] != '+'))
    {
      throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
           ERR_TELEPHONE_NUMBER_VALIDATION_MISSING_PLUS.get(
                value.stringValue()));
    }


    // Iterate through the bytes of the value and make sure it only contains a
    // plus sign, one or more numeric digits, and optionally spaces and/or
    // dashes.  A plus sign will only be allowed at position zero, and digits,
    // spaces, and hyphens will be allowed anywhere.
    boolean digitFound = false;
    for (int i=0; i < valueBytes.length; i++)
    {
      final byte b = valueBytes[i];
      if (b == '+')
      {
        if (i != 0)
        {
          if (isSubstring)
          {
            throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                 ERR_TELEPHONE_NUMBER_VALIDATION_NON_FIRST_PLUS_SUB.get(
                      value.stringValue(), i));
          }
          else
          {
            throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                 ERR_TELEPHONE_NUMBER_VALIDATION_NON_FIRST_PLUS.get(
                      value.stringValue(), i));
          }
        }
      }
      else if ((b >= '0') && (b <= '9'))
      {
        digitFound = true;
      }
      else if ((b == ' ') || (b == '-'))
      {
        // These are always allowed and always ignored.
      }
      else
      {
        if (isSubstring)
        {
            throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                 ERR_TELEPHONE_NUMBER_VALIDATION_INVALID_CHAR_SUB.get(
                      value.stringValue(), i));
        }
        else
        {
            throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
                 ERR_TELEPHONE_NUMBER_VALIDATION_INVALID_CHAR.get(
                      value.stringValue(), i));
        }
      }
    }


    // If we didn't find any digits, then that's an error, even for a substring
    // assertion.
    if (! digitFound)
    {
      if (isSubstring)
      {
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_TELEPHONE_NUMBER_VALIDATION_NO_DIGITS_SUB.get(
                  value.stringValue()));
      }
      else
      {
        throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
             ERR_TELEPHONE_NUMBER_VALIDATION_NO_DIGITS.get(
                  value.stringValue()));
      }
    }
  }
}
