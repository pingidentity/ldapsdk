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
package com.unboundid.ldap.matchingrules;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;



/**
 * This class provides an implementation of a matching rule that may be used for
 * telephone numbers.  It will accept values with any ASCII printable character.
 * When making comparisons, spaces and dashes will be ignored.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class TelephoneNumberMatchingRule
       extends SimpleMatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  @NotNull private static final TelephoneNumberMatchingRule INSTANCE =
       new TelephoneNumberMatchingRule();



  /**
   * The name for the telephoneNumberMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_NAME =
       "telephoneNumberMatch";



  /**
   * The name for the telephoneNumberMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  @NotNull static final String LOWER_EQUALITY_RULE_NAME =
       StaticUtils.toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the telephoneNumberMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_OID = "2.5.13.20";



  /**
   * The name for the telephoneNumberSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_NAME =
       "telephoneNumberSubstringsMatch";



  /**
   * The name for the telephoneNumberSubstringsMatch substring matching rule,
   * formatted in all lowercase characters.
   */
  @NotNull static final String LOWER_SUBSTRING_RULE_NAME =
       StaticUtils.toLowerCase(SUBSTRING_RULE_NAME);



  /**
   * The OID for the telephoneNumberSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_OID = "2.5.13.21";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5463096544849211252L;



  /**
   * Creates a new instance of this telephone number matching rule.
   */
  public TelephoneNumberMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  @NotNull()
  public static TelephoneNumberMatchingRule getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getEqualityMatchingRuleName()
  {
    return EQUALITY_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getEqualityMatchingRuleOID()
  {
    return EQUALITY_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getOrderingMatchingRuleName()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public String getOrderingMatchingRuleOID()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSubstringMatchingRuleName()
  {
    return SUBSTRING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getSubstringMatchingRuleOID()
  {
    return SUBSTRING_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(@NotNull final ASN1OctetString value1,
                           @NotNull final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_TELEPHONE_NUMBER_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalize(@NotNull final ASN1OctetString value)
         throws LDAPException
  {
    final byte[] valueBytes = value.getValue();
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < valueBytes.length; i++)
    {
      switch (valueBytes[i])
      {
        case ' ':
        case '-':
          // These should be ignored.
          break;

        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '.':
        case '=':
        case '/':
        case ':':
        case '?':
          // These should be retained.
          buffer.append((char) valueBytes[i]);
          break;

        default:
          final byte b = valueBytes[i];
          if (((b >= '0') && (b <= '9')) ||
              ((b >= 'a') && (b <= 'z')) ||
              ((b >= 'A') && (b <= 'Z')))
          {
            // These should be retained.
            buffer.append((char) valueBytes[i]);
            break;
          }

          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_TELEPHONE_NUMBER_INVALID_CHARACTER.get(i));
      }
    }

    return new ASN1OctetString(buffer.toString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalizeSubstring(
                              @NotNull final ASN1OctetString value,
                              final byte substringType)
         throws LDAPException
  {
    return normalize(value);
  }
}
