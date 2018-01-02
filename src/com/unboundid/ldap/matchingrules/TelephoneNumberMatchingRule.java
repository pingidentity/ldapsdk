/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;
import static com.unboundid.util.StaticUtils.*;



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
  private static final TelephoneNumberMatchingRule INSTANCE =
       new TelephoneNumberMatchingRule();



  /**
   * The name for the telephoneNumberMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_NAME = "telephoneNumberMatch";



  /**
   * The name for the telephoneNumberMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  static final String LOWER_EQUALITY_RULE_NAME =
       toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the telephoneNumberMatch equality matching rule.
   */
  public static final String EQUALITY_RULE_OID = "2.5.13.20";



  /**
   * The name for the telephoneNumberSubstringsMatch substring matching rule.
   */
  public static final String SUBSTRING_RULE_NAME =
       "telephoneNumberSubstringsMatch";



  /**
   * The name for the telephoneNumberSubstringsMatch substring matching rule,
   * formatted in all lowercase characters.
   */
  static final String LOWER_SUBSTRING_RULE_NAME =
       toLowerCase(SUBSTRING_RULE_NAME);



  /**
   * The OID for the telephoneNumberSubstringsMatch substring matching rule.
   */
  public static final String SUBSTRING_RULE_OID = "2.5.13.21";



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
  public static TelephoneNumberMatchingRule getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getEqualityMatchingRuleName()
  {
    return EQUALITY_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getEqualityMatchingRuleOID()
  {
    return EQUALITY_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleName()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getOrderingMatchingRuleOID()
  {
    return null;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleName()
  {
    return SUBSTRING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getSubstringMatchingRuleOID()
  {
    return SUBSTRING_RULE_OID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int compareValues(final ASN1OctetString value1,
                           final ASN1OctetString value2)
         throws LDAPException
  {
    throw new LDAPException(ResultCode.INAPPROPRIATE_MATCHING,
         ERR_TELEPHONE_NUMBER_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ASN1OctetString normalize(final ASN1OctetString value)
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
  public ASN1OctetString normalizeSubstring(final ASN1OctetString value,
                                            final byte substringType)
         throws LDAPException
  {
    return normalize(value);
  }
}
