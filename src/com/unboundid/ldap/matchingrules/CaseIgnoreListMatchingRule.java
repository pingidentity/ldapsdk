/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.matchingrules.MatchingRuleMessages.*;



/**
 * This class provides an implementation of a matching rule that may be used to
 * process values containing lists of items, in which each item is separated by
 * a dollar sign ($) character.  Substring matching is also supported, but
 * ordering matching is not.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CaseIgnoreListMatchingRule
       extends MatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  @NotNull private static final CaseIgnoreListMatchingRule INSTANCE =
       new CaseIgnoreListMatchingRule();



  /**
   * The name for the caseIgnoreListMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_NAME =
       "caseIgnoreListMatch";



  /**
   * The name for the caseIgnoreListMatch equality matching rule, formatted in
   * all lowercase characters.
   */
  @NotNull static final String LOWER_EQUALITY_RULE_NAME =
       StaticUtils.toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the caseIgnoreListMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_OID = "2.5.13.11";



  /**
   * The name for the caseIgnoreListSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_NAME =
       "caseIgnoreListSubstringsMatch";



  /**
   * The name for the caseIgnoreListSubstringsMatch substring matching rule,
   * formatted in all lowercase characters.
   */
  @NotNull static final String LOWER_SUBSTRING_RULE_NAME =
       StaticUtils.toLowerCase(SUBSTRING_RULE_NAME);



  /**
   * The OID for the caseIgnoreListSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_OID = "2.5.13.12";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7795143670808983466L;



  /**
   * Creates a new instance of this case-ignore list matching rule.
   */
  public CaseIgnoreListMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  @NotNull()
  public static CaseIgnoreListMatchingRule getInstance()
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
  public boolean valuesMatch(@NotNull final ASN1OctetString value1,
                             @NotNull final ASN1OctetString value2)
         throws LDAPException
  {
    return normalize(value1).equals(normalize(value2));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean matchesSubstring(@NotNull final ASN1OctetString value,
                                  @Nullable final ASN1OctetString subInitial,
                                  @Nullable final ASN1OctetString[] subAny,
                                  @Nullable final ASN1OctetString subFinal)
         throws LDAPException
  {
    String normStr = normalize(value).stringValue();

    if (subInitial != null)
    {
      final String normSubInitial = normalizeSubstring(subInitial,
           SUBSTRING_TYPE_SUBINITIAL).stringValue();
      if (normSubInitial.indexOf('$') >= 0)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR.get(
                  normSubInitial));
      }

      if (! normStr.startsWith(normSubInitial))
      {
        return false;
      }

      normStr = normStr.substring(normSubInitial.length());
    }

    if (subFinal != null)
    {
      final String normSubFinal = normalizeSubstring(subFinal,
           SUBSTRING_TYPE_SUBFINAL).stringValue();
      if (normSubFinal.indexOf('$') >= 0)
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR.get(
                  normSubFinal));
      }

      if (! normStr.endsWith(normSubFinal))
      {

        return false;
      }

      normStr = normStr.substring(0, normStr.length() - normSubFinal.length());
    }

    if (subAny != null)
    {
      for (final ASN1OctetString s : subAny)
      {
        final String normSubAny =
             normalizeSubstring(s, SUBSTRING_TYPE_SUBANY).stringValue();
        if (normSubAny.indexOf('$') >= 0)
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_SUBSTRING_COMPONENT_CONTAINS_DOLLAR.get(
                    normSubAny));
        }

        final int pos = normStr.indexOf(normSubAny);
        if (pos < 0)
        {
          return false;
        }

        normStr = normStr.substring(pos + normSubAny.length());
      }
    }

    return true;
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
         ERR_CASE_IGNORE_LIST_ORDERING_MATCHING_NOT_SUPPORTED.get());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalize(@NotNull final ASN1OctetString value)
         throws LDAPException
  {
    final List<String>     items    = getLowercaseItems(value);
    final Iterator<String> iterator = items.iterator();

    final StringBuilder buffer = new StringBuilder();
    while (iterator.hasNext())
    {
      normalizeItem(buffer, iterator.next());
      if (iterator.hasNext())
      {
        buffer.append('$');
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
    return CaseIgnoreStringMatchingRule.getInstance().normalizeSubstring(value,
         substringType);
  }



  /**
   * Retrieves a list of the items contained in the provided value.  The items
   * will use the case of the provided value.
   *
   * @param  value  The value for which to obtain the list of items.  It must
   *                not be {@code null}.
   *
   * @return  An unmodifiable list of the items contained in the provided value.
   *
   * @throws  LDAPException  If the provided value does not represent a valid
   *                         list in accordance with this matching rule.
   */
  @NotNull()
  public static List<String> getItems(@NotNull final ASN1OctetString value)
         throws LDAPException
  {
    return getItems(value.stringValue());
  }



  /**
   * Retrieves a list of the items contained in the provided value.  The items
   * will use the case of the provided value.
   *
   * @param  value  The value for which to obtain the list of items.  It must
   *                not be {@code null}.
   *
   * @return  An unmodifiable list of the items contained in the provided value.
   *
   * @throws  LDAPException  If the provided value does not represent a valid
   *                         list in accordance with this matching rule.
   */
  @NotNull()
  public static List<String> getItems(@NotNull final String value)
         throws LDAPException
  {
    final ArrayList<String> items = new ArrayList<>(10);

    final int length = value.length();
    final StringBuilder buffer = new StringBuilder();
    for (int i=0; i < length; i++)
    {
      final char c = value.charAt(i);
      if (c == '\\')
      {
        try
        {
          buffer.append(decodeHexChar(value, i+1));
          i += 2;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_MALFORMED_HEX_CHAR.get(value), e);
        }
      }
      else if (c == '$')
      {
        final String s = buffer.toString().trim();
        if (s.length() == 0)
        {
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_EMPTY_ITEM.get(value));
        }

        items.add(s);
        buffer.delete(0, buffer.length());
      }
      else
      {
        buffer.append(c);
      }
    }

    final String s = buffer.toString().trim();
    if (s.length() == 0)
    {
      if (items.isEmpty())
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
             ERR_CASE_IGNORE_LIST_EMPTY_LIST.get(value));
      }
      else
      {
        throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
                                ERR_CASE_IGNORE_LIST_EMPTY_ITEM.get(value));
      }
    }
    items.add(s);

    return Collections.unmodifiableList(items);
  }



  /**
   * Retrieves a list of the lowercase representations of the items contained in
   * the provided value.
   *
   * @param  value  The value for which to obtain the list of items.  It must
   *                not be {@code null}.
   *
   * @return  An unmodifiable list of the items contained in the provided value.
   *
   * @throws  LDAPException  If the provided value does not represent a valid
   *                         list in accordance with this matching rule.
   */
  @NotNull()
  public static List<String> getLowercaseItems(
                                  @NotNull final ASN1OctetString value)
         throws LDAPException
  {
    return getLowercaseItems(value.stringValue());
  }



  /**
   * Retrieves a list of the lowercase representations of the items contained in
   * the provided value.
   *
   * @param  value  The value for which to obtain the list of items.  It must
   *                not be {@code null}.
   *
   * @return  An unmodifiable list of the items contained in the provided value.
   *
   * @throws  LDAPException  If the provided value does not represent a valid
   *                         list in accordance with this matching rule.
   */
  @NotNull()
  public static List<String> getLowercaseItems(@NotNull final String value)
         throws LDAPException
  {
    return getItems(StaticUtils.toLowerCase(value));
  }



  /**
   * Normalizes the provided list item.
   *
   * @param  buffer  The buffer to which to append the normalized representation
   *                 of the given item.
   * @param  item    The item to be normalized.  It must already be trimmed and
   *                 all characters converted to lowercase.
   */
  static void normalizeItem(@NotNull final StringBuilder buffer,
                            @NotNull final String item)
  {
    final int length = item.length();

    boolean lastWasSpace = false;
    for (int i=0; i < length; i++)
    {
      final char c = item.charAt(i);
      if (c == '\\')
      {
        buffer.append("\\5c");
        lastWasSpace = false;
      }
      else if (c == '$')
      {
        buffer.append("\\24");
        lastWasSpace = false;
      }
      else if (c == ' ')
      {
        if (! lastWasSpace)
        {
          buffer.append(' ');
          lastWasSpace = true;
        }
      }
      else
      {
        buffer.append(c);
        lastWasSpace = false;
      }
    }
  }



  /**
   * Reads two characters from the specified position in the provided string and
   * returns the character that they represent.
   *
   * @param  s  The string from which to take the hex characters.
   * @param  p  The position at which the hex characters begin.
   *
   * @return  The character that was read and decoded.
   *
   * @throws  LDAPException  If either of the characters are not hexadecimal
   *                         digits.
   */
  static char decodeHexChar(@NotNull final String s, final int p)
         throws LDAPException
  {
    char c = 0;

    for (int i=0, j=p; (i < 2); i++,j++)
    {
      c <<= 4;

      switch (s.charAt(j))
      {
        case '0':
          break;
        case '1':
          c |= 0x01;
          break;
        case '2':
          c |= 0x02;
          break;
        case '3':
          c |= 0x03;
          break;
        case '4':
          c |= 0x04;
          break;
        case '5':
          c |= 0x05;
          break;
        case '6':
          c |= 0x06;
          break;
        case '7':
          c |= 0x07;
          break;
        case '8':
          c |= 0x08;
          break;
        case '9':
          c |= 0x09;
          break;
        case 'a':
        case 'A':
          c |= 0x0A;
          break;
        case 'b':
        case 'B':
          c |= 0x0B;
          break;
        case 'c':
        case 'C':
          c |= 0x0C;
          break;
        case 'd':
        case 'D':
          c |= 0x0D;
          break;
        case 'e':
        case 'E':
          c |= 0x0E;
          break;
        case 'f':
        case 'F':
          c |= 0x0F;
          break;
        default:
          throw new LDAPException(ResultCode.INVALID_ATTRIBUTE_SYNTAX,
               ERR_CASE_IGNORE_LIST_NOT_HEX_DIGIT.get(s.charAt(j)));
      }
    }

    return c;
  }
}
