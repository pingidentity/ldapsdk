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
package com.unboundid.ldap.matchingrules;



import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a matching rule that uses
 * case-insensitive matching that also treats multiple consecutive (non-escaped)
 * spaces as a single space.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class CaseIgnoreStringMatchingRule
       extends AcceptAllSimpleMatchingRule
{
  /**
   * The singleton instance that will be returned from the {@code getInstance}
   * method.
   */
  @NotNull private static final CaseIgnoreStringMatchingRule INSTANCE =
       new CaseIgnoreStringMatchingRule();



  /**
   * The name for the caseIgnoreMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_NAME = "caseIgnoreMatch";



  /**
   * The name for the caseIgnoreMatch equality matching rule, formatted in all
   * lowercase characters.
   */
  @NotNull static final String LOWER_EQUALITY_RULE_NAME =
       StaticUtils.toLowerCase(EQUALITY_RULE_NAME);



  /**
   * The OID for the caseIgnoreMatch equality matching rule.
   */
  @NotNull public static final String EQUALITY_RULE_OID = "2.5.13.2";



  /**
   * The name for the caseIgnoreOrderingMatch ordering matching rule.
   */
  @NotNull public static final String ORDERING_RULE_NAME =
       "caseIgnoreOrderingMatch";



  /**
   * The name for the caseIgnoreOrderingMatch ordering matching rule, formatted
   * in all lowercase characters.
   */
  @NotNull static final String LOWER_ORDERING_RULE_NAME =
       StaticUtils.toLowerCase(ORDERING_RULE_NAME);



  /**
   * The OID for the caseIgnoreOrderingMatch ordering matching rule.
   */
  @NotNull public static final String ORDERING_RULE_OID = "2.5.13.3";



  /**
   * The name for the caseIgnoreSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_NAME =
       "caseIgnoreSubstringsMatch";



  /**
   * The name for the caseIgnoreSubstringsMatch substring matching rule,
   * formatted in all lowercase characters.
   */
  @NotNull static final String LOWER_SUBSTRING_RULE_NAME =
       StaticUtils.toLowerCase(SUBSTRING_RULE_NAME);



  /**
   * The OID for the caseIgnoreSubstringsMatch substring matching rule.
   */
  @NotNull public static final String SUBSTRING_RULE_OID = "2.5.13.4";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1293370922676445525L;



  /**
   * Creates a new instance of this case ignore string matching rule.
   */
  public CaseIgnoreStringMatchingRule()
  {
    // No implementation is required.
  }



  /**
   * Retrieves a singleton instance of this matching rule.
   *
   * @return  A singleton instance of this matching rule.
   */
  @NotNull()
  public static CaseIgnoreStringMatchingRule getInstance()
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
  @NotNull()
  public String getOrderingMatchingRuleName()
  {
    return ORDERING_RULE_NAME;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getOrderingMatchingRuleOID()
  {
    return ORDERING_RULE_OID;
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
  {
    // Try to use a quick, no-copy determination if possible.  If this fails,
    // then we'll fall back on a more thorough, but more costly, approach.
    final byte[] value1Bytes = value1.getValue();
    final byte[] value2Bytes = value2.getValue();
    if (value1Bytes.length == value2Bytes.length)
    {
      for (int i=0; i< value1Bytes.length; i++)
      {
        final byte b1 = value1Bytes[i];
        final byte b2 = value2Bytes[i];

        if (((b1 & 0x7F) != (b1 & 0xFF)) ||
            ((b2 & 0x7F) != (b2 & 0xFF)))
        {
          return normalize(value1).equals(normalize(value2));
        }
        else if (b1 != b2)
        {
          if ((b1 == ' ') || (b2 == ' '))
          {
            return normalize(value1).equals(normalize(value2));
          }
          else if (Character.isUpperCase((char) b1))
          {
            final char c = Character.toLowerCase((char) b1);
            if (c != ((char) b2))
            {
              return false;
            }
          }
          else if (Character.isUpperCase((char) b2))
          {
            final char c = Character.toLowerCase((char) b2);
            if (c != ((char) b1))
            {
              return false;
            }
          }
          else
          {
            return false;
          }
        }
      }

      // If we've gotten to this point, then the values must be equal.
      return true;
    }
    else
    {
      return normalizeInternal(value1, false, (byte) 0x00).equals(
                  normalizeInternal(value2, false, (byte) 0x00));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalize(@NotNull final ASN1OctetString value)
  {
    return normalizeInternal(value, false, (byte) 0x00);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1OctetString normalizeSubstring(
                              @NotNull final ASN1OctetString value,
                              final byte substringType)
  {
    return normalizeInternal(value, true, substringType);
  }



  /**
   * Normalizes the provided value for use in either an equality or substring
   * matching operation.
   *
   * @param  value          The value to be normalized.
   * @param  isSubstring    Indicates whether the value should be normalized as
   *                        part of a substring assertion rather than an
   *                        equality assertion.
   * @param  substringType  The substring type for the element, if it is to be
   *                        part of a substring assertion.
   *
   * @return  The appropriately normalized form of the provided value.
   */
  @NotNull()
  private static ASN1OctetString normalizeInternal(
                                      @NotNull final ASN1OctetString value,
                                      final boolean isSubstring,
                                      final byte substringType)
  {
    final byte[] valueBytes = value.getValue();
    if (valueBytes.length == 0)
    {
      return value;
    }

    final boolean trimInitial;
    final boolean trimFinal;
    if (isSubstring)
    {
      switch (substringType)
      {
        case SUBSTRING_TYPE_SUBINITIAL:
          trimInitial = true;
          trimFinal   = false;
          break;

        case SUBSTRING_TYPE_SUBFINAL:
          trimInitial = false;
          trimFinal   = true;
          break;

        default:
          trimInitial = false;
          trimFinal   = false;
          break;
      }
    }
    else
    {
      trimInitial = true;
      trimFinal   = true;
    }

    // Count the number of duplicate spaces in the value, and determine whether
    // there are any non-space characters.  Also, see if there are any non-ASCII
    // characters.
    boolean containsNonSpace = false;
    boolean lastWasSpace = trimInitial;
    int numDuplicates = 0;
    for (final byte b : valueBytes)
    {
      if ((b & 0x7F) != (b & 0xFF))
      {
        return normalizeNonASCII(value, trimInitial, trimFinal);
      }

      if (b == ' ')
      {
        if (lastWasSpace)
        {
          numDuplicates++;
        }
        else
        {
          lastWasSpace = true;
        }
      }
      else
      {
        containsNonSpace = true;
        lastWasSpace = false;
      }
    }

    if (! containsNonSpace)
    {
      return new ASN1OctetString(" ");
    }

    if (lastWasSpace && trimFinal)
    {
      numDuplicates++;
    }


    // Create a new byte array to hold the normalized value.
    lastWasSpace = trimInitial;
    int targetPos = 0;
    final byte[] normalizedBytes = new byte[valueBytes.length - numDuplicates];
    for (int i=0; i < valueBytes.length; i++)
    {
      switch (valueBytes[i])
      {
        case ' ':
          if (lastWasSpace || (trimFinal && (i == (valueBytes.length - 1))))
          {
            // No action is required.
          }
          else
          {
            // This condition is needed to handle the special case in which
            // there are multiple spaces at the end of the value.
            if (targetPos < normalizedBytes.length)
            {
              normalizedBytes[targetPos++] = ' ';
              lastWasSpace = true;
            }
          }

          break;
        case 'A':
          normalizedBytes[targetPos++] = 'a';
          lastWasSpace = false;
          break;
        case 'B':
          normalizedBytes[targetPos++] = 'b';
          lastWasSpace = false;
          break;
        case 'C':
          normalizedBytes[targetPos++] = 'c';
          lastWasSpace = false;
          break;
        case 'D':
          normalizedBytes[targetPos++] = 'd';
          lastWasSpace = false;
          break;
        case 'E':
          normalizedBytes[targetPos++] = 'e';
          lastWasSpace = false;
          break;
        case 'F':
          normalizedBytes[targetPos++] = 'f';
          lastWasSpace = false;
          break;
        case 'G':
          normalizedBytes[targetPos++] = 'g';
          lastWasSpace = false;
          break;
        case 'H':
          normalizedBytes[targetPos++] = 'h';
          lastWasSpace = false;
          break;
        case 'I':
          normalizedBytes[targetPos++] = 'i';
          lastWasSpace = false;
          break;
        case 'J':
          normalizedBytes[targetPos++] = 'j';
          lastWasSpace = false;
          break;
        case 'K':
          normalizedBytes[targetPos++] = 'k';
          lastWasSpace = false;
          break;
        case 'L':
          normalizedBytes[targetPos++] = 'l';
          lastWasSpace = false;
          break;
        case 'M':
          normalizedBytes[targetPos++] = 'm';
          lastWasSpace = false;
          break;
        case 'N':
          normalizedBytes[targetPos++] = 'n';
          lastWasSpace = false;
          break;
        case 'O':
          normalizedBytes[targetPos++] = 'o';
          lastWasSpace = false;
          break;
        case 'P':
          normalizedBytes[targetPos++] = 'p';
          lastWasSpace = false;
          break;
        case 'Q':
          normalizedBytes[targetPos++] = 'q';
          lastWasSpace = false;
          break;
        case 'R':
          normalizedBytes[targetPos++] = 'r';
          lastWasSpace = false;
          break;
        case 'S':
          normalizedBytes[targetPos++] = 's';
          lastWasSpace = false;
          break;
        case 'T':
          normalizedBytes[targetPos++] = 't';
          lastWasSpace = false;
          break;
        case 'U':
          normalizedBytes[targetPos++] = 'u';
          lastWasSpace = false;
          break;
        case 'V':
          normalizedBytes[targetPos++] = 'v';
          lastWasSpace = false;
          break;
        case 'W':
          normalizedBytes[targetPos++] = 'w';
          lastWasSpace = false;
          break;
        case 'X':
          normalizedBytes[targetPos++] = 'x';
          lastWasSpace = false;
          break;
        case 'Y':
          normalizedBytes[targetPos++] = 'y';
          lastWasSpace = false;
          break;
        case 'Z':
          normalizedBytes[targetPos++] = 'z';
          lastWasSpace = false;
          break;
        default:
          normalizedBytes[targetPos++] = valueBytes[i];
          lastWasSpace = false;
          break;
      }
    }


    return new ASN1OctetString(normalizedBytes);
  }



  /**
   * Normalizes the provided value a string representation, properly handling
   * any non-ASCII characters.
   *
   * @param  value        The value to be normalized.
   * @param  trimInitial  Indicates whether to trim off all leading spaces at
   *                      the beginning of the value.
   * @param  trimFinal    Indicates whether to trim off all trailing spaces at
   *                      the end of the value.
   *
   * @return  The normalized form of the value.
   */
  @NotNull()
  private static ASN1OctetString normalizeNonASCII(
                                      @NotNull final ASN1OctetString value,
                                      final boolean trimInitial,
                                      final boolean trimFinal)
  {
    final StringBuilder buffer = new StringBuilder(value.stringValue());

    int pos = 0;
    boolean lastWasSpace = trimInitial;
    while (pos < buffer.length())
    {
      final char c = buffer.charAt(pos++);
      if (c == ' ')
      {
        if (lastWasSpace || (trimFinal && (pos >= buffer.length())))
        {
          buffer.deleteCharAt(--pos);
        }
        else
        {
          lastWasSpace = true;
        }
      }
      else
      {
        if (Character.isHighSurrogate(c))
        {
          if (pos < buffer.length())
          {
            final char c2 = buffer.charAt(pos++);
            if (Character.isLowSurrogate(c2))
            {
              final int codePoint = Character.toCodePoint(c, c2);
              if (Character.isUpperCase(codePoint))
              {
                final int lowerCaseCodePoint = Character.toLowerCase(codePoint);
                buffer.setCharAt((pos-2),
                     Character.highSurrogate(lowerCaseCodePoint));
                buffer.setCharAt((pos-1),
                     Character.lowSurrogate(lowerCaseCodePoint));
              }
            }
          }
        }
        else if (Character.isUpperCase(c))
        {
          buffer.setCharAt((pos-1), Character.toLowerCase(c));
        }

        lastWasSpace = false;
      }
    }

    // It is possible that there could be an extra space at the end.  If that's
    // the case, then remove it.
    if (trimFinal && (buffer.length() > 0) &&
        (buffer.charAt(buffer.length() - 1) == ' '))
    {
      buffer.deleteCharAt(buffer.length() - 1);
    }

    return new ASN1OctetString(buffer.toString());
  }
}
