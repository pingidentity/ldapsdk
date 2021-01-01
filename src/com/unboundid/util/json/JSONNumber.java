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
package com.unboundid.util.json;



import java.math.BigDecimal;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.json.JSONMessages.*;



/**
 * This class provides an implementation of a JSON value that represents a
 * base-ten numeric value of arbitrary size.  It may or may not be a
 * floating-point value (including a decimal point with numbers to the right of
 * it), and it may or may not be expressed using scientific notation.  The
 * numeric value will be represented internally as a {@code BigDecimal}.
 * <BR><BR>
 * The string representation of a JSON number consists of the following
 * elements, in the following order:
 * <OL>
 *   <LI>
 *     An optional minus sign to indicate that the value is negative.  If this
 *     is absent, then the number will be positive.  Positive numbers must not
 *     be prefixed with a plus sign.
 *   </LI>
 *   <LI>
 *     One or more numeric digits to specify the whole number portion of the
 *     value.  There must not be any unnecessary leading zeroes, so the first
 *     digit may be zero only if it is the only digit in the whole number
 *     portion of the value.
 *   </LI>
 *   <LI>
 *     An optional decimal point followed by at least one numeric digit to
 *     indicate the fractional portion of the value.  Trailing zeroes are
 *     allowed in the fractional component.
 *   </LI>
 *   <LI>
 *     An optional 'e' or 'E' character, followed by an optional '+' or '-'
 *     character and at least one numeric digit to indicate that the value is
 *     expressed in scientific notation and the number before the uppercase or
 *     lowercase E should be multiplied by the specified positive or negative
 *     power of ten.
 *   </LI>
 * </OL>
 * It is possible for the same number to have multiple equivalent string
 * representations.  For example, all of the following valid string
 * representations of JSON numbers represent the same numeric value:
 * <UL>
 *   <LI>12345</LI>
 *   <LI>12345.0</LI>
 *   <LI>1.2345e4</LI>
 *   <LI>1.2345e+4</LI>
 * </UL>
 * JSON numbers must not be enclosed in quotation marks.
 * <BR><BR>
 * If a JSON number is created from its string representation, then that
 * string representation will be returned from the {@link #toString()} method
 * (or appended to the provided buffer for the {@link #toString(StringBuilder)}
 * method).  If a JSON number is created from a {@code long} or {@code double}
 * value, then the Java string representation of that value (as obtained from
 * the {@code String.valueOf} method) will be used as the string representation
 * for the number.  If a JSON number is created from a {@code BigDecimal} value,
 * then the Java string representation will be obtained via that value's
 * {@code toPlainString} method.
 * <BR><BR>
 * The normalized representation of a JSON number is a canonical string
 * representation for that number.  That is, all equivalent JSON number values
 * will have the same normalized representation.  The normalized representation
 * will never use scientific notation, will never have trailing zeroes in the
 * fractional component, and will never have a fractional component if that
 * fractional component would be zero.  For example, for the
 * logically-equivalent values "12345", "12345.0", "1.2345e4", and "1.2345e+4",
 * the normalized representation will be "12345".  For the logically-equivalent
 * values "9876.5", "9876.50", and "9.8765e3", the normalized representation
 * will be "9876.5".
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONNumber
       extends JSONValue
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9194944952299318254L;



  // The numeric value for this object.
  @NotNull private final BigDecimal value;

  // The normalized representation of the value.
  @NotNull private final BigDecimal normalizedValue;

  // The string representation for this object.
  @NotNull private final String stringRepresentation;



  /**
   * Creates a new JSON number with the provided value.
   *
   * @param  value  The value for this JSON number.
   */
  public JSONNumber(final long value)
  {
    this.value = new BigDecimal(value);
    normalizedValue = this.value;
    stringRepresentation = String.valueOf(value);
  }



  /**
   * Creates a new JSON number with the provided value.
   *
   * @param  value  The value for this JSON number.
   */
  public JSONNumber(final double value)
  {
    this.value = new BigDecimal(value);
    normalizedValue = this.value;
    stringRepresentation = String.valueOf(value);
  }



  /**
   * Creates a new JSON number with the provided value.
   *
   * @param  value  The value for this JSON number.  It must not be
   *                {@code null}.
   */
  public JSONNumber(@NotNull final BigDecimal value)
  {
    this.value = value;
    stringRepresentation = value.toPlainString();

    // There isn't a simple way to get a good normalized value from a
    // BigDecimal.  If it represents an integer but has a decimal point followed
    // by some zeroes, then the only way we can strip them off is to convert it
    // from a BigDecimal to a BigInteger and back.  If it represents a
    // floating-point value that has unnecessary zeros then we have to call the
    // stripTrailingZeroes method.
    BigDecimal minimalValue;
    try
    {
      minimalValue = new BigDecimal(value.toBigIntegerExact());
    }
    catch (final Exception e)
    {
      // This is fine -- it just means that the value does not represent an
      // integer.
      minimalValue = value.stripTrailingZeros();
    }
    normalizedValue = minimalValue;
  }



  /**
   * Creates a new JSON number from the provided string representation.
   *
   * @param  stringRepresentation  The string representation to parse as a JSON
   *                               number.  It must not be {@code null}.
   *
   * @throws  JSONException  If the provided string cannot be parsed as a valid
   *                         JSON number.
   */
  public JSONNumber(@NotNull final String stringRepresentation)
         throws JSONException
  {
    this.stringRepresentation = stringRepresentation;


    // Make sure that the provided string represents a valid JSON number.  This
    // is a little more strict than what BigDecimal accepts.  First, make sure
    // it's not an empty string.
    final char[] chars = stringRepresentation.toCharArray();
    if (chars.length == 0)
    {
      throw new JSONException(ERR_NUMBER_EMPTY_STRING.get());
    }


    // Make sure that the last character is a digit.  All valid string
    // representations of JSON numbers must end with a digit, and validating
    // that now allows us to do less error handling in subsequent checks.
    if (! isDigit(chars[chars.length-1]))
    {
      throw new JSONException(ERR_NUMBER_LAST_CHAR_NOT_DIGIT.get(
           stringRepresentation));
    }


    // If the value starts with a minus sign, then skip over it.
    int pos = 0;
    if (chars[0] == '-')
    {
      pos++;
    }


    // Make sure that the first character (after the potential minus sign) is a
    // digit.  If it's a zero, then make sure it's not followed by another
    // digit.
    if (! isDigit(chars[pos]))
    {
      throw new JSONException(ERR_NUMBER_ILLEGAL_CHAR.get(stringRepresentation,
           pos));
    }

    if (chars[pos++] == '0')
    {
      if ((chars.length > pos) && isDigit(chars[pos]))
      {
        throw new JSONException(ERR_NUMBER_ILLEGAL_LEADING_ZERO.get(
             stringRepresentation));
      }
    }


    // Parse the rest of the string.  Make sure that it satisfies all of the
    // following constraints:
    // - There can be at most one decimal point.  If there is a decimal point,
    //   it must be followed by at least one digit.
    // - There can be at most one uppercase or lowercase 'E'.  If there is an
    //   'E', then it must be followed by at least one digit, or it must be
    //   followed by a plus or minus sign and at least one digit.
    // - If there are both a decimal point and an 'E', then the decimal point
    //   must come before the 'E'.
    // - The only other characters allowed are digits.
    boolean decimalFound = false;
    boolean eFound = false;
    for ( ; pos < chars.length; pos++)
    {
      final char c = chars[pos];
      if (c == '.')
      {
        if (decimalFound)
        {
          throw new JSONException(ERR_NUMBER_MULTIPLE_DECIMAL_POINTS.get(
               stringRepresentation));
        }
        else
        {
          decimalFound = true;
        }

        if (eFound)
        {
          throw new JSONException(ERR_NUMBER_DECIMAL_IN_EXPONENT.get(
               stringRepresentation));
        }

        if (! isDigit(chars[pos+1]))
        {
          throw new JSONException(ERR_NUMBER_DECIMAL_NOT_FOLLOWED_BY_DIGIT.get(
               stringRepresentation));
        }
      }
      else if ((c == 'e') || (c == 'E'))
      {
        if (eFound)
        {
          throw new JSONException(ERR_NUMBER_MULTIPLE_EXPONENTS.get(
               stringRepresentation));
        }
        else
        {
          eFound = true;
        }

        if ((chars[pos+1] == '-') || (chars[pos+1] == '+'))
        {
          if (! isDigit(chars[pos+2]))
          {
            throw new JSONException(
                 ERR_NUMBER_EXPONENT_NOT_FOLLOWED_BY_DIGIT.get(
                      stringRepresentation));
          }

          // Increment the counter to skip over the sign.
          pos++;
        }
        else if (! isDigit(chars[pos+1]))
        {
          throw new JSONException(ERR_NUMBER_EXPONENT_NOT_FOLLOWED_BY_DIGIT.get(
               stringRepresentation));
        }
      }
      else if (! isDigit(chars[pos]))
      {
        throw new JSONException(ERR_NUMBER_ILLEGAL_CHAR.get(
             stringRepresentation, pos));
      }
    }


    // If we've gotten here, then we know the string represents a valid JSON
    // number.  BigDecimal should be able to parse all valid JSON numbers.
    try
    {
      value = new BigDecimal(stringRepresentation);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      // This should never happen if all of the validation above is correct, but
      // handle it just in case.
      throw new JSONException(
           ERR_NUMBER_CANNOT_PARSE.get(stringRepresentation,
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    // There isn't a simple way to get a good normalized value from a
    // BigDecimal.  If it represents an integer but has a decimal point followed
    // by some zeroes, then the only way we can strip them off is to convert it
    // from a BigDecimal to a BigInteger and back.  If it represents a
    // floating-point value that has unnecessary zeros then we have to call the
    // stripTrailingZeroes method.
    BigDecimal minimalValue;
    try
    {
      minimalValue = new BigDecimal(value.toBigIntegerExact());
    }
    catch (final Exception e)
    {
      // This is fine -- it just means that the value does not represent an
      // integer.
      minimalValue = value.stripTrailingZeros();
    }
    normalizedValue = minimalValue;
  }



  /**
   * Indicates whether the specified character represents a digit.
   *
   * @param  c  The character for which to make the determination.
   *
   * @return  {@code true} if the specified character represents a digit, or
   *          {@code false} if not.
   */
  private static boolean isDigit(final char c)
  {
    switch (c)
    {
      case '0':
      case '1':
      case '2':
      case '3':
      case '4':
      case '5':
      case '6':
      case '7':
      case '8':
      case '9':
        return true;
      default:
        return false;
    }
  }



  /**
   * Retrieves the value of this JSON number as a {@code BigDecimal}.
   *
   * @return  The value of this JSON number as a {@code BigDecimal}.
   */
  @NotNull()
  public BigDecimal getValue()
  {
    return value;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    return normalizedValue.hashCode();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == this)
    {
      return true;
    }

    if (o instanceof JSONNumber)
    {
      // NOTE:  BigDecimal.equals probably doesn't do what you want, nor what
      // anyone would normally expect.  If you want to determine if two
      // BigDecimal values are the same, then use compareTo.
      final JSONNumber n = (JSONNumber) o;
      return (value.compareTo(n.value) == 0);
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(@NotNull final JSONValue v,
                        final boolean ignoreFieldNameCase,
                        final boolean ignoreValueCase,
                        final boolean ignoreArrayOrder)
  {
    return ((v instanceof JSONNumber) &&
         (value.compareTo(((JSONNumber) v).value) == 0));
  }



  /**
   * Retrieves a string representation of this number as it should appear in a
   * JSON object.  If the object containing this number was decoded from a
   * string, then this method will use the same string representation as in that
   * original object.  Otherwise, the string representation will be constructed.
   *
   * @return  A string representation of this number as it should appear in a
   *          JSON object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return stringRepresentation;
  }



  /**
   * Appends a string representation of this number as it should appear in a
   * JSON object to the provided buffer.  If the object containing this number
   * was decoded from a string, then this method will use the same string
   * representation as in that original object.  Otherwise, the string
   * representation will be constructed.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(stringRepresentation);
  }



  /**
   * Retrieves a single-line string representation of this number as it should
   * appear in a JSON object.  If the object containing this number was decoded
   * from a string, then this method will use the same string representation as
   * in that original object.  Otherwise, the string representation will be
   * constructed.
   *
   * @return  A single-line string representation of this number as it should
   *          appear in a JSON object.
   */
  @Override()
  @NotNull()
  public String toSingleLineString()
  {
    return stringRepresentation;
  }



  /**
   * Appends a single-line string representation of this number as it should
   * appear in a JSON object to the provided buffer.  If the object containing
   * this number was decoded from a string, then this method will use the same
   * string representation as in that original object.  Otherwise, the string
   * representation will be constructed.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toSingleLineString(@NotNull final StringBuilder buffer)
  {
    buffer.append(stringRepresentation);
  }



  /**
   * Retrieves a normalized string representation of this number as it should
   * appear in a JSON object.  The normalized representation will not use
   * exponentiation, will not include a decimal point if the value can be
   * represented as an integer, and will not include any unnecessary trailing
   * zeroes if it can only be represented as a floating-point value.
   *
   * @return  A normalized string representation of this number as it should
   *          appear in a JSON object.
   */
  @Override()
  @NotNull()
  public String toNormalizedString()
  {
    return normalizedValue.toPlainString();
  }



  /**
   * Appends a normalized string representation of this number as it should
   * appear in a JSON object to the provided buffer.  The normalized
   * representation will not use exponentiation, will not include a decimal
   * point if the value can be represented as an integer, and will not include
   * any unnecessary trailing zeroes if it can only be represented as a
   * floating-point value.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    buffer.append(normalizedValue.toPlainString());
  }



  /**
   * Retrieves a normalized string representation of this number as it should
   * appear in a JSON object.  The normalized representation will not use
   * exponentiation, will not include a decimal point if the value can be
   * represented as an integer, and will not include any unnecessary trailing
   * zeroes if it can only be represented as a floating-point value.
   *
   * @param  ignoreFieldNameCase  Indicates whether field names should be
   *                              treated in a case-sensitive (if {@code false})
   *                              or case-insensitive (if {@code true}) manner.
   * @param  ignoreValueCase      Indicates whether string field values should
   *                              be treated in a case-sensitive (if
   *                              {@code false}) or case-insensitive (if
   *                              {@code true}) manner.
   * @param  ignoreArrayOrder     Indicates whether the order of elements in an
   *                              array should be considered significant (if
   *                              {@code false}) or insignificant (if
   *                              {@code true}).
   *
   * @return  A normalized string representation of this number as it should
   *          appear in a JSON object.
   */
  @Override()
  @NotNull()
  public String toNormalizedString(final boolean ignoreFieldNameCase,
                                   final boolean ignoreValueCase,
                                   final boolean ignoreArrayOrder)
  {
    return normalizedValue.toPlainString();
  }



  /**
   * Appends a normalized string representation of this number as it should
   * appear in a JSON object to the provided buffer.  The normalized
   * representation will not use exponentiation, will not include a decimal
   * point if the value can be represented as an integer, and will not include
   * any unnecessary trailing zeroes if it can only be represented as a
   * floating-point value.
   *
   * @param  buffer               The buffer to which the information should be
   *                              appended.
   * @param  ignoreFieldNameCase  Indicates whether field names should be
   *                              treated in a case-sensitive (if {@code false})
   *                              or case-insensitive (if {@code true}) manner.
   * @param  ignoreValueCase      Indicates whether string field values should
   *                              be treated in a case-sensitive (if
   *                              {@code false}) or case-insensitive (if
   *                              {@code true}) manner.
   * @param  ignoreArrayOrder     Indicates whether the order of elements in an
   *                              array should be considered significant (if
   *                              {@code false}) or insignificant (if
   *                              {@code true}).
   */
  @Override()
  public void toNormalizedString(@NotNull final StringBuilder buffer,
                                 final boolean ignoreFieldNameCase,
                                 final boolean ignoreValueCase,
                                 final boolean ignoreArrayOrder)
  {
    buffer.append(normalizedValue.toPlainString());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(stringRepresentation);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final String fieldName,
                                 @NotNull final JSONBuffer buffer)
  {
    buffer.appendNumber(fieldName, stringRepresentation);
  }
}
