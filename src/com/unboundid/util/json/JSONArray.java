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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a JSON value that represents an
 * ordered collection of zero or more values.  An array can contain elements of
 * any type, including a mix of types, and including nested arrays.  The same
 * value may appear multiple times in an array.
 * <BR><BR>
 * The string representation of a JSON array is an open square bracket (U+005B)
 * followed by a comma-delimited list of the string representations of the
 * values in that array and a closing square bracket (U+005D).  There must not
 * be a comma between the last item in the array and the closing square bracket.
 * There may optionally be any amount of whitespace (where whitespace characters
 * include the ASCII space, horizontal tab, line feed, and carriage return
 * characters) after the open square bracket, on either or both sides of commas
 * separating values, and before the close square bracket.
 * <BR><BR>
 * The string representation returned by the {@link #toString()} method (or
 * appended to the buffer provided to the {@link #toString(StringBuilder)}
 * method) will include one space before each value in the array and one space
 * before the closing square bracket.  There will not be any space between a
 * value and the comma that follows it.  The string representation of each value
 * in the array will be obtained using that value's {@code toString} method.
 * <BR><BR>
 * The normalized string representation will not include any optional spaces,
 * and the normalized string representation of each value in the array will be
 * obtained using that value's {@code toNormalizedString} method.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONArray
       extends JSONValue
{
  /**
   * A pre-allocated empty JSON array.
   */
  @NotNull public static final JSONArray EMPTY_ARRAY = new JSONArray();



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5493008945333225318L;



  // The hash code for this JSON array.
  @Nullable private Integer hashCode;

  // The list of values for this array.
  @NotNull private final List<JSONValue> values;

  // The string representation for this JSON array.
  @Nullable private String stringRepresentation;



  /**
   * Creates a new JSON array with the provided values.
   *
   * @param  values  The set of values to include in this JSON array.  It may be
   *                 {@code null} or empty to indicate that the array should be
   *                 empty.
   */
  public JSONArray(@Nullable final JSONValue... values)
  {
    this((values == null) ? null : Arrays.asList(values));
  }



  /**
   * Creates a new JSON array with the provided values.
   *
   * @param  values  The set of values to include in this JSON array.  It may be
   *                 {@code null} or empty to indicate that the array should be
   *                 empty.
   */
  public JSONArray(@Nullable final List<? extends JSONValue> values)
  {
    if (values == null)
    {
      this.values = Collections.emptyList();
    }
    else
    {
      this.values =
           Collections.unmodifiableList(new ArrayList<>(values));
    }

    hashCode = null;
    stringRepresentation = null;
  }



  /**
   * Retrieves the set of values contained in this JSON array.
   *
   * @return  The set of values contained in this JSON array.
   */
  @NotNull()
  public List<JSONValue> getValues()
  {
    return values;
  }



  /**
   * Indicates whether this array is empty.
   *
   * @return  {@code true} if this array does not contain any values, or
   *          {@code false} if this array contains at least one value.
   */
  public boolean isEmpty()
  {
    return values.isEmpty();
  }



  /**
   * Retrieves the number of values contained in this array.
   *
   * @return  The number of values contained in this array.
   */
  public int size()
  {
    return values.size();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    if (hashCode == null)
    {
      int hc = 0;
      for (final JSONValue v : values)
      {
        hc = (hc * 31) + v.hashCode();
      }

      hashCode = hc;
    }

    return hashCode;
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

    if (o instanceof JSONArray)
    {
      final JSONArray a = (JSONArray) o;
      return values.equals(a.values);
    }

    return false;
  }



  /**
   * Indicates whether this JSON array is considered equivalent to the provided
   * array, subject to the specified constraints.
   *
   * @param  array                The array for which to make the determination.
   * @param  ignoreFieldNameCase  Indicates whether to ignore differences in
   *                              capitalization in field names for any JSON
   *                              objects contained in the array.
   * @param  ignoreValueCase      Indicates whether to ignore differences in
   *                              capitalization for array elements that are
   *                              JSON strings, as well as for the string values
   *                              of any JSON objects and arrays contained in
   *                              the array.
   * @param  ignoreArrayOrder     Indicates whether to ignore differences in the
   *                              order of elements contained in the array.
   *
   * @return  {@code true} if this JSON array is considered equivalent to the
   *          provided array (subject to the specified constraints), or
   *          {@code false} if not.
   */
  public boolean equals(@NotNull final JSONArray array,
                        final boolean ignoreFieldNameCase,
                        final boolean ignoreValueCase,
                        final boolean ignoreArrayOrder)
  {
    // See if we can do a straight-up List.equals.  If so, just do that.
    if ((! ignoreFieldNameCase) && (! ignoreValueCase) && (! ignoreArrayOrder))
    {
      return values.equals(array.values);
    }

    // Make sure the arrays have the same number of elements.
    if (values.size() != array.values.size())
    {
      return false;
    }

    // Optimize for the case in which the order of values is significant.
    if (! ignoreArrayOrder)
    {
      final Iterator<JSONValue> thisIterator = values.iterator();
      final Iterator<JSONValue> thatIterator = array.values.iterator();
      while (thisIterator.hasNext())
      {
        final JSONValue thisValue = thisIterator.next();
        final JSONValue thatValue = thatIterator.next();
        if (! thisValue.equals(thatValue, ignoreFieldNameCase, ignoreValueCase,
             ignoreArrayOrder))
        {
          return false;
        }
      }

      return true;
    }


    // If we've gotten here, then we know that we don't care about the order.
    // Create a new list that we can remove values from as we find matches.
    // This is important because arrays can have duplicate values, and we don't
    // want to keep matching the same element.
    final ArrayList<JSONValue> thatValues = new ArrayList<>(array.values);
    final Iterator<JSONValue> thisIterator = values.iterator();
    while (thisIterator.hasNext())
    {
      final JSONValue thisValue = thisIterator.next();

      boolean found = false;
      final Iterator<JSONValue> thatIterator = thatValues.iterator();
      while (thatIterator.hasNext())
      {
        final JSONValue thatValue = thatIterator.next();
        if (thisValue.equals(thatValue, ignoreFieldNameCase, ignoreValueCase,
             ignoreArrayOrder))
        {
          found = true;
          thatIterator.remove();
          break;
        }
      }

      if (! found)
      {
        return false;
      }
    }

    return true;
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
    return ((v instanceof JSONArray) &&
         equals((JSONArray) v, ignoreFieldNameCase, ignoreValueCase,
              ignoreArrayOrder));
  }



  /**
   * Indicates whether this JSON array contains an element with the specified
   * value.
   *
   * @param  value                The value for which to make the determination.
   * @param  ignoreFieldNameCase  Indicates whether to ignore differences in
   *                              capitalization in field names for any JSON
   *                              objects contained in the array.
   * @param  ignoreValueCase      Indicates whether to ignore differences in
   *                              capitalization for array elements that are
   *                              JSON strings, as well as for the string values
   *                              of any JSON objects and arrays contained in
   *                              the array.
   * @param  ignoreArrayOrder     Indicates whether to ignore differences in the
   *                              order of elements contained in arrays.  This
   *                              is only applicable if the provided value is
   *                              itself an array or is a JSON object that
   *                              contains values that are arrays.
   * @param  recursive            Indicates whether to recursively look into any
   *                              arrays contained inside this array.
   *
   * @return  {@code true} if this JSON array contains an element with the
   *          specified value, or {@code false} if not.
   */
  public boolean contains(@NotNull final JSONValue value,
                          final boolean ignoreFieldNameCase,
                          final boolean ignoreValueCase,
                          final boolean ignoreArrayOrder,
                          final boolean recursive)
  {
    for (final JSONValue v : values)
    {
      if (v.equals(value, ignoreFieldNameCase, ignoreValueCase,
           ignoreArrayOrder))
      {
        return true;
      }

      if (recursive && (v instanceof JSONArray) &&
          ((JSONArray) v).contains(value, ignoreFieldNameCase, ignoreValueCase,
               ignoreArrayOrder, recursive))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Retrieves a string representation of this array as it should appear in a
   * JSON object, including the surrounding square brackets.  Appropriate
   * encoding will also be used for all elements in the array.    If the object
   * containing this array was decoded from a string, then this method will use
   * the same string representation as in that original object.  Otherwise, the
   * string representation will be constructed.
   *
   * @return  A string representation of this array as it should appear in a
   *          JSON object, including the surrounding square brackets.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    if (stringRepresentation == null)
    {
      final StringBuilder buffer = new StringBuilder();
      toString(buffer);
      stringRepresentation = buffer.toString();
    }

    return stringRepresentation;
  }



  /**
   * Appends a string representation of this value as it should appear in a
   * JSON object, including the surrounding square brackets,. to the provided
   * buffer.  Appropriate encoding will also be used for all elements in the
   * array.    If the object containing this array was decoded from a string,
   * then this method will use the same string representation as in that
   * original object.  Otherwise, the string representation will be constructed.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    if (stringRepresentation != null)
    {
      buffer.append(stringRepresentation);
      return;
    }

    buffer.append("[ ");

    final Iterator<JSONValue> iterator = values.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
      buffer.append(' ');
    }

    buffer.append(']');
  }



  /**
   * Retrieves a single-line string representation of this array as it should
   * appear in a JSON object, including the surrounding square brackets.
   * Appropriate encoding will also be used for all elements in the array.
   *
   * @return  A string representation of this array as it should appear in a
   *          JSON object, including the surrounding square brackets.
   */
  @Override()
  @NotNull()
  public String toSingleLineString()
  {
    final StringBuilder buffer = new StringBuilder();
    toSingleLineString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a single-line string representation of this array as it should
   * appear in a JSON object, including the surrounding square brackets, to the
   * provided buffer.  Appropriate encoding will also be used for all elements
   * in the array.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toSingleLineString(@NotNull final StringBuilder buffer)
  {
    buffer.append("[ ");

    final Iterator<JSONValue> iterator = values.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toSingleLineString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
      buffer.append(' ');
    }

    buffer.append(']');
  }



  /**
   * Retrieves a normalized string representation of this array.  The normalized
   * representation will not contain any line breaks, will not include any
   * spaces around the enclosing brackets or around commas used to separate the
   * elements, and it will use the normalized representations of those elements.
   * The order of elements in an array is considered significant, and will not
   * be affected by the normalization process.
   *
   * @return  A normalized string representation of this array.
   */
  @Override()
  @NotNull()
  public String toNormalizedString()
  {
    final StringBuilder buffer = new StringBuilder();
    toNormalizedString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a normalized string representation of this array to the provided
   * buffer.  The normalized representation will not contain any line breaks,
   * will not include any spaces around the enclosing brackets or around commas
   * used to separate the elements, and it will use the normalized
   * representations of those elements. The order of elements in an array is
   * considered significant, and will not be affected by the normalization
   * process.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toNormalizedString(@NotNull final StringBuilder buffer)
  {
    toNormalizedString(buffer, false, true, false);
  }



  /**
   * Retrieves a normalized string representation of this array.  The normalized
   * representation will not contain any line breaks, will not include any
   * spaces around the enclosing brackets or around commas used to separate the
   * elements, and it will use the normalized representations of those elements.
   * The order of elements in an array is considered significant, and will not
   * be affected by the normalization process.
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
   * @return  A normalized string representation of this array.
   */
  @Override()
  @NotNull()
  public String toNormalizedString(final boolean ignoreFieldNameCase,
                                   final boolean ignoreValueCase,
                                   final boolean ignoreArrayOrder)
  {
    final StringBuilder buffer = new StringBuilder();
    toNormalizedString(buffer, ignoreFieldNameCase, ignoreValueCase,
         ignoreArrayOrder);
    return buffer.toString();
  }



  /**
   * Appends a normalized string representation of this array to the provided
   * buffer.  The normalized representation will not contain any line breaks,
   * will not include any spaces around the enclosing brackets or around commas
   * used to separate the elements, and it will use the normalized
   * representations of those elements. The order of elements in an array is
   * considered significant, and will not be affected by the normalization
   * process.
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
    final List<String> normalizedValues = new ArrayList<>(values.size());
    for (final JSONValue v : values)
    {
      normalizedValues.add(v.toNormalizedString(ignoreFieldNameCase,
           ignoreValueCase, ignoreArrayOrder));
    }

    if (ignoreArrayOrder)
    {
      Collections.sort(normalizedValues);
    }

    buffer.append('[');

    final Iterator<String> iterator = normalizedValues.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next());
      if (iterator.hasNext())
      {
        buffer.append(',');
      }
    }

    buffer.append(']');
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final JSONBuffer buffer)
  {
    buffer.beginArray();

    for (final JSONValue value : values)
    {
      value.appendToJSONBuffer(buffer);
    }

    buffer.endArray();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(@NotNull final String fieldName,
                                 @NotNull final JSONBuffer buffer)
  {
    buffer.beginArray(fieldName);

    for (final JSONValue value : values)
    {
      value.appendToJSONBuffer(buffer);
    }

    buffer.endArray();
  }
}
