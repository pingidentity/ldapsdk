/*
 * Copyright 2015-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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



import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an implementation of a JSON value that represents a
 * Java Boolean.  The string representation of the JSON Boolean true value is
 * {@code true}, and the string representation of the JSON Boolean false value
 * is {@code false}.  These values are not surrounded by quotation marks, and
 * they must be entirely lowercase.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONBoolean
       extends JSONValue
{
  /**
   * A pre-allocated object that represents a value of {@code false}.
   */
  public static final JSONBoolean FALSE = new JSONBoolean(false);



  /**
   * A pre-allocated object that represents a value of {@code true}.
   */
  public static final JSONBoolean TRUE = new JSONBoolean(true);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5090296701442873481L;



  // The boolean value for this object.
  private final boolean booleanValue;

  // The string representation for this object.
  private final String stringRepresentation;



  /**
   * Creates a new JSON value capable of representing a Boolean value of either
   * {@code true} or {@code false}.
   *
   * @param  booleanValue  The Boolean value for this JSON value.
   */
  public JSONBoolean(final boolean booleanValue)
  {
    this.booleanValue = booleanValue;
    stringRepresentation = (booleanValue ? "true" : "false");
  }



  /**
   * Retrieves the Java boolean value for this JSON value.
   *
   * @return  The Java boolean value for this JSON value.
   */
  public boolean booleanValue()
  {
    return booleanValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public int hashCode()
  {
    return (booleanValue ? Boolean.TRUE.hashCode() : Boolean.FALSE.hashCode());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(final Object o)
  {
    if (o == this)
    {
      return true;
    }

    if (o instanceof JSONBoolean)
    {
      final JSONBoolean b = (JSONBoolean) o;
      return (b.booleanValue == booleanValue);
    }

    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean equals(final JSONValue v, final boolean ignoreFieldNameCase,
                        final boolean ignoreValueCase,
                        final boolean ignoreArrayOrder)
  {
    return ((v instanceof JSONBoolean) &&
         (booleanValue == ((JSONBoolean) v).booleanValue));
  }



  /**
   * Retrieves a string representation of this Boolean value as it should appear
   * in a JSON object.  If the Boolean value is {@code true}, then the string
   * representation will be "{@code true}" (without the surrounding quotes).  If
   * the Boolean value is {@code false}, then the string representation will be
   * "{@code false}" (again, without the quotes).
   *
   * @return  A string representation of this Boolean value as it should appear
   *          in a JSON object.
   */
  @Override()
  public String toString()
  {
    return stringRepresentation;
  }



  /**
   * Appends a string representation of this Boolean value as it should appear
   * in a JSON object to the provided buffer.  If the Boolean value is
   * {@code true}, then the string representation will be "{@code true}"
   * (without the surrounding quotes).  If the Boolean value is {@code false},
   * then the string representation will be "{@code false}" (again, without the
   * quotes).
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append(stringRepresentation);
  }



  /**
   * Retrieves a single-line string representation of this Boolean value as it
   * should appear in a JSON object.  If the Boolean value is {@code true}, then
   * the string representation will be "{@code true}" (without the surrounding
   * quotes).  If the Boolean value is {@code false}, then the string
   * representation will be "{@code false}" (again, without the quotes).
   *
   * @return  A single-line string representation of this Boolean value as it
   *          should appear in a JSON object.
   */
  @Override()
  public String toSingleLineString()
  {
    return stringRepresentation;
  }



  /**
   * Appends a single-line string representation of this Boolean value as it
   * should appear in a JSON object to the provided buffer.  If the Boolean
   * value is {@code true}, then the string representation will be
   * "{@code true}" (without the surrounding quotes).  If the Boolean value is
   * {@code false}, then the string representation will be "{@code false}"
   * (again, without the quotes).
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toSingleLineString(final StringBuilder buffer)
  {
    buffer.append(stringRepresentation);
  }



  /**
   * Retrieves a normalized string representation of this Boolean value as it
   * should appear in a JSON object.  If the Boolean value is {@code true}, then
   * the string representation will be "{@code true}" (without the surrounding
   * quotes).  If the Boolean value is {@code false}, then the string
   * representation will be "{@code false}" (again, without the quotes).
   *
   * @return  A normalized string representation of this Boolean value as it
   *          should appear in a JSON object.
   */
  @Override()
  public String toNormalizedString()
  {
    return stringRepresentation;
  }



  /**
   * Appends a normalized string representation of this Boolean value as it
   * should appear in a JSON object to the provided buffer.  If the Boolean
   * value is {@code true}, then the string representation will be
   * "{@code true}" (without the surrounding quotes).  If the Boolean value is
   * {@code false}, then the string representation will be "{@code false}"
   * (again, without the quotes).
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  @Override()
  public void toNormalizedString(final StringBuilder buffer)
  {
    buffer.append(stringRepresentation);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(final JSONBuffer buffer)
  {
    buffer.appendBoolean(booleanValue);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void appendToJSONBuffer(final String fieldName,
                                 final JSONBuffer buffer)
  {
    buffer.appendBoolean(fieldName, booleanValue);
  }
}
