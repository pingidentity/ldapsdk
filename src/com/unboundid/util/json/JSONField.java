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



import java.io.Serializable;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a simple data structure that represents a field in a
 * JSON object, containing a name and a value.  This is primarily intended as a
 * convenience when programmatically constructing JSON objects.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class JSONField
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1397826405959590851L;



  // The value for this field.
  private final JSONValue value;

  // The name for this field.
  private final String name;



  /**
   * Creates a new JSON field with the specified name and value.
   *
   * @param name  The name for this field.  It must not be {@code null}.
   * @param value The value for this field.  It must not be {@code null}
   *              (although it may be a {@link JSONNull} instance).
   */
  public JSONField(final String name, final JSONValue value)
  {
    Validator.ensureNotNull(name);
    Validator.ensureNotNull(value);

    this.name = name;
    this.value = value;
  }



  /**
   * Creates a new JSON field with the specified name and a {@link JSONBoolean}
   * value.
   *
   * @param name  The name for this field.  It must not be {@code null}.
   * @param value The value for this field.  It must not be {@code null}.
   */
  public JSONField(final String name, final boolean value)
  {
    this(name, (value ? JSONBoolean.TRUE : JSONBoolean.FALSE));
  }



  /**
   * Creates a new JSON field with the specified name and a {@link JSONNumber}
   * value.
   *
   * @param name  The name for this field.  It must not be {@code null}.
   * @param value The value for this field.  It must not be {@code null}.
   */
  public JSONField(final String name, final long value)
  {
    this(name, new JSONNumber(value));
  }



  /**
   * Creates a new JSON field with the specified name and a {@link JSONNumber}
   * value.
   *
   * @param name  The name for this field.  It must not be {@code null}.
   * @param value The value for this field.  It must not be {@code null}.
   */
  public JSONField(final String name, final double value)
  {
    this(name, new JSONNumber(value));
  }



  /**
   * Creates a new JSON field with the specified name and a {@link JSONString}
   * value.
   *
   * @param name  The name for this field.  It must not be {@code null}.
   * @param value The value for this field.  It must not be {@code null}.
   */
  public JSONField(final String name, final String value)
  {
    this(name, new JSONString(value));
  }



  /**
   * Retrieves the name for this field.
   *
   * @return  The name for this field.
   */
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves the value for this field.
   *
   * @return  The value for this field.
   */
  public JSONValue getValue()
  {
    return value;
  }



  /**
   * Retrieves a hash code for this JSON field.
   *
   * @return  A hash code for this JSON field.
   */
  @Override()
  public int hashCode()
  {
    return name.hashCode() + value.hashCode();
  }



  /**
   * Indicates whether the provided object is considered equal to this JSON
   * field.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is a JSON field with the same
   *          name and an equivalent value, or {@code false} if not.
   */
  @Override()
  public boolean equals(final Object o)
  {
    if (o == this)
    {
      return true;
    }

    if (o instanceof JSONField)
    {
      final JSONField f = (JSONField) o;
      return (name.equals(f.name) && value.equals(f.value));
    }

    return false;
  }



  /**
   * Retrieves a string representation of this field.
   *
   * @return  A string representation of this field.
   */
  @Override()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this field to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(final StringBuilder buffer)
  {
    JSONString.encodeString(name, buffer);
    buffer.append(':');
    value.toString(buffer);
  }
}
