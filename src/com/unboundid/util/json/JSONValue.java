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

import com.unboundid.util.NotExtensible;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides the base class for data types that can be used as values
 * in JSON objects and as elements in JSON arrays.  The types of values defined
 * in the ECMA-404 specification are:
 * <UL>
 *   <LI>
 *     The {@code null} value, as implemented in the {@link JSONNull} class.
 *   </LI>
 *   <LI>
 *     The Boolean {@code true} and {@code false} values, as implemented in the
 *     {@link JSONBoolean} class.
 *   </LI>
 *   <LI>
 *     Numeric values, as implemented in the {@link JSONNumber} class.
 *   </LI>
 *   <LI>
 *     String values, as implemented in the {@link JSONString} class.
 *   </LI>
 *   <LI>
 *     Object values (consisting of zero or more name-value pairs), as
 *     implemented in the {@link JSONObject} class.
 *   </LI>
 *   <LI>
 *     Arrays of JSON values, as implemented in the {@link JSONArray} class.
 *   </LI>
 * </UL>
 */
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class JSONValue
       implements Serializable
{
  /**
   * A serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4446120225858980451L;



  /**
   * Retrieves a hash code for this JSON value.
   *
   * @return  The hash code for this JSON value.
   */
  public abstract int hashCode();



  /**
   * Indicates whether the provided object is equal to this JSON value.
   *
   * @param  o  The object to compare against this JSON value.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          JSON value, or {@code false} if not.
   */
  public abstract boolean equals(Object o);



  /**
   * Indicates whether this JSON value is considered equal to the provided JSON
   * value, subject to the specified constraints.  Note that not all constraints
   * will apply to all data types.
   *
   * @param  v                    The JSON value for which to make the
   *                              determination.  It must not be {@code null}.
   * @param  ignoreFieldNameCase  Indicates whether to ignore differences in the
   *                              capitalization of JSON field names.
   * @param  ignoreValueCase      Indicates whether to ignore differences in
   *                              the capitalization of JSON values that
   *                              represent strings.
   * @param  ignoreArrayOrder     Indicates whether to ignore differences in the
   *                              order of elements in JSON arrays.
   *
   * @return  {@code true} if this JSON value is considered equal to the
   *          provided JSON value (subject to the specified constraints), or
   *          {@code false} if not.
   */
  public abstract boolean equals(JSONValue v, boolean ignoreFieldNameCase,
                                 boolean ignoreValueCase,
                                 boolean ignoreArrayOrder);



  /**
   * Retrieves a string representation of this value as it should appear in a
   * JSON object, including any necessary quoting, escaping, etc.  If the object
   * containing this value was decoded from a string, then this method will use
   * the same string representation as in that original object.  Otherwise, the
   * string representation will be constructed.
   *
   * @return  A string representation of this value as it should appear in a
   *          JSON object.
   */
  public abstract String toString();



  /**
   * Appends a string representation of this value (as it should appear in a
   * JSON object, including any necessary quoting, escaping, etc.) to the
   * provided buffer.  If the object containing this value was decoded from a
   * string, then this method will use the same string representation as in that
   * original object.  Otherwise, the string representation will be constructed.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(StringBuilder buffer);



  /**
   * Retrieves a single-line string representation of this value as it should
   * appear in a JSON object, including any necessary quoting, escaping, etc.
   *
   * @return  A string representation of this value as it should appear in a
   *          JSON object.
   */
  public abstract String toSingleLineString();



  /**
   * Appends a single-line string representation of this value (as it should
   * appear in a JSON object, including any necessary quoting, escaping, etc.)
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toSingleLineString(StringBuilder buffer);



  /**
   * Retrieves a normalized string representation of this value.  All equivalent
   * JSON values must have equivalent normalized representations, even if there
   * are other legal representations for the value.
   *
   * @return  A normalized string representation of this value.
   */
  public abstract String toNormalizedString();



  /**
   * Appends a normalized string representation of this value to the provided
   * buffer.  All equivalent JSON values must have equivalent normalized
   * representations, even if there are other legal representations for the
   * value.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toNormalizedString(StringBuilder buffer);



  /**
   * Appends this value to the provided JSON buffer.  This will not include a
   * field name, so it should only be used for Boolean value elements in an
   * array.
   *
   * @param  buffer  The JSON buffer to which this value should be appended.
   */
  public abstract void appendToJSONBuffer(JSONBuffer buffer);



  /**
   * Appends a field with the given name and this value to the provided JSON
   * buffer.
   *
   * @param  fieldName  The name to use for the field.
   * @param  buffer     The JSON buffer to which this value should be appended.
   */
  public abstract void appendToJSONBuffer(String fieldName, JSONBuffer buffer);
}
