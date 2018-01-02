/*
 * Copyright 2009-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;

import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a data structure for holding a compact attribute, which
 * will only contain the name and raw values for the attribute.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class CompactAttribute
      implements Serializable
{
  /**
   * The maximum number of cached names to maintain.
   */
  private static final int MAX_CACHED_NAMES = 1000;



  /**
   * A set of cached attribute names to conserve space.
   */
  private static final ConcurrentHashMap<String,String> cachedNames =
       new ConcurrentHashMap<String,String>(MAX_CACHED_NAMES);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 9056952830029621727L;



  // The set of values for this attribute.
  private final byte[][] values;

  // The name for this attribute.
  private final String name;



  /**
   * Creates a compact attribute from the provided attribute.
   *
   * @param  attribute  The attribute to use to create this compact attribute.
   */
  CompactAttribute(final Attribute attribute)
  {
    name = internName(attribute.getName());
    values = attribute.getValueByteArrays();
  }



  /**
   * Retrieves an internalized representation of the provided attribute name.
   * It will be a cached name, so that the same string can be used for the same
   * attribute name rather than multiple equivalent strings.
   *
   * @param  name  The name to be internalized.
   *
   * @return  The internalized representation of the provided name.
   */
  private static String internName(final String name)
  {
    String s = cachedNames.get(name);
    if (s == null)
    {
      if (cachedNames.size() >= MAX_CACHED_NAMES)
      {
        cachedNames.clear();
      }

      cachedNames.put(name, name);
      s = name;
    }

    return s;
  }



  /**
   * Retrieves the name for this attribute.
   *
   * @return  The name for this attribute.
   */
  String getName()
  {
    return name;
  }



  /**
   * Retrieves the set of values for this attribute as byte arrays..
   *
   * @return  The set of values for this attribute as byte arrays.
   */
  byte[][] getByteValues()
  {
    return values;
  }



  /**
   * Retrieves the set of values for this attribute as strings..
   *
   * @return  The set of values for this attribute as strings.
   */
  String[] getStringValues()
  {
    final String[] stringValues = new String[values.length];
    for (int i=0; i < values.length; i++)
    {
      stringValues[i] = toUTF8String(values[i]);
    }

    return stringValues;
  }



  /**
   * Retrieves an attribute that is equivalent to this compact attribute.
   *
   * @return  An attribute that is equivalent to this compact attribute.
   */
  Attribute toAttribute()
  {
    return new Attribute(name, values);
  }
}
