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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Set;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about an LDAP
 * attribute, including an attribute description (a base name or OID and
 * optional set of options) and zero or more values.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link Attribute} class should
 * be used instead.
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPAttribute
       implements Serializable
{
  /**
   * The serial version UID for this serializable attribute.
   */
  private static final long serialVersionUID = 839217229050750570L;



  // The Attribute object wrapped by this LDAPAttribute.
  @NotNull private Attribute attribute;



  /**
   * Creates a new LDAP attribute from the provided {@link Attribute} object.
   *
   * @param  attr  The LDAP attribute to use to create this attribute.
   */
  public LDAPAttribute(@NotNull final Attribute attr)
  {
    attribute = attr;
  }



  /**
   * Creates a new LDAP attribute that is a duplicate of the provided attribute.
   *
   * @param  attr  The LDAP attribute to use to create this attribute.
   */
  public LDAPAttribute(@NotNull final LDAPAttribute attr)
  {
    attribute = attr.attribute;
  }



  /**
   * Creates a new LDAP attribute with the specified name and no values.
   *
   * @param  attrName  The name for this attribute.
   */
  public LDAPAttribute(@NotNull final String attrName)
  {
    attribute = new Attribute(attrName);
  }



  /**
   * Creates a new LDAP attribute with the specified name and value.
   *
   * @param  attrName   The name for this attribute.
   * @param  attrBytes  The value for this attribute.
   */
  public LDAPAttribute(@NotNull final String attrName,
                       @NotNull final byte[] attrBytes)
  {
    attribute = new Attribute(attrName, attrBytes);
  }



  /**
   * Creates a new LDAP attribute with the specified name and value.
   *
   * @param  attrName    The name for this attribute.
   * @param  attrString  The value for this attribute.
   */
  public LDAPAttribute(@NotNull final String attrName,
                       @NotNull final String attrString)
  {
    attribute = new Attribute(attrName, attrString);
  }



  /**
   * Creates a new LDAP attribute with the specified name and values.
   *
   * @param  attrName     The name for this attribute.
   * @param  attrStrings  The values for this attribute.
   */
  public LDAPAttribute(@NotNull final String attrName,
                       @NotNull final String[] attrStrings)
  {
    attribute = new Attribute(attrName, attrStrings);
  }



  /**
   * Retrieves the name for this attribute.
   *
   * @return  The name for this attribute.
   */
  @NotNull()
  public String getName()
  {
    return attribute.getName();
  }



  /**
   * Retrieves the base name for this attribute, without any options.
   *
   * @return  The base name for this attribute.
   */
  @NotNull()
  public String getBaseName()
  {
    return attribute.getBaseName();
  }



  /**
   * Retrieves the base name for the attribute with the provided name.
   *
   * @param  attrName  The attribute name for which to retrieve the base name.
   *
   * @return  The base name for the attribute with the provided name.
   */
  @NotNull()
  public static String getBaseName(@NotNull final String attrName)
  {
    return Attribute.getBaseName(attrName);
  }



  /**
   * Retrieves the subtypes (i.e., attribute options) contained in the name for
   * this attribute.
   *
   * @return  The subtypes contained in the name for this attribute, or
   *          {@code null} if there are none.
   */
  @Nullable()
  public String[] getSubtypes()
  {
    final Set<String> optionSet = attribute.getOptions();
    if (optionSet.isEmpty())
    {
      return null;
    }

    final String[] options = new String[optionSet.size()];
    return optionSet.toArray(options);
  }



  /**
   * Retrieves the subtypes (i.e., attribute options) contained in the provided
   * attribute name.
   *
   * @param  attrName  The attribute name from which to extract the subtypes.
   *
   * @return  The subtypes contained in the provided attribute name, or
   *          {@code null} if there are none.
   */
  @Nullable()
  public static String[] getSubtypes(@NotNull final String attrName)
  {
    return new LDAPAttribute(attrName).getSubtypes();
  }



  /**
   * Retrieves the language subtype (i.e., the attribute option which begins
   * with "lang-") for this attribute, if present.
   *
   * @return  The language subtype for this attribute, or {@code null} if there
   *          is none.
   */
  @Nullable()
  public String getLangSubtype()
  {
    for (final String s : attribute.getOptions())
    {
      final String lowerName = StaticUtils.toLowerCase(s);
      if (lowerName.startsWith("lang-"))
      {
        return s;
      }
    }

    return null;
  }



  /**
   * Indicates whether this attribute contains the specified subtype.
   *
   * @param  subtype  The subtype for which to make the determination.
   *
   * @return  {@code true} if this option has the specified subtype, or
   *          {@code false} if not.
   */
  public boolean hasSubtype(@NotNull final String subtype)
  {
    return attribute.hasOption(subtype);
  }



  /**
   * Indicates whether this attribute contains all of the specified subtypes.
   *
   * @param  subtypes  The subtypes for which to make the determination.
   *
   * @return  {@code true} if this option has all of the specified subtypes, or
   *          {@code false} if not.
   */
  public boolean hasSubtypes(@NotNull final String[] subtypes)
  {
    for (final String s : subtypes)
    {
      if (! attribute.hasOption(s))
      {
        return false;
      }
    }

    return true;
  }



  /**
   * Retrieves an enumeration over the string values for this attribute.
   *
   * @return  An enumeration over the string values for this attribute.
   */
  @NotNull()
  public Enumeration<String> getStringValues()
  {
    return new IterableEnumeration<>(Arrays.asList(attribute.getValues()));
  }



  /**
   * Retrieves an array of the values for this attribute.
   *
   * @return  An array of the values for this attribute.
   */
  @NotNull()
  public String[] getStringValueArray()
  {
    return attribute.getValues();
  }



  /**
   * Retrieves an enumeration over the binary values for this attribute.
   *
   * @return  An enumeration over the binary values for this attribute.
   */
  @NotNull()
  public Enumeration<byte[]> getByteValues()
  {
    return new IterableEnumeration<>(
         Arrays.asList(attribute.getValueByteArrays()));
  }



  /**
   * Retrieves an array of the values for this attribute.
   *
   * @return  An array of the values for this attribute.
   */
  @NotNull()
  public byte[][] getByteValueArray()
  {
    return attribute.getValueByteArrays();
  }



  /**
   * Adds the provided value to the set of values for this attribute.
   *
   * @param  attrString  The value to add to this attribute.
   */
  public void addValue(@NotNull final String attrString)
  {
    attribute = Attribute.mergeAttributes(attribute,
         new Attribute(attribute.getName(), attrString));
  }



  /**
   * Adds the provided value to the set of values for this attribute.
   *
   * @param  attrBytes  The value to add to this attribute.
   */
  public void addValue(@NotNull final byte[] attrBytes)
  {
    attribute = Attribute.mergeAttributes(attribute,
         new Attribute(attribute.getName(), attrBytes));
  }



  /**
   * Removes the provided value from this attribute.
   *
   * @param  attrValue  The value to remove.
   */
  public void removeValue(@NotNull final String attrValue)
  {
    attribute = Attribute.removeValues(attribute,
         new Attribute(attribute.getName(), attrValue));
  }



  /**
   * Removes the provided value from this attribute.
   *
   * @param  attrValue  The value to remove.
   */
  public void removeValue(@NotNull final byte[] attrValue)
  {
    attribute = Attribute.removeValues(attribute,
         new Attribute(attribute.getName(), attrValue));
  }



  /**
   * Retrieves the number of values for this attribute.
   *
   * @return  The number of values for this attribute.
   */
  public int size()
  {
    return attribute.size();
  }



  /**
   * Converts this LDAP attribute to an {@link Attribute} object.
   *
   * @return  The {@code Attribute} object which corresponds to this LDAP
   *          attribute.
   */
  @NotNull()
  public final Attribute toAttribute()
  {
    return attribute;
  }



  /**
   * Retrieves a string representation of this LDAP attribute.
   *
   * @return  A string representation of this LDAP attribute.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return attribute.toString();
  }
}
