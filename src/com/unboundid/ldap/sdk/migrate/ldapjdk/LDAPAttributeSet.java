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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Iterator;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that contains a set of LDAP attribute
 * objects.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, arrays or collections of
 * {@link com.unboundid.ldap.sdk.Attribute} objects should be used instead.
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPAttributeSet
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4872457565092606186L;



  // The list of LDAPAttribute objects.
  @NotNull private final ArrayList<LDAPAttribute> attributes;



  /**
   * Creates a new LDAP attribute set with no attributes.
   */
  public LDAPAttributeSet()
  {
    attributes = new ArrayList<>(20);
  }



  /**
   * Creates a new LDAP attribute set with the provided attributes.
   *
   * @param  attrs  The set of attributes to include in the set.
   */
  public LDAPAttributeSet(@NotNull final LDAPAttribute[] attrs)
  {
    attributes = new ArrayList<>(Arrays.asList(attrs));
  }



  /**
   * Creates a new LDAP attribute set with the provided attributes.
   *
   * @param  attrs  The set of attributes to include in the set.
   */
  private LDAPAttributeSet(@NotNull final ArrayList<LDAPAttribute> attrs)
  {
    attributes = new ArrayList<>(attrs);
  }



  /**
   * Retrieves an enumeration of the attributes in this set.
   *
   * @return  An enumeration of the attributes in this set.
   */
  @NotNull()
  public Enumeration<LDAPAttribute> getAttributes()
  {
    return new IterableEnumeration<>(attributes);
  }



  /**
   * Retrieves a subset of the attributes in this attribute set which contain
   * the specified subtype.
   *
   * @param  subtype  The subtype for which to retrieve all of the attributes.
   *
   * @return  A new attribute set with all attributes from this set containing
   *          the specified subtype.
   */
  @NotNull()
  public LDAPAttributeSet getSubset(@NotNull final String subtype)
  {
    final ArrayList<LDAPAttribute> subset = new ArrayList<>(attributes.size());

    for (final LDAPAttribute a : attributes)
    {
      if (a.hasSubtype(subtype))
      {
        subset.add(a);
      }
    }

    return new LDAPAttributeSet(subset);
  }



  /**
   * Retrieves the attribute from this set whose name exactly matches the
   * provided name.
   *
   * @param  attrName  The name of the attribute to retrieve.
   *
   * @return  The requested attribute, or {@code null} if there is no such
   *          attribute in this set.
   */
  @Nullable()
  public LDAPAttribute getAttribute(@NotNull final String attrName)
  {
    for (final LDAPAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attrName))
      {
        return a;
      }
    }

    return null;
  }



  /**
   * Retrieves the attribute with the specified base name and the specified
   * language subtype.
   *
   * @param  attrName  The base name for the attribute to retrieve.
   * @param  lang      The language subtype to retrieve, or {@code null} if
   *                   there should not be a language subtype.
   *
   * @return  The attribute with the specified base name and language subtype,
   *          or {@code null} if there is no such attribute.
   */
  @Nullable()
  public LDAPAttribute getAttribute(@NotNull final String attrName,
                                    @Nullable final String lang)
  {
    if (lang == null)
    {
      return getAttribute(attrName);
    }

    final String lowerLang = StaticUtils.toLowerCase(lang);

    for (final LDAPAttribute a : attributes)
    {
      if (a.getBaseName().equalsIgnoreCase(attrName))
      {
        final String[] subtypes = a.getSubtypes();
        if (subtypes != null)
        {
          for (final String s : subtypes)
          {
            final String lowerOption = StaticUtils.toLowerCase(s);
            if (lowerOption.equals(lowerLang) ||
                lowerOption.startsWith(lang + '-'))
            {
              return a;
            }
          }
        }
      }
    }

    return null;
  }



  /**
   * Retrieves the attribute at the specified position in this attribute set.
   *
   * @param  index  The position of the attribute to retrieve.
   *
   * @return  The attribute at the specified position.
   *
   * @throws  IndexOutOfBoundsException  If the provided index invalid.
   */
  @NotNull()
  public LDAPAttribute elementAt(final int index)
         throws IndexOutOfBoundsException
  {
    return attributes.get(index);
  }



  /**
   * Adds the provided attribute to this attribute set.
   *
   * @param  attr  The attribute to be added to this set.
   */
  public void add(@NotNull final LDAPAttribute attr)
  {
    for (final LDAPAttribute a : attributes)
    {
      if (attr.getName().equalsIgnoreCase(a.getName()))
      {
        for (final byte[] value : attr.getByteValueArray())
        {
          a.addValue(value);
        }
        return;
      }
    }

    attributes.add(attr);
  }



  /**
   * Removes the attribute with the specified name.
   *
   * @param  name  The name of the attribute to remove.
   */
  public void remove(@NotNull final String name)
  {
    final Iterator<LDAPAttribute> iterator = attributes.iterator();
    while (iterator.hasNext())
    {
      final LDAPAttribute a = iterator.next();
      if (name.equalsIgnoreCase(a.getName()))
      {
        iterator.remove();
        return;
      }
    }
  }



  /**
   * Removes the attribute at the specified position in this attribute set.
   *
   * @param  index  The position of the attribute to remove.
   *
   * @throws  IndexOutOfBoundsException  If the provided index is invalid.
   */
  public void removeElementAt(final int index)
         throws IndexOutOfBoundsException
  {
    attributes.remove(index);
  }



  /**
   * Retrieves the number of attributes contained in this attribute set.
   *
   * @return  The number of attributes contained in this attribute set.
   */
  public int size()
  {
    return attributes.size();
  }



  /**
   * Creates a duplicate of this attribute set.
   *
   * @return  A duplicate of this attribute set.
   */
  @NotNull()
  public LDAPAttributeSet duplicate()
  {
    return new LDAPAttributeSet(attributes);
  }



  /**
   * Retrieves a string representation of this attribute set.
   *
   * @return  A string representation of this attribute set.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return attributes.toString();
  }
}
