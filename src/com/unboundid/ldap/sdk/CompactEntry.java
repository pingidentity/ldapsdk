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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure that represents a compact version of an
 * entry.  This is basically the same as an {@code Entry} object, except that
 * it stores the information in a more compact form that requires less space in
 * memory.  This may be useful in applications that need to hold a large number
 * of entries in memory.  Note that performance of some methods in this class
 * may be significantly worse than the performance of the corresponding methods
 * in the {@code Entry} class.
 *
 * @see  Entry
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class CompactEntry
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 8067151651120794058L;



  // The set of attributes for this entry.
  @NotNull private final CompactAttribute[] attributes;

  // The hash code for this entry, if it has been calculated.
  private int hashCode;

  // The DN for this entry.
  @NotNull private final String dn;



  /**
   * Creates a new compact entry from the provided entry.
   *
   * @param  entry  The entry to use to create this compact entry.  It must not
   *                be {@code null}.
   */
  public CompactEntry(@NotNull final Entry entry)
  {
    Validator.ensureNotNull(entry);

    dn = entry.getDN();
    hashCode = -1;

    final Collection<Attribute> attrs = entry.getAttributes();
    attributes = new CompactAttribute[attrs.size()];
    final Iterator<Attribute> iterator = attrs.iterator();
    for (int i=0; i < attributes.length; i++)
    {
      attributes[i] = new CompactAttribute(iterator.next());
    }
  }



  /**
   * Retrieves the DN for this entry.
   *
   * @return  The DN for this entry.
   */
  @NotNull()
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the parsed DN for this entry.
   *
   * @return  The parsed DN for this entry.
   *
   * @throws  LDAPException  If the DN string cannot be parsed as a valid DN.
   */
  @NotNull()
  public DN getParsedDN()
         throws LDAPException
  {
    return new DN(dn);
  }



  /**
   * Retrieves the RDN for this entry.
   *
   * @return  The RDN for this entry, or {@code null} if the DN is the null DN.
   *
   * @throws  LDAPException  If the DN string cannot be parsed as a valid DN.
   */
  @Nullable()
  public RDN getRDN()
         throws LDAPException
  {
    return getParsedDN().getRDN();
  }



  /**
   * Retrieves the parent DN for this entry.
   *
   * @return  The parent DN for this entry, or {@code null} if there is no
   *          parent.
   *
   * @throws  LDAPException  If the DN string cannot be parsed as a valid DN.
   */
  @Nullable()
  public DN getParentDN()
         throws LDAPException
  {
    return getParsedDN().getParent();
  }



  /**
   * Retrieves the parent DN for this entry as a string.
   *
   * @return  The parent DN for this entry as a string, or {@code null} if there
   *          is no parent.
   *
   * @throws  LDAPException  If the DN string cannot be parsed as a valid DN.
   */
  @Nullable()
  public String getParentDNString()
         throws LDAPException
  {
    return getParsedDN().getParentString();
  }



  /**
   * Indicates whether this entry contains the specified attribute.
   *
   * @param  attributeName  The name of the attribute for which to make the
   *                        determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this entry contains the specified attribute, or
   *          {@code false} if not.
   */
  public boolean hasAttribute(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether this entry contains the specified attribute.  It will
   * only return {@code true} if this entry contains an attribute with the same
   * name and exact set of values.
   *
   * @param  attribute  The attribute for which to make the determination.  It
   *                    must not be {@code null}.
   *
   * @return  {@code true} if this entry contains the specified attribute, or
   *          {@code false}.
   */
  public boolean hasAttribute(@NotNull final Attribute attribute)
  {
    Validator.ensureNotNull(attribute);

    for (final CompactAttribute a : attributes)
    {
      if (a.toAttribute().equals(attribute))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether this entry contains an attribute with the given name and
   * value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeValue  The value for which to make the determination.  It
   *                         must not be {@code null}.
   *
   * @return  {@code true} if this entry contains an attribute with the
   *          specified name and value, or {@code false} if not.
   */
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final String attributeValue)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName) &&
          a.toAttribute().hasValue(attributeValue))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether this entry contains an attribute with the given name and
   * value.
   *
   * @param  attributeName   The name of the attribute for which to make the
   *                         determination.  It must not be {@code null}.
   * @param  attributeValue  The value for which to make the determination.  It
   *                         must not be {@code null}.
   *
   * @return  {@code true} if this entry contains an attribute with the
   *          specified name and value, or {@code false} if not.
   */
  public boolean hasAttributeValue(@NotNull final String attributeName,
                                   @NotNull final byte[] attributeValue)
  {
    Validator.ensureNotNull(attributeName, attributeValue);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName) &&
          a.toAttribute().hasValue(attributeValue))
      {
        return true;
      }
    }

    return false;
  }



  /**
   * Indicates whether this entry contains the specified object class.
   *
   * @param  objectClassName  The name of the object class for which to make the
   *                          determination.  It must not be {@code null}.
   *
   * @return  {@code true} if this entry contains the specified object class, or
   *          {@code false} if not.
   */
  public boolean hasObjectClass(@NotNull final String objectClassName)
  {
    return hasAttributeValue("objectClass", objectClassName);
  }



  /**
   * Retrieves the set of attributes contained in this entry.
   *
   * @return  The set of attributes contained in this entry.
   */
  @NotNull()
  public Collection<Attribute> getAttributes()
  {
    final ArrayList<Attribute> attrList =
         new ArrayList<>(attributes.length);
    for (final CompactAttribute a : attributes)
    {
      attrList.add(a.toAttribute());
    }

    return Collections.unmodifiableCollection(attrList);
  }



  /**
   * Retrieves the attribute with the specified name.
   *
   * @param  attributeName  The name of the attribute to retrieve.  It must not
   *                        be {@code null}.
   *
   * @return  The requested attribute from this entry, or {@code null} if the
   *          specified attribute is not present in this entry.
   */
  @Nullable()
  public Attribute getAttribute(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a.toAttribute();
      }
    }

    return null;
  }



  /**
   * Retrieves the list of attributes with the given base name and all of the
   * specified options.
   *
   * @param  baseName  The base name (without any options) for the attribute to
   *                   retrieve.  It must not be {@code null}.
   * @param  options   The set of options that should be included in the
   *                   attributes that are returned.  It may be empty or
   *                   {@code null} if all attributes with the specified base
   *                   name should be returned, regardless of the options that
   *                   they contain (if any).
   *
   * @return  The list of attributes with the given base name and all of the
   *          specified options.  It may be empty if there are no attributes
   *          with the specified base name and set of options.
   */
  @NotNull()
  public List<Attribute> getAttributesWithOptions(
                              @NotNull final String baseName,
                              @NotNull final Set<String> options)
  {
    return toEntry().getAttributesWithOptions(baseName, options);
  }



  /**
   * Retrieves the value for the specified attribute, if available.  If the
   * attribute has more than one value, then the first value will be returned.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The value for the specified attribute, or {@code null} if that
   *          attribute is not available.
   */
  @Nullable()
  public String getAttributeValue(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        final String[] values = a.getStringValues();
        if (values.length > 0)
        {
          return values[0];
        }
        else
        {
          return null;
        }
      }
    }

    return null;
  }



  /**
   * Retrieves the value for the specified attribute as a byte array, if
   * available.  If the attribute has more than one value, then the first value
   * will be returned.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The value for the specified attribute as a byte array, or
   *          {@code null} if that attribute is not available.
   */
  @Nullable()
  public byte[] getAttributeValueBytes(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        final byte[][] values = a.getByteValues();
        if (values.length > 0)
        {
          return values[0];
        }
        else
        {
          return null;
        }
      }
    }

    return null;
  }



  /**
   * Retrieves the value for the specified attribute as a Boolean, if available.
   * If the attribute has more than one value, then the first value will be
   * returned.  Values of "true", "t", "yes", "y", "on", and "1" will be
   * interpreted as {@code TRUE}.  Values of "false", "f", "no", "n", "off", and
   * "0" will be interpreted as {@code FALSE}.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The Boolean value parsed from the specified attribute, or
   *          {@code null} if that attribute is not available or the value
   *          cannot be parsed as a Boolean.
   */
  @Nullable()
  public Boolean getAttributeValueAsBoolean(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsBoolean();
    }
  }



  /**
   * Retrieves the value for the specified attribute as a Date, formatted using
   * the generalized time syntax, if available.  If the attribute has more than
   * one value, then the first value will be returned.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The Date value parsed from the specified attribute, or
   *           {@code null} if that attribute is not available or the value
   *           cannot be parsed as a Date.
   */
  @Nullable()
  public Date getAttributeValueAsDate(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsDate();
    }
  }



  /**
   * Retrieves the value for the specified attribute as a DN, if available.  If
   * the attribute has more than one value, then the first value will be
   * returned.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The Date value parsed from the specified attribute, or
   *           {@code null} if that attribute is not available or the value
   *           cannot be parsed as a DN.
   */
  @Nullable()
  public DN getAttributeValueAsDN(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsDN();
    }
  }



  /**
   * Retrieves the value for the specified attribute as an Integer, if
   * available.  If the attribute has more than one value, then the first value
   * will be returned.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The Integer value parsed from the specified attribute, or
   *          {@code null} if that attribute is not available or the value
   *          cannot be parsed as an Integer.
   */
  @Nullable()
  public Integer getAttributeValueAsInteger(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsInteger();
    }
  }



  /**
   * Retrieves the value for the specified attribute as a Long, if available.
   * If the attribute has more than one value, then the first value will be
   * returned.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        value.  It must not be {@code null}.
   *
   * @return  The Long value parsed from the specified attribute, or
   *          {@code null} if that attribute is not available or the value
   *          cannot be parsed as a Long.
   */
  @Nullable()
  public Long getAttributeValueAsLong(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    final Attribute a = getAttribute(attributeName);
    if (a == null)
    {
      return null;
    }
    else
    {
      return a.getValueAsLong();
    }
  }



  /**
   * Retrieves the set of values for the specified attribute, if available.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        values.  It must not be {@code null}.
   *
   * @return  The set of values for the specified attribute, or {@code null} if
   *          that attribute is not available.
   */
  @Nullable()
  public String[] getAttributeValues(@NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a.getStringValues();
      }
    }

    return null;
  }



  /**
   * Retrieves the set of values for the specified attribute as byte arrays, if
   * available.
   *
   * @param  attributeName  The name of the attribute for which to retrieve the
   *                        values.  It must not be {@code null}.
   *
   * @return  The set of values for the specified attribute as byte arrays, or
   *          {@code null} if that attribute is not available.
   */
  @Nullable()
  public byte[][] getAttributeValueByteArrays(
                       @NotNull final String attributeName)
  {
    Validator.ensureNotNull(attributeName);

    for (final CompactAttribute a : attributes)
    {
      if (a.getName().equalsIgnoreCase(attributeName))
      {
        return a.getByteValues();
      }
    }

    return null;
  }



  /**
   * Retrieves the "objectClass" attribute from the entry, if available.
   *
   * @return  The "objectClass" attribute from the entry, or {@code null} if
   *          that attribute not available.
   */
  @Nullable()
  public Attribute getObjectClassAttribute()
  {
    return getAttribute("objectClass");
  }



  /**
   * Retrieves the values of the "objectClass" attribute from the entry, if
   * available.
   *
   * @return  The values of the "objectClass" attribute from the entry, or
   *          {@code null} if that attribute is not available.
   */
  @Nullable()
  public String[] getObjectClassValues()
  {
    return getAttributeValues("objectClass");
  }



  /**
   * Converts this compact entry to a full entry.
   *
   * @return  The entry created from this compact entry.
   */
  @NotNull()
  public Entry toEntry()
  {
    final Attribute[] attrs = new Attribute[attributes.length];
    for (int i=0; i < attributes.length; i++)
    {
      attrs[i] = attributes[i].toAttribute();
    }

    return new Entry(dn, attrs);
  }



  /**
   * Generates a hash code for this entry.
   *
   * @return  The generated hash code for this entry.
   */
  @Override()
  public int hashCode()
  {
    if (hashCode == -1)
    {
      hashCode = toEntry().hashCode();
    }

    return hashCode;
  }



  /**
   * Indicates whether the provided object is equal to this entry.  The provided
   * object will only be considered equal to this entry if it is an entry with
   * the same DN and set of attributes.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is considered equal to this
   *          entry, or {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if ((o == null) || (! (o instanceof CompactEntry)))
    {
      return false;
    }

    return toEntry().equals(((CompactEntry) o).toEntry());
  }



  /**
   * Retrieves an LDIF representation of this entry, with each attribute value
   * on a separate line.  Long lines will not be wrapped.
   *
   * @return  An LDIF representation of this entry.
   */
  @NotNull()
  public String[] toLDIF()
  {
    return toLDIF(0);
  }



  /**
   * Retrieves an LDIF representation of this entry, with each attribute value
   * on a separate line.  Long lines will be wrapped at the specified column.
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.  A
   *                     value less than or equal to two indicates that no
   *                     wrapping should be performed.
   *
   * @return  An LDIF representation of this entry.
   */
  @NotNull()
  public String[] toLDIF(final int wrapColumn)
  {
    return toEntry().toLDIF(wrapColumn);
  }



  /**
   * Appends an LDIF representation of this entry to the provided buffer.  Long
   * lines will not be wrapped.
   *
   * @param  buffer The buffer to which the LDIF representation of this entry
   *                should be written.
   */
  public void toLDIF(@NotNull final ByteStringBuffer buffer)
  {
    toLDIF(buffer, 0);
  }



  /**
   * Appends an LDIF representation of this entry to the provided buffer.
   *
   * @param  buffer      The buffer to which the LDIF representation of this
   *                     entry should be written.
   * @param  wrapColumn  The column at which long lines should be wrapped.  A
   *                     value less than or equal to two indicates that no
   *                     wrapping should be performed.
   */
  public void toLDIF(@NotNull final ByteStringBuffer buffer,
                     final int wrapColumn)
  {
    toEntry().toLDIF(buffer, wrapColumn);
  }



  /**
   * Retrieves an LDIF-formatted string representation of this entry.  No
   * wrapping will be performed, and no extra blank lines will be added.
   *
   * @return  An LDIF-formatted string representation of this entry.
   */
  @NotNull()
  public String toLDIFString()
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, 0);
    return buffer.toString();
  }



  /**
   * Retrieves an LDIF-formatted string representation of this entry.  No
   * extra blank lines will be added.
   *
   * @param  wrapColumn  The column at which long lines should be wrapped.  A
   *                     value less than or equal to two indicates that no
   *                     wrapping should be performed.
   *
   * @return  An LDIF-formatted string representation of this entry.
   */
  @NotNull()
  public String toLDIFString(final int wrapColumn)
  {
    final StringBuilder buffer = new StringBuilder();
    toLDIFString(buffer, wrapColumn);
    return buffer.toString();
  }



  /**
   * Appends an LDIF-formatted string representation of this entry to the
   * provided buffer.  No wrapping will be performed, and no extra blank lines
   * will be added.
   *
   * @param  buffer  The buffer to which to append the LDIF representation of
   *                 this entry.
   */
  public void toLDIFString(@NotNull final StringBuilder buffer)
  {
    toLDIFString(buffer, 0);
  }



  /**
   * Appends an LDIF-formatted string representation of this entry to the
   * provided buffer.  No extra blank lines will be added.
   *
   * @param  buffer      The buffer to which to append the LDIF representation
   *                     of this entry.
   * @param  wrapColumn  The column at which long lines should be wrapped.  A
   *                     value less than or equal to two indicates that no
   *                     wrapping should be performed.
   */
  public void toLDIFString(@NotNull final StringBuilder buffer,
                           final int wrapColumn)
  {
    toEntry().toLDIFString(buffer, wrapColumn);
  }



  /**
   * Retrieves a string representation of this entry.
   *
   * @return  A string representation of this entry.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this entry to the provided buffer.
   *
   * @param  buffer  The buffer to which to append the string representation of
   *                 this entry.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("Entry(dn='");
    buffer.append(dn);
    buffer.append("', attributes={");

    for (int i=0; i < attributes.length; i++)
    {
      if (i > 0)
      {
        buffer.append(", ");
      }
      attributes[i].toAttribute().toString(buffer);
    }

    buffer.append("})");
  }
}
