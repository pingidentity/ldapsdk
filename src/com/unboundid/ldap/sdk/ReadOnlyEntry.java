/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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



import java.util.Collection;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an {@link Entry} subclass in which the contents of the
 * entry cannot be modified.  Any attempt to call a method which could be used
 * to alter the contents of the entry will result in an
 * {@link UnsupportedOperationException}.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class ReadOnlyEntry
       extends Entry
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6482574870325012756L;



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final String dn, final Attribute... attributes)
  {
    this(dn, null, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  schema      The schema to use for operations involving this entry.
   *                     It may be {@code null} if no schema is available.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final String dn, final Schema schema,
                       final Attribute... attributes)
  {
    super(dn, schema, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final DN dn, final Attribute... attributes)
  {
    this(dn, null, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  schema      The schema to use for operations involving this entry.
   *                     It may be {@code null} if no schema is available.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final DN dn, final Schema schema,
                       final Attribute... attributes)
  {
    super(dn, schema, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final String dn, final Collection<Attribute> attributes)
  {
    this(dn, null, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  schema      The schema to use for operations involving this entry.
   *                     It may be {@code null} if no schema is available.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final String dn, final Schema schema,
                       final Collection<Attribute> attributes)
  {
    super(dn, schema, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final DN dn, final Collection<Attribute> attributes)
  {
    this(dn, null, attributes);
  }



  /**
   * Creates a new read-only entry with the provided DN and set of attributes.
   *
   * @param  dn          The DN for this entry.  It must not be {@code null}.
   * @param  schema      The schema to use for operations involving this entry.
   *                     It may be {@code null} if no schema is available.
   * @param  attributes  The set of attributes for this entry.  It must not be
   *                     {@code null}.
   */
  public ReadOnlyEntry(final DN dn, final Schema schema,
                       final Collection<Attribute> attributes)
  {
    super(dn, schema, attributes);
  }



  /**
   * Creates a new read-only entry from the provided {@link Entry}.
   *
   * @param  entry  The entry to use to create this read-only entry.
   */
  public ReadOnlyEntry(final Entry entry)
  {
    super(entry);
  }



  /**
   * Creates a new read-only entry from the provided LDIF representation.
   *
   * @param  ldifLines  The set of lines that comprise an LDIF representation
   *                    of the entry.  It must not be {@code null} or empty.
   *
   * @throws  LDIFException  If the provided lines cannot be decoded as an entry
   *                         in LDIF format.
   */
  public ReadOnlyEntry(final String... ldifLines)
         throws LDIFException
  {
    this(null, ldifLines);
  }



  /**
   * Creates a new read-only entry from the provided LDIF representation.
   *
   * @param  schema     The schema to use for operations involving this entry.
   *                    It may be {@code null} if no schema is available.
   * @param  ldifLines  The set of lines that comprise an LDIF representation
   *                    of the entry.  It must not be {@code null} or empty.
   *
   * @throws  LDIFException  If the provided lines cannot be decoded as an entry
   *                         in LDIF format.
   */
  public ReadOnlyEntry(final Schema schema, final String... ldifLines)
         throws LDIFException
  {
    super(schema, ldifLines);
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  dn  The DN for this entry.  It must not be {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setDN(final String dn)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  dn  The DN for this entry.  It must not be {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setDN(final DN dn)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attribute  The attribute to be added.  It must not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean addAttribute(final Attribute attribute)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName   The name for the attribute to be added.  It must
   *                         not be {@code null}.
   * @param  attributeValue  The value for the attribute to be added.  It must
   *                         not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean addAttribute(final String attributeName,
                              final String attributeValue)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName   The name for the attribute to be added.  It must
   *                         not be {@code null}.
   * @param  attributeValue  The value for the attribute to be added.  It must
   *                         not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean addAttribute(final String attributeName,
                              final byte[] attributeValue)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName    The name for the attribute to be added.  It must
   *                          not be {@code null}.
   * @param  attributeValues  The set of values for the attribute to be added.
   *                          It must not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean addAttribute(final String attributeName,
                              final String... attributeValues)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName    The name for the attribute to be added.  It must
   *                          not be {@code null}.
   * @param  attributeValues  The set of values for the attribute to be added.
   *                          It must not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean addAttribute(final String attributeName,
                              final byte[]... attributeValues)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName  The name of the attribute to remove.  It must not be
   *                        {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean removeAttribute(final String attributeName)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName   The name of the attribute to remove.  It must not
   *                         be {@code null}.
   * @param  attributeValue  The value of the attribute to remove.  It must not
   *                         be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean removeAttributeValue(final String attributeName,
                                      final String attributeValue)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName   The name of the attribute to remove.  It must not
   *                         be {@code null}.
   * @param  attributeValue  The value of the attribute to remove.  It must not
   *                         be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean removeAttributeValue(final String attributeName,
                                      final byte[] attributeValue)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName    The name of the attribute to remove.  It must not
   *                          be {@code null}.
   * @param  attributeValues  The values of the attribute to remove.  It must
   *                          not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean removeAttributeValues(final String attributeName,
                                       final String... attributeValues)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName    The name of the attribute to remove.  It must not
   *                          be {@code null}.
   * @param  attributeValues  The values of the attribute to remove.  It must
   *                          not be {@code null}.
   *
   * @return  This method will never return successfully.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public boolean removeAttributeValues(final String attributeName,
                                       final byte[]... attributeValues)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attribute  The attribute to be included in this entry.  It must not
   *                    be {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setAttribute(final Attribute attribute)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName   The name to use for the attribute.  It must not be
   *                         {@code null}.
   * @param  attributeValue  The value to use for the attribute.  It must not be
   *                         {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setAttribute(final String attributeName,
                           final String attributeValue)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName   The name to use for the attribute.  It must not be
   *                         {@code null}.
   * @param  attributeValue  The value to use for the attribute.  It must not be
   *                         {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setAttribute(final String attributeName,
                           final byte[] attributeValue)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName    The name to use for the attribute.  It must not be
   *                          {@code null}.
   * @param  attributeValues  The set of values to use for the attribute.  It
   *                          must not be {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setAttribute(final String attributeName,
                           final String... attributeValues)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }



  /**
   * Throws an {@code UnsupportedOperationException} to indicate that this is a
   * read-only entry.
   *
   * @param  attributeName    The name to use for the attribute.  It must not be
   *                          {@code null}.
   * @param  attributeValues  The set of values to use for the attribute.  It
   *                          must not be {@code null}.
   *
   * @throws  UnsupportedOperationException  To indicate that this is a
   *                                         read-only entry.
   */
  @Override()
  public void setAttribute(final String attributeName,
                           final byte[]... attributeValues)
         throws UnsupportedOperationException
  {
    throw new UnsupportedOperationException();
  }
}
