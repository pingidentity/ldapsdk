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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Enumeration;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents an LDAP entry.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link Entry} class should be
 * used instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public class LDAPEntry
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6285850560316222689L;



  // The DN for this entry.
  private final String dn;

  // The attribute set for this entry.
  private final LDAPAttributeSet attributeSet;



  /**
   * Creates a new LDAP entry with a zero-length DN and no attributes.
   */
  public LDAPEntry()
  {
    this("", new LDAPAttributeSet());
  }



  /**
   * Creates a new LDAP entry with the provided DN and no attributes.
   *
   * @param  distinguishedName  The DN to use for the entry.
   */
  public LDAPEntry(final String distinguishedName)
  {
    this(distinguishedName, new LDAPAttributeSet());
  }



  /**
   * Creates a new LDAP entry with the provided DN and attributes.
   *
   * @param  distinguishedName  The DN to use for the entry.
   * @param  attrs              The attributes to use for the entry.
   */
  public LDAPEntry(final String distinguishedName, final LDAPAttributeSet attrs)
  {
    dn = distinguishedName;

    if (attrs == null)
    {
      attributeSet = new LDAPAttributeSet();
    }
    else
    {
      attributeSet = attrs;
    }
  }



  /**
   * Creates a new LDAP entry from the provided {@link Entry} object.
   *
   * @param  entry  The entry to use to create this LDAP entry.
   */
  public LDAPEntry(final Entry entry)
  {
    dn = entry.getDN();

    attributeSet = new LDAPAttributeSet();
    for (final Attribute a : entry.getAttributes())
    {
      attributeSet.add(new LDAPAttribute(a));
    }
  }



  /**
   * Retrieves the distinguished name for this entry.
   *
   * @return  The distinguished name for this entry.
   */
  public String getDN()
  {
    return dn;
  }



  /**
   * Retrieves the attributes for this entry.
   *
   * @return  The attributes for this entry.
   */
  public LDAPAttributeSet getAttributeSet()
  {
    return attributeSet;
  }



  /**
   * Retrieves the set of attributes containing the specified subtype for this
   * entry.
   *
   * @param  subtype  The subtype for the attributes to retrieve.
   *
   * @return  The set of attributes containing the specified subtype.
   */
  public LDAPAttributeSet getAttributeSet(final String subtype)
  {
    return attributeSet.getSubset(subtype);
  }



  /**
   * Retrieves the attribute with the specified name.
   *
   * @param  attrName  The name of the attribute to retrieve.
   *
   * @return  The requested attribute, or {@code null} if there is none.
   */
  public LDAPAttribute getAttribute(final String attrName)
  {
    return attributeSet.getAttribute(attrName);
  }



  /**
   * Retrieves the attribute with the specified base name and language subtype.
   *
   * @param  attrName  The base name of the attribute to retrieve.
   * @param  lang      The language subtype for the attribute to retrieve.
   *
   * @return  The requested attribute, or {@code null} if there is none.
   */
  public LDAPAttribute getAttribute(final String attrName, final String lang)
  {
    return attributeSet.getAttribute(attrName, lang);
  }



  /**
   * Retrieves an {@link Entry} object that is the equivalent of this LDAP
   * entry.
   *
   * @return  The {@code Entry} object that is the equivalent of this LDAP
   *          entry.
   */
  public final Entry toEntry()
  {
    final ArrayList<Attribute> attrs =
         new ArrayList<Attribute>(attributeSet.size());
    final Enumeration<LDAPAttribute> attrEnum = attributeSet.getAttributes();
    while (attrEnum.hasMoreElements())
    {
      attrs.add(attrEnum.nextElement().toAttribute());
    }

    return new Entry(dn, attrs);
  }




  /**
   * Retrieves a string representation of this LDAP entry.
   *
   * @return  A string representation of this LDAP entry.
   */
  @Override()
  public String toString()
  {
    return toEntry().toString();
  }
}
