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
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that represents an LDAP URL.
 * <BR><BR>
 * This class is primarily intended to be used in the process of updating
 * applications which use the Netscape Directory SDK for Java to switch to or
 * coexist with the UnboundID LDAP SDK for Java.  For applications not written
 * using the Netscape Directory SDK for Java, the {@link LDAPURL} class should
 * be used instead.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class LDAPUrl
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1716384037873600695L;



  // The LDAP URL for this object.
  @NotNull private final LDAPURL ldapURL;



  /**
   * Creates a new {@code LDAPUrl} object from the provided string
   * representation.
   *
   * @param  url  The string representation of the LDAP URL to create.
   *
   * @throws  MalformedURLException  If the provided string cannot be parsed as
   *                                 a valid LDAP URL.
   */
  public LDAPUrl(@NotNull final String url)
         throws MalformedURLException
  {
    try
    {
      ldapURL = new LDAPURL(url);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new MalformedURLException(le.getMessage());
    }
  }



  /**
   * Creates a new {@code LDAPUrl} object with the provided information.
   *
   * @param  host  The address of the directory server, or {@code null} if there
   *               should not be an address.
   * @param  port  The port of the directory server.
   * @param  dn    The DN for the URL.
   *
   * @throws  RuntimeException  If any of the provided information cannot be
   *                            used to create a valid LDAP URL.
   */
  public LDAPUrl(@Nullable final String host, final int port,
                 @Nullable final String dn)
         throws RuntimeException
  {
    try
    {
      final DN dnObject = (dn == null) ? null : new DN(dn);
      ldapURL = new LDAPURL("ldap", host, port, dnObject, null, null, null);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new RuntimeException(e);
    }
  }



  /**
   * Creates a new {@code LDAPUrl} object with the provided information.
   *
   * @param  host        The address of the directory server, or {@code null} if
   *                     there should not be an address.
   * @param  port        The port of the directory server.
   * @param  dn          The DN for the URL.
   * @param  attributes  The set of requested attributes.
   * @param  scope       The scope to use for the LDAP URL.
   * @param  filter      The filter to use for the LDAP URL.
   *
   * @throws  RuntimeException  If any of the provided information cannot be
   *                            used to create a valid LDAP URL.
   */
  public LDAPUrl(@Nullable final String host, final int port,
                 @Nullable final String dn,
                 @Nullable final String[] attributes, final int scope,
                 @NotNull final String filter)
         throws RuntimeException
  {
    try
    {
      final DN          dnObject     = (dn == null) ? null : new DN(dn);
      final SearchScope scopeObject  = SearchScope.valueOf(scope);
      final Filter      filterObject = Filter.create(filter);
      ldapURL = new LDAPURL("ldap", host, port, dnObject, attributes,
                            scopeObject, filterObject);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new RuntimeException(e);
    }
  }



  /**
   * Creates a new {@code LDAPUrl} object with the provided information.
   *
   * @param  host        The address of the directory server, or {@code null} if
   *                     there should not be an address.
   * @param  port        The port of the directory server.
   * @param  dn          The DN for the URL.
   * @param  attributes  The set of requested attributes.
   * @param  scope       The scope to use for the LDAP URL.
   * @param  filter      The filter to use for the LDAP URL.
   *
   * @throws  RuntimeException  If any of the provided information cannot be
   *                            used to create a valid LDAP URL.
   */
  public LDAPUrl(@Nullable final String host, final int port,
                 @Nullable final String dn,
                 @Nullable final Enumeration<String> attributes,
                 final int scope, @NotNull final String filter)
         throws RuntimeException
  {
    try
    {
      final DN          dnObject     = (dn == null) ? null : new DN(dn);
      final SearchScope scopeObject  = SearchScope.valueOf(scope);
      final Filter      filterObject = Filter.create(filter);

      final String[] attrs;
      if (attributes == null)
      {
        attrs = null;
      }
      else
      {
        final ArrayList<String> attrList = new ArrayList<>(10);
        while (attributes.hasMoreElements())
        {
          attrList.add(attributes.nextElement());
        }
        attrs = new String[attrList.size()];
        attrList.toArray(attrs);
      }

      ldapURL = new LDAPURL("ldap", host, port, dnObject, attrs, scopeObject,
                            filterObject);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new RuntimeException(e);
    }
  }



  /**
   * Creates a new {@code LDAPUrl} object from the provided {@link LDAPURL}
   * object.
   *
   * @param  ldapURL  The {@code LDAPURL} object to use to create this LDAP URL.
   */
  public LDAPUrl(@NotNull final LDAPURL ldapURL)
  {
    this.ldapURL = ldapURL;
  }



  /**
   * Retrieves the address for this LDAP URL, if available.
   *
   * @return  The address for this LDAP URL, or {@code null} if it is not
   *          available.
   */
  @Nullable()
  public String getHost()
  {
    return ldapURL.getHost();
  }



  /**
   * Retrieves the port number for this LDAP URL.
   *
   * @return  The port number for this LDAP URL.
   */
  public int getPort()
  {
    return ldapURL.getPort();
  }



  /**
   * Retrieves the DN for this LDAP URL, if available.
   *
   * @return  The DN for this LDAP URL, or {@code null} if it is not available.
   */
  @Nullable()
  public String getDN()
  {
    if (ldapURL.baseDNProvided())
    {
      return ldapURL.getBaseDN().toString();
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves an enumeration of the names of the requested attributes for this
   * LDAP URL, if available.
   *
   * @return  An enumeration of the names of the requested attributes for this
   *          LDAP URL, or {@code null} if there are none.
   */
  @Nullable()
  public Enumeration<String> getAttributes()
  {
    final String[] attributes = ldapURL.getAttributes();
    if (attributes.length == 0)
    {
      return null;
    }
    else
    {
      return new IterableEnumeration<>(Arrays.asList(attributes));
    }
  }



  /**
   * Retrieves an array of the names of the requested attributes for this LDAP
   * URL, if available.
   *
   * @return  An array of the names of the requested attributes for this LDAP
   *          URL, or {@code null} if there are none.
   */
  @Nullable()
  public String[] getAttributeArray()
  {
    final String[] attributes = ldapURL.getAttributes();
    if (attributes.length == 0)
    {
      return null;
    }
    else
    {
      return attributes;
    }
  }



  /**
   * Retrieves the search scope for the LDAP URL.
   *
   * @return  The search scope for the LDAP URL.
   */
  public int getScope()
  {
    return ldapURL.getScope().intValue();
  }



  /**
   * Retrieves the filter for this LDAP URL.
   *
   * @return  The filter for this LDAP URL.
   */
  @NotNull()
  public String getFilter()
  {
    return ldapURL.getFilter().toString();
  }



  /**
   * Retrieves a hash code for this LDAP URL.
   *
   * @return  A hash code for this LDAP URL.
   */
  @Override()
  public int hashCode()
  {
    return ldapURL.hashCode();
  }



  /**
   * Indicates whether the provided object is equal to this LDAP URL.
   *
   * @param  o  The object for which to make the determination.
   *
   * @return  {@code true} if the provided object is equal to this LDAP URL, or
   *          {@code false} if not.
   */
  @Override()
  public boolean equals(@Nullable final Object o)
  {
    if (o == null)
    {
      return false;
    }

    if (o instanceof LDAPUrl)
    {
      return ldapURL.equals(((LDAPUrl) o).ldapURL);
    }

    return false;
  }



  /**
   * Retrieves a string representation of this LDAP URL.
   *
   * @return  A string representation of this LDAP URL.
   */
  @NotNull()
  public String getUrl()
  {
    return ldapURL.toString();
  }



  /**
   * Retrieves an {@link LDAPURL} object that is the equivalent of this LDAP
   * URL.
   *
   * @return  An {@code LDAPURL} object that is the equivalent of this LDAP URL.
   */
  @NotNull()
  public final LDAPURL toLDAPURL()
  {
    return ldapURL;
  }



  /**
   * Retrieves a string representation of this LDAP URL.
   *
   * @return  A string representation of this LDAP URL.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return ldapURL.toString();
  }
}
