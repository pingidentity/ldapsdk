/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPInterface;
import com.unboundid.ldap.sdk.LDAPRequest;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchResultReference;
import com.unboundid.ldap.sdk.SearchScope;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a number of convenience methods that can be used to help
 * write test cases for directory-enabled applications.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPTestUtils
{
  /**
   * Ensure that this utility class cannot be instantiated.
   */
  private LDAPTestUtils()
  {
    // No implementation required.
  }



  /**
   * Generates a domain entry with the provided information.  It will include
   * the top and domain object classes and will use dc as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the domain, which will be used
   *                               as the value of the "dc" attribute.  It must
   *                               not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateDomainEntry(@NotNull final String name,
                           @Nullable final String parentDN,
                           @Nullable final Attribute... additionalAttributes)
  {
    return generateDomainEntry(name, parentDN,
         StaticUtils.toList(additionalAttributes));
  }



  /**
   * Generates a domain entry with the provided information.  It will include
   * the top and domain object classes and will use dc as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the domain, which will be used
   *                               as the value of the "dc" attribute.  It must
   *                               not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateDomainEntry(@NotNull final String name,
              @Nullable final String parentDN,
              @Nullable final Collection<Attribute> additionalAttributes)
  {
    return generateEntry("dc", name, parentDN, new String[] { "top", "domain" },
         additionalAttributes);
  }



  /**
   * Generates an organization entry with the provided information.  It will
   * include the top and organization object classes and will use o as the RDN
   * attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organization, which will be
   *                               used as the value of the "o" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateOrgEntry(@NotNull final String name,
                           @Nullable final String parentDN,
                           @Nullable final Attribute... additionalAttributes)
  {
    return generateOrgEntry(name, parentDN,
         StaticUtils.toList(additionalAttributes));
  }



  /**
   * Generates an organization entry with the provided information.  It will
   * include the top and organization object classes and will use o as the RDN
   * attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organization, which will be
   *                               used as the value of the "o" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateOrgEntry(@NotNull final String name,
              @Nullable final String parentDN,
              @Nullable final Collection<Attribute> additionalAttributes)
  {
    return generateEntry("o", name, parentDN,
         new String[] { "top", "organization" },
         additionalAttributes);
  }



  /**
   * Generates an organizationalUnit entry with the provided information.  It
   * will include the top and organizationalUnit object classes and will use ou
   * as the RDN attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organizationalUnit, which
   *                               will be used as the value of the "ou"
   *                               attribute.  It must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateOrgUnitEntry(@NotNull final String name,
                           @Nullable final String parentDN,
                           @Nullable final Attribute... additionalAttributes)
  {
    return generateOrgUnitEntry(name, parentDN,
         StaticUtils.toList(additionalAttributes));
  }



  /**
   * Generates an organizationalUnit entry with the provided information.  It
   * will include the top and organizationalUnit object classes and will use ou
   * as the RDN attribute.  It may optionally include additional attributes.
   *
   * @param  name                  The name for the organizationalUnit, which
   *                               will be used as the value of the "ou"
   *                               attribute.  It must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateOrgUnitEntry(@NotNull final String name,
              @Nullable final String parentDN,
              @Nullable final Collection<Attribute> additionalAttributes)
  {
    return generateEntry("ou", name, parentDN,
         new String[] { "top", "organizationalUnit" },
         additionalAttributes);
  }



  /**
   * Generates a country entry with the provided information.  It will include
   * the top and country object classes and will use c as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the country (typically a
   *                               two-character country code), which will be
   *                               used as the value of the "c" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateCountryEntry(@NotNull final String name,
                           @Nullable final String parentDN,
                           @Nullable final Attribute... additionalAttributes)
  {
    return generateCountryEntry(name, parentDN,
         StaticUtils.toList(additionalAttributes));
  }



  /**
   * Generates a country entry with the provided information.  It will include
   * the top and country object classes and will use c as the RDN attribute.  It
   * may optionally include additional attributes.
   *
   * @param  name                  The name for the country (typically a
   *                               two-character country code), which will be
   *                               used as the value of the "c" attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateCountryEntry(@NotNull final String name,
              @Nullable final String parentDN,
              @Nullable final Collection<Attribute> additionalAttributes)
  {
    return generateEntry("c", name, parentDN,
         new String[] { "top", "country" },
         additionalAttributes);
  }



  /**
   * Generates a user entry with the provided information.  It will include the
   * top, person, organizationalPerson, and inetOrgPerson object classes, will
   * use uid as the RDN attribute, and will have givenName, sn, and cn
   * attributes.  It may optionally include additional attributes.
   *
   * @param  uid                   The value to use for the "uid: attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  firstName             The first name for the user.  It must not be
   *                               {@code null}.
   * @param  lastName              The last name for the user.  It must not be
   *                               {@code null}.
   * @param  password              The password for the user.  It may be
   *                               {@code null} if the user should not have a
   *                               password.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateUserEntry(@NotNull final String uid,
              @Nullable final String parentDN, @NotNull final String firstName,
              @NotNull final String lastName, @Nullable final String password,
              @Nullable final Attribute... additionalAttributes)
  {
    return generateUserEntry(uid, parentDN, firstName, lastName, password,
         StaticUtils.toList(additionalAttributes));
  }



  /**
   * Generates a user entry with the provided information.  It will include the
   * top, person, organizationalPerson, and inetOrgPerson object classes, will
   * use uid as the RDN attribute, and will have givenName, sn, and cn
   * attributes.  It may optionally include additional attributes.
   *
   * @param  uid                   The value to use for the "uid: attribute.  It
   *                               must not be {@code null}.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  firstName             The first name for the user.  It must not be
   *                               {@code null}.
   * @param  lastName              The last name for the user.  It must not be
   *                               {@code null}.
   * @param  password              The password for the user.  It may be
   *                               {@code null} if the user should not have a
   *                               password.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateUserEntry(@NotNull final String uid,
              @Nullable final String parentDN,
              @NotNull final String firstName,
              @NotNull final String lastName,
              @Nullable final String password,
              @Nullable final Collection<Attribute> additionalAttributes)
  {
    final List<Attribute> attrList = new ArrayList<>(4);
    attrList.add(new Attribute("givenName", firstName));
    attrList.add(new Attribute("sn", lastName));
    attrList.add(new Attribute("cn", firstName + ' ' + lastName));

    if (password != null)
    {
      attrList.add(new Attribute("userPassword", password));
    }

    if (additionalAttributes != null)
    {
      attrList.addAll(additionalAttributes);
    }

    final String[] objectClasses =
    {
      "top",
      "person",
      "organizationalPerson",
      "inetOrgPerson",
    };

    return generateEntry("uid", uid, parentDN, objectClasses, attrList);
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateGroupOfNamesEntry(@NotNull final String name,
                           @Nullable final String parentDN,
                           @NotNull final String... memberDNs)
  {
    return generateGroupOfNamesEntry(name, parentDN,
         StaticUtils.toList(memberDNs));
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateGroupOfNamesEntry(@NotNull final String name,
                           @Nullable final String parentDN,
                           @NotNull final Collection<String> memberDNs)
  {
    final ArrayList<Attribute> attrList = new ArrayList<>(1);
    attrList.add(new Attribute("member",
         DistinguishedNameMatchingRule.getInstance(), memberDNs));

    return generateEntry("cn", name, parentDN,
         new String[] { "top", "groupOfNames" }, attrList);
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfUniqueNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateGroupOfUniqueNamesEntry(
                           @NotNull final String name,
                           @Nullable final String parentDN,
                           @NotNull final String... memberDNs)
  {
    return generateGroupOfUniqueNamesEntry(name, parentDN,
         StaticUtils.toList(memberDNs));
  }



  /**
   * Generates a group entry with the provided information.  It will include
   * the top and groupOfUniqueNames object classes and will use cn as the RDN
   * attribute.
   *
   * @param  name       The name for the group, which will be used as the value
   *                    of the "cn" attribute.  It must not be {@code null}.
   * @param  parentDN   The DN of the entry below which the new entry should be
   *                    placed.  It may be {@code null} if the new entry should
   *                    not have a parent.
   * @param  memberDNs  The DNs of the users that should be listed as members of
   *                    the group.
   *
   * @return  The generated entry.
   */
  @NotNull()
  public static Entry generateGroupOfUniqueNamesEntry(
                           @NotNull final String name,
                           @Nullable final String parentDN,
                           @NotNull final Collection<String> memberDNs)
  {
    final ArrayList<Attribute> attrList = new ArrayList<>(1);
    attrList.add(new Attribute("uniqueMember",
         DistinguishedNameMatchingRule.getInstance(), memberDNs));

    return generateEntry("cn", name, parentDN,
         new String[] { "top", "groupOfUniqueNames" }, attrList);
  }



  /**
   * Generates entry with the provided information.
   *
   * @param  rdnAttr               The name of the attribute to use for the RDN.
   * @param  rdnValue              The value of the attribute to use for the
   *                               RDN.
   * @param  parentDN              The DN of the entry below which the new
   *                               entry should be placed.  It may be
   *                               {@code null} if the new entry should not have
   *                               a parent.
   * @param  objectClasses         The object class values to include in the
   *                               entry.
   * @param  additionalAttributes  A set of additional attributes to include in
   *                               the generated entry.  It may be {@code null}
   *                               or empty if no additional attributes should
   *                               be included.
   *
   * @return  The generated entry.
   */
  @NotNull()
  private static Entry generateEntry(@NotNull final String rdnAttr,
               @NotNull final String rdnValue,
               @Nullable final String parentDN,
               @NotNull final String[] objectClasses,
               @Nullable final Collection<Attribute> additionalAttributes)
  {
    final RDN rdn = new RDN(rdnAttr, rdnValue);

    final String dn;
    if ((parentDN == null) || parentDN.trim().isEmpty())
    {
      dn = rdn.toString();
    }
    else
    {
      dn = rdn.toString() + ',' + parentDN;
    }

    final Entry entry = new Entry(dn,
         new Attribute("objectClass", objectClasses),
         new Attribute(rdnAttr, rdnValue));

    if (additionalAttributes != null)
    {
      for (final Attribute a : additionalAttributes)
      {
        entry.addAttribute(a);
      }
    }

    return entry;
  }



  /**
   * Indicates whether the specified entry exists in the server.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dn    The DN of the entry for which to make the determination.
   *
   * @return  {@code true} if the entry exists, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public static boolean entryExists(@NotNull final LDAPInterface conn,
                                    @NotNull final String dn)
         throws LDAPException
  {
    return (conn.getEntry(dn, "1.1") != null);
  }



  /**
   * Indicates whether the specified entry exists in the server and matches the
   * given filter.
   *
   * @param  conn    The connection to use to communicate with the directory
   *                 server.
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  The filter the entry is expected to match.
   *
   * @return  {@code true} if the entry exists and matches the specified filter,
   *          or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public static boolean entryExists(@NotNull final LDAPInterface conn,
                                    @NotNull final String dn,
                                    @NotNull final String filter)
         throws LDAPException
  {
    try
    {
      final SearchResult searchResult =
           conn.search(dn, SearchScope.BASE, filter, "1.1");
      return (searchResult.getEntryCount() == 1);
    }
    catch (final LDAPException le)
    {
      if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        return false;
      }
      else
      {
        throw le;
      }
    }
  }



  /**
   * Indicates whether the specified entry exists in the server.  This will
   * return {@code true} only if the target entry exists and contains all values
   * for all attributes of the provided entry.  The entry will be allowed to
   * have attribute values not included in the provided entry.
   *
   * @param  conn   The connection to use to communicate with the directory
   *                server.
   * @param  entry  The entry to compare against the directory server.
   *
   * @return  {@code true} if the entry exists in the server and is a superset
   *          of the provided entry, or {@code false} if not.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  public static boolean entryExists(@NotNull final LDAPInterface conn,
                                    @NotNull final Entry entry)
         throws LDAPException
  {
    final Collection<Attribute> attrs = entry.getAttributes();

    final List<Filter> comps = new ArrayList<>(attrs.size());
    for (final Attribute a : attrs)
    {
      for (final byte[] value : a.getValueByteArrays())
      {
        comps.add(Filter.createEqualityFilter(a.getName(), value));
      }
    }

    try
    {
      final SearchResult searchResult = conn.search(entry.getDN(),
           SearchScope.BASE, Filter.createANDFilter(comps), "1.1");
      return (searchResult.getEntryCount() == 1);
    }
    catch (final LDAPException le)
    {
      if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        return false;
      }
      else
      {
        throw le;
      }
    }
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dn    The DN of the entry for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist.
   */
  public static void assertEntryExists(@NotNull final LDAPInterface conn,
                                       @NotNull final String dn)
         throws LDAPException, AssertionError
  {
    if (conn.getEntry(dn, "1.1") == null)
    {
      throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(dn));
    }
  }



  /**
   * Ensures that an entry with the provided DN exists in the directory.
   *
   * @param  conn    The connection to use to communicate with the directory
   *                 server.
   * @param  dn      The DN of the entry for which to make the determination.
   * @param  filter  A filter that the target entry must match.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public static void assertEntryExists(@NotNull final LDAPInterface conn,
                                       @NotNull final String dn,
                                       @NotNull final String filter)
         throws LDAPException, AssertionError
  {
    try
    {
      final SearchResult searchResult =
           conn.search(dn, SearchScope.BASE, filter, "1.1");
      if (searchResult.getEntryCount() == 0)
      {
        throw new AssertionError(ERR_TEST_ENTRY_DOES_NOT_MATCH_FILTER.get(dn,
             filter));
      }
    }
    catch (final LDAPException le)
    {
      if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
      {
        throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(dn));
      }
      else
      {
        throw le;
      }
    }
  }



  /**
   * Ensures that an entry exists in the directory with the same DN and all
   * attribute values contained in the provided entry.  The server entry may
   * contain additional attributes and/or attribute values not included in the
   * provided entry.
   *
   * @param  conn   The connection to use to communicate with the directory
   *                server.
   * @param  entry  The entry expected to be present in the directory server.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          match the provided filter.
   */
  public static void assertEntryExists(@NotNull final LDAPInterface conn,
                                       @NotNull final Entry entry)
         throws LDAPException, AssertionError
  {
    // First, try to make the determination with a single search.  Only if
    // this returns false will we perform a more thorough test to construct the
    // most useful error message possible.
    if (entryExists(conn, entry))
    {
      return;
    }

    final Collection<Attribute> attributes = entry.getAttributes();
    final List<String> messages = new ArrayList<>(attributes.size());

    for (final Attribute a : attributes)
    {
      // Determine whether the attribute is present in the entry.
      try
      {
        final SearchResult searchResult = conn.search(entry.getDN(),
             SearchScope.BASE, Filter.createPresenceFilter(a.getName()), "1.1");
        if (searchResult.getEntryCount() == 0)
        {
          messages.add(ERR_TEST_ATTR_MISSING.get(entry.getDN(), a.getName()));
          continue;
        }
      }
      catch (final LDAPException le)
      {
        if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
        {
          throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(entry.getDN()));
        }
        else
        {
          throw le;
        }
      }

      for (final byte[] value : a.getValueByteArrays())
      {
        final SearchResult searchResult = conn.search(entry.getDN(),
             SearchScope.BASE, Filter.createEqualityFilter(a.getName(), value),
             "1.1");
        if (searchResult.getEntryCount() == 0)
        {
          messages.add(ERR_TEST_VALUE_MISSING.get(entry.getDN(), a.getName(),
               StaticUtils.toUTF8String(value)));
        }
      }
    }

    if (! messages.isEmpty())
    {
      throw new AssertionError(StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  public static List<String> getMissingEntryDNs(
                                  @NotNull final LDAPInterface conn,
                                  @NotNull final String... dns)
         throws LDAPException
  {
    return getMissingEntryDNs(conn, StaticUtils.toList(dns));
  }



  /**
   * Retrieves a list containing the DNs of the entries which are missing from
   * the directory server.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries to try to find in the server.
   *
   * @return  A list containing all of the provided DNs that were not found in
   *          the server, or an empty list if all entries were found.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @NotNull()
  public static List<String> getMissingEntryDNs(
                                  @NotNull final LDAPInterface conn,
                                  @NotNull final Collection<String> dns)
         throws LDAPException
  {
    final List<String> missingDNs = new ArrayList<>(dns.size());

    for (final String dn : dns)
    {
      if (conn.getEntry(dn, "1.1") == null)
      {
        missingDNs.add(dn);
      }
    }

    return missingDNs;
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public static void assertEntriesExist(@NotNull final LDAPInterface conn,
                                        @NotNull final String... dns)
         throws LDAPException, AssertionError
  {
    assertEntriesExist(conn, StaticUtils.toList(dns));
  }



  /**
   * Ensures that all of the entries with the provided DNs exist in the
   * directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dns   The DNs of the entries for which to make the determination.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If any of the target entries does not exist.
   */
  public static void assertEntriesExist(@NotNull final LDAPInterface conn,
                                        @NotNull final Collection<String> dns)
         throws LDAPException, AssertionError
  {
    final List<String> missingDNs = getMissingEntryDNs(conn, dns);
    if (missingDNs.isEmpty())
    {
      return;
    }

    final ArrayList<String> msgList = new ArrayList<>(missingDNs.size());
    for (final String dn : missingDNs)
    {
      msgList.add(ERR_TEST_ENTRY_MISSING.get(dn));
    }

    throw new AssertionError(StaticUtils.concatenateStrings(msgList));
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public static List<String> getMissingAttributeNames(
                                  @NotNull final LDAPInterface conn,
                                  @NotNull final String dn,
                                  @NotNull final String... attributeNames)
         throws LDAPException
  {
    return getMissingAttributeNames(conn, dn,
         StaticUtils.toList(attributeNames));
  }



  /**
   * Retrieves a list containing all of the named attributes which do not exist
   * in the target entry.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes expected to be present
   *                         in the target entry.
   *
   * @return  A list containing the names of the attributes which were not
   *          present in the target entry, an empty list if all specified
   *          attributes were found in the entry, or {@code null} if the target
   *          entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public static List<String> getMissingAttributeNames(
                     @NotNull final LDAPInterface conn,
                     @NotNull final String dn,
                     @NotNull final Collection<String> attributeNames)
         throws LDAPException
  {
    final List<String> missingAttrs = new ArrayList<>(attributeNames.size());

    // We will use a separate search for each target attribute so that we can
    // handle the case in which the attribute is present with a different name
    // than the one provided.
    for (final String attrName : attributeNames)
    {
      try
      {
        final SearchResult result = conn.search(dn, SearchScope.BASE,
             Filter.createPresenceFilter(attrName));
        if (result.getEntryCount() == 0)
        {
          missingAttrs.add(attrName);
        }
      }
      catch (final LDAPException le)
      {
        if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
        {
          return null;
        }
        else
        {
          throw le;
        }
      }
    }

    return missingAttrs;
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  public static void assertAttributeExists(
                          @NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final String... attributeNames)
        throws LDAPException, AssertionError
  {
    assertAttributeExists(conn, dn, StaticUtils.toList(attributeNames));
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry to examine.
   * @param  attributeNames  The names of the attributes that are expected to be
   *                         present in the provided entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist or does not
   *                          contain all of the specified attributes.
   */
  public static void assertAttributeExists(@NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final Collection<String> attributeNames)
        throws LDAPException, AssertionError
  {
    final List<String> missingAttrs =
         getMissingAttributeNames(conn, dn, attributeNames);
    if (missingAttrs == null)
    {
      // The target entry does not exist.
      throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(dn));
    }
    else if (missingAttrs.isEmpty())
    {
      return;
    }

    final List<String> msgList = new ArrayList<>(missingAttrs.size());
    for (final String attrName : missingAttrs)
    {
      msgList.add(ERR_TEST_ATTR_MISSING.get(dn, attrName));
    }

    throw new AssertionError(StaticUtils.concatenateStrings(msgList));
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public static List<String> getMissingAttributeValues(
                                  @NotNull final LDAPInterface conn,
                                  @NotNull final String dn,
                                  @NotNull final String attributeName,
                                  @NotNull final String... attributeValues)
         throws LDAPException
  {
    return getMissingAttributeValues(conn, dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Retrieves a list of all provided attribute values which are missing from
   * the specified entry.  The target attribute may or may not contain
   * additional values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The attribute expected to be present in the target
   *                          entry with the given values.
   * @param  attributeValues  The values expected to be present in the target
   *                          entry.
   *
   * @return  A list containing all of the provided values which were not found
   *          in the entry, an empty list if all provided attribute values were
   *          found, or {@code null} if the target entry does not exist.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   */
  @Nullable()
  public static List<String> getMissingAttributeValues(
                     @NotNull final LDAPInterface conn,
                     @NotNull final String dn,
                     @NotNull final String attributeName,
                     @NotNull final Collection<String> attributeValues)
       throws LDAPException
  {
    final List<String> missingValues = new ArrayList<>(attributeValues.size());

    for (final String value : attributeValues)
    {
      try
      {
        final SearchResult searchResult = conn.search(dn, SearchScope.BASE,
             Filter.createEqualityFilter(attributeName, value), "1.1");
        if (searchResult.getEntryCount() == 0)
        {
          missingValues.add(value);
        }
      }
      catch (final LDAPException le)
      {
        if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
        {
          return null;
        }
        else
        {
          throw le;
        }
      }
    }

    return missingValues;
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  public static void assertValueExists(@NotNull final LDAPInterface conn,
                                       @NotNull final String dn,
                                       @NotNull final String attributeName,
                                       @NotNull final String... attributeValues)
        throws LDAPException, AssertionError
  {
    assertValueExists(conn, dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Ensures that the specified entry exists in the directory with all of the
   * specified values for the given attribute.  The attribute may or may not
   * contain additional values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry to examine.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The set of values which must exist for the given
   *                          attribute.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry does not exist, does not
   *                          contain the specified attribute, or that attribute
   *                          does not have all of the specified values.
   */
  public static void assertValueExists(@NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final String attributeName,
                          @NotNull final Collection<String> attributeValues)
        throws LDAPException, AssertionError
  {
    final List<String> missingValues =
         getMissingAttributeValues(conn, dn, attributeName, attributeValues);
    if (missingValues == null)
    {
      // The target entry does not exist.
      throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(dn));
    }
    else if (missingValues.isEmpty())
    {
      return;
    }

    // Get the entry and see if the attribute exists in it at all.
    final Entry entry = conn.getEntry(dn, attributeName);
    if ((entry != null) && entry.hasAttribute(attributeName))
    {
      final Attribute a = entry.getAttribute(attributeName);
      throw new AssertionError(ERR_TEST_ATTR_MISSING_VALUE.get(dn,
           attributeName,
           StaticUtils.concatenateStrings("{", " '", ",", "'", " }",
                a.getValues()),
           StaticUtils.concatenateStrings("{", " '", ",", "'", " }",
                missingValues)));
    }
    else
    {
      throw new AssertionError(ERR_TEST_ATTR_MISSING.get(dn, attributeName));
    }
  }



  /**
   * Ensures that the specified entry does not exist in the directory.
   *
   * @param  conn  The connection to use to communicate with the directory
   *               server.
   * @param  dn    The DN of the entry expected to be missing.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is found in the server.
   */
  public static void assertEntryMissing(@NotNull final LDAPInterface conn,
                                        @NotNull final String dn)
         throws LDAPException, AssertionError
  {
    if (conn.getEntry(dn, "1.1") != null)
    {
      throw new AssertionError(ERR_TEST_ENTRY_EXISTS.get(dn));
    }
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  public static void assertAttributeMissing(@NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final String... attributeNames)
         throws LDAPException, AssertionError
  {
    assertAttributeMissing(conn, dn, StaticUtils.toList(attributeNames));
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attributes.
   *
   * @param  conn            The connection to use to communicate with the
   *                         directory server.
   * @param  dn              The DN of the entry expected to be present.
   * @param  attributeNames  The names of the attributes expected to be missing
   *                         from the entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attributes.
   */
  public static void assertAttributeMissing(@NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final Collection<String> attributeNames)
         throws LDAPException, AssertionError
  {
    final List<String> messages = new ArrayList<>(attributeNames.size());
    for (final String attrName : attributeNames)
    {
      try
      {
        final SearchResult searchResult = conn.search(dn, SearchScope.BASE,
             Filter.createPresenceFilter(attrName), attrName);
        if (searchResult.getEntryCount() == 1)
        {
          final Attribute a =
               searchResult.getSearchEntries().get(0).getAttribute(attrName);
          if (a == null)
          {
            messages.add(ERR_TEST_ATTR_EXISTS.get(dn, attrName));
          }
          else
          {
            messages.add(ERR_TEST_ATTR_EXISTS_WITH_VALUES.get(dn, attrName,
                 StaticUtils.concatenateStrings("{", " '", ",", "'", " }",
                                 a.getValues())));
          }
        }
      }
      catch (final LDAPException le)
      {
        if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
        {
          throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(dn));
        }
        else
        {
          throw le;
        }
      }
    }

    if (! messages.isEmpty())
    {
      throw new AssertionError(StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  public static void assertValueMissing(@NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final String attributeName,
                          @NotNull final String... attributeValues)
         throws LDAPException, AssertionError
  {
    assertValueMissing(conn, dn, attributeName,
         StaticUtils.toList(attributeValues));
  }



  /**
   * Ensures that the specified entry exists in the directory but does not
   * contain any of the specified attribute values.
   *
   * @param  conn             The connection to use to communicate with the
   *                          directory server.
   * @param  dn               The DN of the entry expected to be present.
   * @param  attributeName    The name of the attribute to examine.
   * @param  attributeValues  The values expected to be missing from the target
   *                          entry.
   *
   * @throws  LDAPException  If a problem is encountered while trying to
   *                         communicate with the directory server.
   *
   * @throws  AssertionError  If the target entry is missing from the server, or
   *                          if it contains any of the target attribute values.
   */
  public static void assertValueMissing(@NotNull final LDAPInterface conn,
                          @NotNull final String dn,
                          @NotNull final String attributeName,
                          @NotNull final Collection<String> attributeValues)
         throws LDAPException, AssertionError
  {
    final List<String> messages = new ArrayList<>(attributeValues.size());
    for (final String value : attributeValues)
    {
      try
      {
        final SearchResult searchResult = conn.search(dn, SearchScope.BASE,
             Filter.createEqualityFilter(attributeName, value), "1.1");
        if (searchResult.getEntryCount() == 1)
        {
          messages.add(ERR_TEST_VALUE_EXISTS.get(dn, attributeName, value));
        }
      }
      catch (final LDAPException le)
      {
        if (le.getResultCode() == ResultCode.NO_SUCH_OBJECT)
        {
          throw new AssertionError(ERR_TEST_ENTRY_MISSING.get(dn));
        }
        else
        {
          throw le;
        }
      }
    }

    if (! messages.isEmpty())
    {
      throw new AssertionError(StaticUtils.concatenateStrings(messages));
    }
  }



  /**
   * Ensures that the result code for the provided result matches one of the
   * given acceptable result codes.
   *
   * @param  result                 The LDAP result to examine.
   * @param  acceptableResultCodes  The set of result codes that are considered
   *                                acceptable.
   *
   * @throws  AssertionError  If the result code from the provided result did
   *                          not match any of the acceptable values.
   */
  public static void assertResultCodeEquals(@NotNull final LDAPResult result,
                          @NotNull final ResultCode... acceptableResultCodes)
         throws AssertionError
  {
    for (final ResultCode rc : acceptableResultCodes)
    {
      if (rc.equals(result.getResultCode()))
      {
        return;
      }
    }

    if (acceptableResultCodes.length == 1)
    {
      throw new AssertionError(ERR_TEST_SINGLE_RESULT_CODE_MISSING.get(
           String.valueOf(result), String.valueOf(acceptableResultCodes[0])));
    }
    else
    {
      throw new AssertionError(ERR_TEST_MULTI_RESULT_CODE_MISSING.get(
           String.valueOf(result), Arrays.toString(acceptableResultCodes)));
    }
  }



  /**
   * Ensures that the result code for the provided LDAP exception matches one of
   * the given acceptable result codes.
   *
   * @param  exception              The LDAP exception to examine.
   * @param  acceptableResultCodes  The set of result codes that are considered
   *                                acceptable.
   *
   * @throws  AssertionError  If the result code from the provided exception did
   *                          not match any of the acceptable values.
   */
  public static void assertResultCodeEquals(
                          @NotNull final LDAPException exception,
                          @NotNull final ResultCode... acceptableResultCodes)
         throws AssertionError
  {
    for (final ResultCode rc : acceptableResultCodes)
    {
      if (rc.equals(exception.getResultCode()))
      {
        return;
      }
    }

    if (acceptableResultCodes.length == 1)
    {
      throw new AssertionError(ERR_TEST_SINGLE_RESULT_CODE_MISSING.get(
           StaticUtils.getExceptionMessage(exception),
           String.valueOf(acceptableResultCodes[0])));
    }
    else
    {
      throw new AssertionError(ERR_TEST_MULTI_RESULT_CODE_MISSING.get(
           StaticUtils.getExceptionMessage(exception),
           Arrays.toString(acceptableResultCodes)));
    }
  }



  /**
   * Processes the provided request using the given connection and ensures that
   * the result code matches one of the provided acceptable values.
   *
   * @param  conn                   The connection to use to communicate with
   *                                the directory server.
   * @param  request                The request to be processed.
   * @param  acceptableResultCodes  The set of result codes that are considered
   *                                acceptable.
   *
   * @return  The result returned from processing the requested operation.
   *
   * @throws  AssertionError  If the result code returned by the server did not
   *                          match any acceptable values.
   */
  @NotNull()
  public static LDAPResult assertResultCodeEquals(
                     @NotNull final LDAPConnection conn,
                     @NotNull final LDAPRequest request,
                     @NotNull final ResultCode... acceptableResultCodes)
         throws AssertionError
  {
    LDAPResult result;

    try
    {
      result = conn.processOperation(request);
    }
    catch (final LDAPException le)
    {
      result = le.toLDAPResult();
    }

    for (final ResultCode rc : acceptableResultCodes)
    {
      if (rc.equals(result.getResultCode()))
      {
        return result;
      }
    }

    if (acceptableResultCodes.length == 1)
    {
      throw new AssertionError(ERR_TEST_SINGLE_RESULT_CODE_MISSING.get(
           String.valueOf(result), String.valueOf(acceptableResultCodes[0])));
    }
    else
    {
      throw new AssertionError(ERR_TEST_MULTI_RESULT_CODE_MISSING.get(
           String.valueOf(result), Arrays.toString(acceptableResultCodes)));
    }
  }



  /**
   * Ensures that the result code for the provided result does not match any of
   * the given unacceptable result codes.
   *
   * @param  result                   The LDAP result to examine.
   * @param  unacceptableResultCodes  The set of result codes that are
   *                                  considered unacceptable.
   *
   * @throws  AssertionError  If the result code from the provided result
   *                          matched any of the unacceptable values.
   */
  public static void assertResultCodeNot(@NotNull final LDAPResult result,
                          @NotNull final ResultCode... unacceptableResultCodes)
         throws AssertionError
  {
    for (final ResultCode rc : unacceptableResultCodes)
    {
      if (rc.equals(result.getResultCode()))
      {
        if (unacceptableResultCodes.length == 1)
        {
          throw new AssertionError(ERR_TEST_SINGLE_RESULT_CODE_FOUND.get(
               String.valueOf(result),
               String.valueOf(unacceptableResultCodes[0])));
        }
        else
        {
          throw new AssertionError(ERR_TEST_MULTI_RESULT_CODE_FOUND.get(
               String.valueOf(result),
               Arrays.toString(unacceptableResultCodes)));
        }
      }
    }
  }



  /**
   * Ensures that the result code for the provided result does not match any of
   * the given unacceptable result codes.
   *
   * @param  exception                The LDAP exception to examine.
   * @param  unacceptableResultCodes  The set of result codes that are
   *                                  considered unacceptable.
   *
   * @throws  AssertionError  If the result code from the provided result
   *                          matched any of the unacceptable values.
   */
  public static void assertResultCodeNot(@NotNull final LDAPException exception,
                          @NotNull final ResultCode... unacceptableResultCodes)
         throws AssertionError
  {
    for (final ResultCode rc : unacceptableResultCodes)
    {
      if (rc.equals(exception.getResultCode()))
      {
        if (unacceptableResultCodes.length == 1)
        {
          throw new AssertionError(ERR_TEST_SINGLE_RESULT_CODE_FOUND.get(
               StaticUtils.getExceptionMessage(exception),
               String.valueOf(unacceptableResultCodes[0])));
        }
        else
        {
          throw new AssertionError(ERR_TEST_MULTI_RESULT_CODE_FOUND.get(
               StaticUtils.getExceptionMessage(exception),
               Arrays.toString(unacceptableResultCodes)));
        }
      }
    }
  }



  /**
   * Processes the provided request using the given connection and ensures that
   * the result code does not match any of the given unacceptable values.
   *
   * @param  conn                     The connection to use to communicate with
   *                                  the directory server.
   * @param  request                  The request to be processed.
   * @param  unacceptableResultCodes  The set of result codes that are
   *                                  considered unacceptable.
   *
   * @return  The result returned from processing the requested operation.
   *
   * @throws  AssertionError  If the result code from the provided result
   *                          matched any of the unacceptable values.
   */
  @NotNull()
  public static LDAPResult assertResultCodeNot(
                     @NotNull final LDAPConnection conn,
                     @NotNull final LDAPRequest request,
                     @NotNull final ResultCode... unacceptableResultCodes)
         throws AssertionError
  {
    LDAPResult result;

    try
    {
      result = conn.processOperation(request);
    }
    catch (final LDAPException le)
    {
      result = le.toLDAPResult();
    }

    for (final ResultCode rc : unacceptableResultCodes)
    {
      if (rc.equals(result.getResultCode()))
      {
        if (unacceptableResultCodes.length == 1)
        {
          throw new AssertionError(ERR_TEST_SINGLE_RESULT_CODE_FOUND.get(
               String.valueOf(result),
               String.valueOf(unacceptableResultCodes[0])));
        }
        else
        {
          throw new AssertionError(ERR_TEST_MULTI_RESULT_CODE_FOUND.get(
               String.valueOf(result),
               Arrays.toString(unacceptableResultCodes)));
        }
      }
    }

    return result;
  }



  /**
   * Ensures that the provided LDAP result contains a matched DN value.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result did not contain a matched
   *                          DN value.
   */
  public static void assertContainsMatchedDN(@NotNull final LDAPResult result)
         throws AssertionError
  {
    if (result.getMatchedDN() == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_MATCHED_DN.get(
           String.valueOf(result)));
    }
  }



  /**
   * Ensures that the provided LDAP exception contains a matched DN value.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception did not contain a
   *                          matched DN value.
   */
  public static void assertContainsMatchedDN(
                          @NotNull final LDAPException exception)
         throws AssertionError
  {
    if (exception.getMatchedDN() == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_MATCHED_DN.get(
           StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Ensures that the provided LDAP result does not contain a matched DN value.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result contained a matched DN
   *                          value.
   */
  public static void assertMissingMatchedDN(@NotNull final LDAPResult result)
         throws AssertionError
  {
    if (result.getMatchedDN() != null)
    {
      throw new AssertionError(ERR_TEST_RESULT_CONTAINS_MATCHED_DN.get(
           String.valueOf(result), result.getMatchedDN()));
    }
  }



  /**
   * Ensures that the provided LDAP exception does not contain a matched DN
   * value.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception contained a matched DN
   *                          value.
   */
  public static void assertMissingMatchedDN(
                          @NotNull final LDAPException exception)
         throws AssertionError
  {
    if (exception.getMatchedDN() != null)
    {
      throw new AssertionError(ERR_TEST_RESULT_CONTAINS_MATCHED_DN.get(
           StaticUtils.getExceptionMessage(exception),
           exception.getMatchedDN()));
    }
  }



  /**
   * Ensures that the provided LDAP result has the given matched DN value.
   *
   * @param  result     The LDAP result to examine.
   * @param  matchedDN  The matched DN value expected to be found in the
   *                    provided result.  It must not be {@code null}.
   *
   * @throws  LDAPException  If either the found or expected matched DN values
   *                         could not be parsed as a valid DN.
   *
   * @throws  AssertionError  If the provided LDAP result did not contain a
   *                          matched DN, or if it had a matched DN that
   *                          differed from the expected value.
   */
  public static void assertMatchedDNEquals(@NotNull final LDAPResult result,
                                           @NotNull final String matchedDN)
         throws LDAPException, AssertionError
  {
    if (result.getMatchedDN() == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_EXPECTED_MATCHED_DN.get(
           String.valueOf(result), matchedDN));
    }

    final DN foundDN    = new DN(result.getMatchedDN());
    final DN expectedDN = new DN(matchedDN);
    if (! foundDN.equals(expectedDN))
    {
      throw new AssertionError(ERR_TEST_MATCHED_DN_MISMATCH.get(
           String.valueOf(result), matchedDN, result.getMatchedDN()));
    }
  }



  /**
   * Ensures that the provided LDAP exception has the given matched DN value.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  matchedDN  The matched DN value expected to be found in the
   *                    provided exception.  It must not be {@code null}.
   *
   * @throws  LDAPException  If either the found or expected matched DN values
   *                         could not be parsed as a valid DN.
   *
   * @throws  AssertionError  If the provided LDAP exception did not contain a
   *                          matched DN, or if it had a matched DN that
   *                          differed from the expected value.
   */
  public static void assertMatchedDNEquals(
                          @NotNull final LDAPException exception,
                          @NotNull final String matchedDN)
         throws LDAPException, AssertionError
  {
    if (exception.getMatchedDN() == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_EXPECTED_MATCHED_DN.get(
           StaticUtils.getExceptionMessage(exception), matchedDN));
    }

    final DN foundDN    = new DN(exception.getMatchedDN());
    final DN expectedDN = new DN(matchedDN);
    if (! foundDN.equals(expectedDN))
    {
      throw new AssertionError(ERR_TEST_MATCHED_DN_MISMATCH.get(
           StaticUtils.getExceptionMessage(exception), matchedDN,
           exception.getMatchedDN()));
    }
  }



  /**
   * Ensures that the provided LDAP result contains a diagnostic message.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result did not contain a
   *                          diagnostic message.
   */
  public static void assertContainsDiagnosticMessage(
                          @NotNull final LDAPResult result)
         throws AssertionError
  {
    if (result.getDiagnosticMessage() == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_DIAGNOSTIC_MESSAGE.get(
           String.valueOf(result)));
    }
  }



  /**
   * Ensures that the provided LDAP exception contains a diagnostic message.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception did not contain a
   *                          diagnostic message.
   */
  public static void assertContainsDiagnosticMessage(
                          @NotNull final LDAPException exception)
         throws AssertionError
  {
    if (exception.getDiagnosticMessage() == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_DIAGNOSTIC_MESSAGE.get(
           StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Ensures that the provided LDAP result does not contain a diagnostic
   * message.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result contained a diagnostic
   *                          message.
   */
  public static void assertMissingDiagnosticMessage(
                          @NotNull final LDAPResult result)
         throws AssertionError
  {
    if (result.getDiagnosticMessage() != null)
    {
      throw new AssertionError(ERR_TEST_RESULT_CONTAINS_DIAGNOSTIC_MESSAGE.get(
           String.valueOf(result), result.getDiagnosticMessage()));
    }
  }



  /**
   * Ensures that the provided LDAP exception does not contain a diagnostic
   * message.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception contained a diagnostic
   *                          message.
   */
  public static void assertMissingDiagnosticMessage(
                          @NotNull final LDAPException exception)
         throws AssertionError
  {
    if (exception.getDiagnosticMessage() != null)
    {
      throw new AssertionError(ERR_TEST_RESULT_CONTAINS_DIAGNOSTIC_MESSAGE.get(
           StaticUtils.getExceptionMessage(exception),
           exception.getDiagnosticMessage()));
    }
  }



  /**
   * Ensures that the provided LDAP result has the given diagnostic message.
   *
   * @param  result             The LDAP result to examine.
   * @param  diagnosticMessage  The diagnostic message expected to be found in
   *                            the provided result.  It must not be
   *                            {@code null}.
   *
   * @throws  AssertionError  If the provided LDAP result did not contain a
   *                          diagnostic message, or if it had a diagnostic
   *                          message that differed from the expected value.
   */
  public static void assertDiagnosticMessageEquals(
                          @NotNull final LDAPResult result,
                          @NotNull final String diagnosticMessage)
         throws AssertionError
  {
    if (result.getDiagnosticMessage() == null)
    {
      throw new AssertionError(
           ERR_TEST_RESULT_MISSING_EXPECTED_DIAGNOSTIC_MESSAGE.get(
                String.valueOf(result), diagnosticMessage));
    }

    if (! result.getDiagnosticMessage().equals(diagnosticMessage))
    {
      throw new AssertionError(ERR_TEST_DIAGNOSTIC_MESSAGE_MISMATCH.get(
           String.valueOf(result), diagnosticMessage,
           result.getDiagnosticMessage()));
    }
  }



  /**
   * Ensures that the provided LDAP exception has the given diagnostic message.
   *
   * @param  exception          The LDAP exception to examine.
   * @param  diagnosticMessage  The diagnostic message expected to be found in
   *                            the provided exception.  It must not be
   *                            {@code null}.
   *
   * @throws  AssertionError  If the provided LDAP exception did not contain a
   *                          diagnostic message, or if it had a diagnostic
   *                          message that differed from the expected value.
   */
  public static void assertDiagnosticMessageEquals(
                          @NotNull final LDAPException exception,
                          @NotNull final String diagnosticMessage)
         throws AssertionError
  {
    if (exception.getDiagnosticMessage() == null)
    {
      throw new AssertionError(
           ERR_TEST_RESULT_MISSING_EXPECTED_DIAGNOSTIC_MESSAGE.get(
                StaticUtils.getExceptionMessage(exception), diagnosticMessage));
    }

    if (! exception.getDiagnosticMessage().equals(diagnosticMessage))
    {
      throw new AssertionError(ERR_TEST_DIAGNOSTIC_MESSAGE_MISMATCH.get(
           StaticUtils.getExceptionMessage(exception), diagnosticMessage,
           exception.getDiagnosticMessage()));
    }
  }



  /**
   * Ensures that the provided LDAP result has one or more referral URLs.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result does not have any referral
   *                          URLs.
   */
  public static void assertHasReferral(@NotNull final LDAPResult result)
         throws AssertionError
  {
    final String[] referralURLs = result.getReferralURLs();
    if ((referralURLs == null) || (referralURLs.length == 0))
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_REFERRAL.get(
           String.valueOf(result)));
    }
  }



  /**
   * Ensures that the provided LDAP exception has one or more referral URLs.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception does not have any
   *                          referral URLs.
   */
  public static void assertHasReferral(@NotNull final LDAPException exception)
         throws AssertionError
  {
    final String[] referralURLs = exception.getReferralURLs();
    if ((referralURLs == null) || (referralURLs.length == 0))
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_REFERRAL.get(
           StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Ensures that the provided LDAP result does not have any referral URLs.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result has one or more referral
   *                          URLs.
   */
  public static void assertMissingReferral(@NotNull final LDAPResult result)
         throws AssertionError
  {
    final String[] referralURLs = result.getReferralURLs();
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      throw new AssertionError(ERR_TEST_RESULT_HAS_REFERRAL.get(
           String.valueOf(result)));
    }
  }



  /**
   * Ensures that the provided LDAP exception does not have any referral URLs.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception has one or more referral
   *                          URLs.
   */
  public static void assertMissingReferral(
                          @NotNull final LDAPException exception)
         throws AssertionError
  {
    final String[] referralURLs = exception.getReferralURLs();
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      throw new AssertionError(ERR_TEST_RESULT_HAS_REFERRAL.get(
           StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Ensures that the provided LDAP result includes at least one control with
   * the specified OID.
   *
   * @param  result  The LDAP result to examine.
   * @param  oid     The OID of the control which is expected to be present in
   *                 the result.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided LDAP result does not include any
   *                          control with the specified OID.
   */
  @NotNull()
  public static Control assertHasControl(@NotNull final LDAPResult result,
                                         @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : result.getResponseControls())
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    throw new AssertionError(ERR_TEST_RESULT_MISSING_CONTROL.get(
         String.valueOf(result), oid));
  }



  /**
   * Ensures that the provided LDAP exception includes at least one control with
   * the specified OID.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  oid        The OID of the control which is expected to be present
   *                    in the exception.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided LDAP exception does not include
   *                          any control with the specified OID.
   */
  @NotNull()
  public static Control assertHasControl(@NotNull final LDAPException exception,
                                         @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : exception.getResponseControls())
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    throw new AssertionError(ERR_TEST_RESULT_MISSING_CONTROL.get(
         StaticUtils.getExceptionMessage(exception), oid));
  }



  /**
   * Ensures that the provided search result entry includes at least one control
   * with the specified OID.
   *
   * @param  entry  The search result entry to examine.
   * @param  oid    The OID of the control which is expected to be present in
   *                the search result entry.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided search result entry does not
   *                          include any control with the specified OID.
   */
  @NotNull()
  public static Control assertHasControl(@NotNull final SearchResultEntry entry,
                                         @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : entry.getControls())
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    throw new AssertionError(ERR_TEST_ENTRY_MISSING_CONTROL.get(
         String.valueOf(entry), oid));
  }



  /**
   * Ensures that the provided search result reference includes at least one
   * control with the specified OID.
   *
   * @param  reference  The search result reference to examine.
   * @param  oid        The OID of the control which is expected to be present
   *                    in the search result reference.
   *
   * @return  The first control found with the specified OID.
   *
   * @throws  AssertionError  If the provided search result reference does not
   *                          include any control with the specified OID.
   */
  @NotNull()
  public static Control assertHasControl(
                             @NotNull final SearchResultReference reference,
                             @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : reference.getControls())
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    throw new AssertionError(ERR_TEST_REF_MISSING_CONTROL.get(
         String.valueOf(reference), oid));
  }



  /**
   * Ensures that the provided LDAP result does not include any control with
   * the specified OID.
   *
   * @param  result  The LDAP result to examine.
   * @param  oid     The OID of the control which is not expected to be present
   *                 in the result.
   *
   * @throws  AssertionError  If the provided LDAP result includes any control
   *                          with the specified OID.
   */
  public static void assertMissingControl(@NotNull final LDAPResult result,
                                          @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : result.getResponseControls())
    {
      if (c.getOID().equals(oid))
      {
        throw new AssertionError(ERR_TEST_RESULT_HAS_CONTROL.get(
             String.valueOf(result), oid));
      }
    }
  }



  /**
   * Ensures that the provided LDAP exception does not include any control with
   * the specified OID.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  oid        The OID of the control which is not expected to be
   *                    present in the exception.
   *
   * @throws  AssertionError  If the provided LDAP exception includes any
   *                          control with the specified OID.
   */
  public static void assertMissingControl(
                          @NotNull final LDAPException exception,
                          @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : exception.getResponseControls())
    {
      if (c.getOID().equals(oid))
      {
        throw new AssertionError(ERR_TEST_RESULT_HAS_CONTROL.get(
             StaticUtils.getExceptionMessage(exception), oid));
      }
    }
  }



  /**
   * Ensures that the provided search result entry does not includes any control
   * with the specified OID.
   *
   * @param  entry  The search result entry to examine.
   * @param  oid    The OID of the control which is not expected to be present
   *                in the search result entry.
   *
   * @throws  AssertionError  If the provided search result entry includes any
   *                          control with the specified OID.
   */
  public static void assertMissingControl(
                          @NotNull final SearchResultEntry entry,
                          @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : entry.getControls())
    {
      if (c.getOID().equals(oid))
      {
        throw new AssertionError(ERR_TEST_ENTRY_HAS_CONTROL.get(
             String.valueOf(entry), oid));
      }
    }
  }



  /**
   * Ensures that the provided search result reference does not includes any
   * control with the specified OID.
   *
   * @param  reference  The search result reference to examine.
   * @param  oid        The OID of the control which is not expected to be
   *                    present in the search result reference.
   *
   * @throws  AssertionError  If the provided search result reference includes
   *                          any control with the specified OID.
   */
  public static void assertMissingControl(
                          @NotNull final SearchResultReference reference,
                          @NotNull final String oid)
         throws AssertionError
  {
    for (final Control c : reference.getControls())
    {
      if (c.getOID().equals(oid))
      {
        throw new AssertionError(ERR_TEST_REF_HAS_CONTROL.get(
             String.valueOf(reference), oid));
      }
    }
  }



  /**
   * Ensures that the provided search result indicates that at least one search
   * result entry was returned.
   *
   * @param  result  The search result to examine.
   *
   * @return  The number of search result entries that were returned.
   *
   * @throws  AssertionError  If the provided search result indicates that no
   *                          entries were returned.
   */
  public static int assertEntryReturned(@NotNull final SearchResult result)
         throws AssertionError
  {
    if (result.getEntryCount() == 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_NO_ENTRIES_RETURNED.get(
           String.valueOf(result)));
    }

    return result.getEntryCount();
  }



  /**
   * Ensures that the provided search exception indicates that at least one
   * search result entry was returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @return  The number of search result entries that were returned.
   *
   * @throws  AssertionError  If the provided search exception indicates that no
   *                          entries were returned.
   */
  public static int assertEntryReturned(
                         @NotNull final LDAPSearchException exception)
         throws AssertionError
  {
    if (exception.getEntryCount() == 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_NO_ENTRIES_RETURNED.get(
           StaticUtils.getExceptionMessage(exception)));
    }

    return exception.getEntryCount();
  }



  /**
   * Ensures that the specified search result entry was included in provided
   * search result.
   *
   * @param  result  The search result to examine.
   * @param  dn      The DN of the entry expected to be included in the
   *                 search result.
   *
   * @return  The search result entry with the provided DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   *
   * @throws  AssertionError  If the specified entry was not included in the
   *                          set of entries that were returned, or if a search
   *                          result listener was used which makes the
   *                          determination impossible.
   */
  @NotNull()
  public static SearchResultEntry assertEntryReturned(
                                       @NotNull final SearchResult result,
                                       @NotNull final String dn)
         throws LDAPException, AssertionError
  {
    final DN parsedDN = new DN(dn);

    final List<SearchResultEntry> entryList = result.getSearchEntries();
    if (entryList != null)
    {
      for (final SearchResultEntry e : entryList)
      {
        if (e.getParsedDN().equals(parsedDN))
        {
          return e;
        }
      }
    }

    throw new AssertionError(ERR_TEST_SEARCH_ENTRY_NOT_RETURNED.get(
         String.valueOf(result), dn));
  }



  /**
   * Ensures that the specified search result entry was included in provided
   * search exception.
   *
   * @param  exception  The search exception to examine.
   * @param  dn         The DN of the entry expected to be included in the
   *                    search exception.
   *
   * @return  The search result entry with the provided DN.
   *
   * @throws  LDAPException  If the provided string cannot be parsed as a valid
   *                         DN.
   *
   * @throws  AssertionError  If the specified entry was not included in the
   *                          set of entries that were returned, or if a search
   *                          result listener was used which makes the
   *                          determination impossible.
   */
  @NotNull()
  public static SearchResultEntry assertEntryReturned(
                     @NotNull final LDAPSearchException exception,
                     @NotNull final String dn)
         throws LDAPException, AssertionError
  {
    final DN parsedDN = new DN(dn);

    final List<SearchResultEntry> entryList = exception.getSearchEntries();
    if (entryList != null)
    {
      for (final SearchResultEntry e : entryList)
      {
        if (e.getParsedDN().equals(parsedDN))
        {
          return e;
        }
      }
    }

    throw new AssertionError(ERR_TEST_SEARCH_ENTRY_NOT_RETURNED.get(
         StaticUtils.getExceptionMessage(exception), dn));
  }



  /**
   * Ensures that the provided search result indicates that no search result
   * entries were returned.
   *
   * @param  result  The search result to examine.
   *
   * @throws  AssertionError  If the provided search result indicates that one
   *                          or more entries were returned.
   */
  public static void assertNoEntriesReturned(@NotNull final SearchResult result)
         throws AssertionError
  {
    if (result.getEntryCount() > 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_ENTRIES_RETURNED.get(
           String.valueOf(result), result.getEntryCount()));
    }
  }



  /**
   * Ensures that the provided search exception indicates that no search result
   * entries were returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @throws  AssertionError  If the provided search exception indicates that
   *                          one or more entries were returned.
   */
  public static void assertNoEntriesReturned(
                          @NotNull final LDAPSearchException exception)
         throws AssertionError
  {
    if (exception.getEntryCount() > 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_ENTRIES_RETURNED.get(
           StaticUtils.getExceptionMessage(exception),
           exception.getEntryCount()));
    }
  }



  /**
   * Ensures that the provided search result indicates that the expected number
   * of entries were returned.
   *
   * @param  result              The search result to examine.
   * @param  expectedEntryCount  The number of expected search result entries.
   *
   * @throws  AssertionError  If the number of entries returned does not match
   *                          the expected value.
   */
  public static void assertEntriesReturnedEquals(
                          @NotNull final SearchResult result,
                          final int expectedEntryCount)
         throws AssertionError
  {
    if (result.getEntryCount() != expectedEntryCount)
    {
      if (expectedEntryCount == 1)
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_ENTRY_COUNT_MISMATCH_ONE_EXPECTED.get(
                  String.valueOf(result), result.getEntryCount()));
      }
      else
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_ENTRY_COUNT_MISMATCH_MULTI_EXPECTED.get(
                  expectedEntryCount, String.valueOf(result),
                  result.getEntryCount()));
      }
    }
  }



  /**
   * Ensures that the provided search exception indicates that the expected
   * number of entries were returned.
   *
   * @param  exception           The search exception to examine.
   * @param  expectedEntryCount  The number of expected search result entries.
   *
   * @throws  AssertionError  If the number of entries returned does not match
   *                          the expected value.
   */
  public static void assertEntriesReturnedEquals(
                          @NotNull final LDAPSearchException exception,
                          final int expectedEntryCount)
         throws AssertionError
  {
    if (exception.getEntryCount() != expectedEntryCount)
    {
      if (expectedEntryCount == 1)
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_ENTRY_COUNT_MISMATCH_ONE_EXPECTED.get(
                  StaticUtils.getExceptionMessage(exception),
                  exception.getEntryCount()));
      }
      else
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_ENTRY_COUNT_MISMATCH_MULTI_EXPECTED.get(
                  expectedEntryCount,
                  StaticUtils.getExceptionMessage(exception),
                  exception.getEntryCount()));
      }
    }
  }



  /**
   * Ensures that the provided search result indicates that at least one search
   * result reference was returned.
   *
   * @param  result  The search result to examine.
   *
   * @return  The number of search result references that were returned.
   *
   * @throws  AssertionError  If the provided search result indicates that no
   *                          references were returned.
   */
  public static int assertReferenceReturned(@NotNull final SearchResult result)
         throws AssertionError
  {
    if (result.getReferenceCount() == 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_NO_REFS_RETURNED.get(
           String.valueOf(result)));
    }

    return result.getReferenceCount();
  }



  /**
   * Ensures that the provided search exception indicates that at least one
   * search result reference was returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @return  The number of search result references that were returned.
   *
   * @throws  AssertionError  If the provided search exception indicates that no
   *                          references were returned.
   */
  public static int assertReferenceReturned(
                         @NotNull final LDAPSearchException exception)
         throws AssertionError
  {
    if (exception.getReferenceCount() == 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_NO_REFS_RETURNED.get(
           StaticUtils.getExceptionMessage(exception)));
    }

    return exception.getReferenceCount();
  }



  /**
   * Ensures that the provided search result indicates that no search result
   * references were returned.
   *
   * @param  result  The search result to examine.
   *
   * @throws  AssertionError  If the provided search result indicates that one
   *                          or more references were returned.
   */
  public static void assertNoReferencesReturned(
                          @NotNull final SearchResult result)
         throws AssertionError
  {
    if (result.getReferenceCount() > 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_REFS_RETURNED.get(
           String.valueOf(result), result.getReferenceCount()));
    }
  }



  /**
   * Ensures that the provided search exception indicates that no search result
   * references were returned.
   *
   * @param  exception  The search exception to examine.
   *
   * @throws  AssertionError  If the provided search exception indicates that
   *                          one or more references were returned.
   */
  public static void assertNoReferencesReturned(
                          @NotNull final LDAPSearchException exception)
         throws AssertionError
  {
    if (exception.getReferenceCount() > 0)
    {
      throw new AssertionError(ERR_TEST_SEARCH_REFS_RETURNED.get(
           StaticUtils.getExceptionMessage(exception),
           exception.getReferenceCount()));
    }
  }



  /**
   * Ensures that the provided search result indicates that the expected number
   * of references were returned.
   *
   * @param  result                  The search result to examine.
   * @param  expectedReferenceCount  The number of expected search result
   *                                 references.
   *
   * @throws  AssertionError  If the number of references returned does not
   *                          match the expected value.
   */
  public static void assertReferencesReturnedEquals(
                          @NotNull final SearchResult result,
                          final int expectedReferenceCount)
         throws AssertionError
  {
    if (result.getReferenceCount() != expectedReferenceCount)
    {
      if (expectedReferenceCount == 1)
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_REF_COUNT_MISMATCH_ONE_EXPECTED.get(
                  String.valueOf(result), result.getReferenceCount()));
      }
      else
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_REF_COUNT_MISMATCH_MULTI_EXPECTED.get(
                  expectedReferenceCount, String.valueOf(result),
                  result.getReferenceCount()));
      }
    }
  }



  /**
   * Ensures that the provided search exception indicates that the expected
   * number of references were returned.
   *
   * @param  exception               The search exception to examine.
   * @param  expectedReferenceCount  The number of expected search result
   *                                 references.
   *
   * @throws  AssertionError  If the number of references returned does not
   *                          match the expected value.
   */
  public static void assertReferencesReturnedEquals(
                          @NotNull final LDAPSearchException exception,
                          final int expectedReferenceCount)
         throws AssertionError
  {
    if (exception.getReferenceCount() != expectedReferenceCount)
    {
      if (expectedReferenceCount == 1)
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_REF_COUNT_MISMATCH_ONE_EXPECTED.get(
                  StaticUtils.getExceptionMessage(exception),
                  exception.getReferenceCount()));
      }
      else
      {
        throw new AssertionError(
             ERR_TEST_SEARCH_REF_COUNT_MISMATCH_MULTI_EXPECTED.get(
                  expectedReferenceCount,
                  StaticUtils.getExceptionMessage(exception),
                  exception.getReferenceCount()));
      }
    }
  }



  /**
   * Ensures that the two provided strings represent the same DN.
   *
   * @param  s1  The first string to compare.
   * @param  s2  The second string to compare.
   *
   * @throws  AssertionError  If either string doesn't represent a valid DN, or
   *                          if they do not represent the same DN.
   */
  public static void assertDNsEqual(@NotNull final String s1,
                                    @NotNull final String s2)
         throws AssertionError
  {
    final DN dn1;
    try
    {
      dn1 = new DN(s1);
    }
    catch (final Exception e)
    {
      throw new AssertionError(ERR_TEST_VALUE_NOT_VALID_DN.get(s1,
           StaticUtils.getExceptionMessage(e)));
    }

    final DN dn2;
    try
    {
      dn2 = new DN(s2);
    }
    catch (final Exception e)
    {
      throw new AssertionError(ERR_TEST_VALUE_NOT_VALID_DN.get(s2,
           StaticUtils.getExceptionMessage(e)));
    }

    if (! dn1.equals(dn2))
    {
      throw new AssertionError(ERR_TEST_DNS_NOT_EQUAL.get(s1, s2));
    }
  }
}
