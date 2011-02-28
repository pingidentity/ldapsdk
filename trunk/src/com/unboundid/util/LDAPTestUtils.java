/*
 * Copyright 2011 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2011 UnboundID Corp.
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
import java.util.Collection;
import java.util.List;

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
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.SearchResult;
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
  public static Entry generateDomainEntry(final String name,
                           final String parentDN,
                           final Attribute... additionalAttributes)
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
  public static Entry generateDomainEntry(final String name,
                           final String parentDN,
                           final Collection<Attribute> additionalAttributes)
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
  public static Entry generateOrgEntry(final String name, final String parentDN,
                           final Attribute... additionalAttributes)
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
  public static Entry generateOrgEntry(final String name, final String parentDN,
                           final Collection<Attribute> additionalAttributes)
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
  public static Entry generateOrgUnitEntry(final String name,
                           final String parentDN,
                           final Attribute... additionalAttributes)
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
  public static Entry generateOrgUnitEntry(final String name,
                           final String parentDN,
                           final Collection<Attribute> additionalAttributes)
  {
    return generateEntry("ou", name, parentDN,
         new String[] { "top", "organizationalUnit" },
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
  public static Entry generateUserEntry(final String uid, final String parentDN,
                           final String firstName, final String lastName,
                           final String password,
                           final Attribute... additionalAttributes)
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
  public static Entry generateUserEntry(final String uid, final String parentDN,
                           final String firstName, final String lastName,
                           final String password,
                           final Collection<Attribute> additionalAttributes)
  {
    final List<Attribute> attrList = new ArrayList<Attribute>(4);
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
  private static Entry generateEntry(final String rdnAttr,
                            final String rdnValue, final String parentDN,
                            final String[] objectClasses,
                            final Collection<Attribute> additionalAttributes)
  {
    final RDN rdn = new RDN(rdnAttr, rdnValue);

    final String dn;
    if ((parentDN == null) || (parentDN.trim().length() == 0))
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
  public static boolean entryExists(final LDAPInterface conn, final String dn)
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
  public static boolean entryExists(final LDAPInterface conn, final String dn,
                                    final String filter)
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
  public static boolean entryExists(final LDAPInterface conn, final Entry entry)
         throws LDAPException
  {
    final Collection<Attribute> attrs = entry.getAttributes();

    final List<Filter> comps = new ArrayList<Filter>(attrs.size());
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
  public static void assertEntryExists(final LDAPInterface conn,
                                       final String dn)
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
  public static void assertEntryExists(final LDAPInterface conn,
                                       final String dn, final String filter)
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
  public static void assertEntryExists(final LDAPInterface conn,
                                       final Entry entry)
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
    final List<String> messages = new ArrayList<String>(attributes.size());

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
  public static List<String> getMissingEntryDNs(final LDAPInterface conn,
                                                final String... dns)
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
  public static List<String> getMissingEntryDNs(final LDAPInterface conn,
                                                final Collection<String> dns)
         throws LDAPException
  {
    final List<String> missingDNs = new ArrayList<String>(dns.size());

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
  public static void assertEntriesExist(final LDAPInterface conn,
                                        final String... dns)
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
  public static void assertEntriesExist(final LDAPInterface conn,
                                        final Collection<String> dns)
         throws LDAPException, AssertionError
  {
    final List<String> missingDNs = getMissingEntryDNs(conn, dns);
    if (missingDNs.isEmpty())
    {
      return;
    }

    final ArrayList<String> msgList = new ArrayList<String>(missingDNs.size());
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
  public static List<String> getMissingAttributeNames(final LDAPInterface conn,
                                  final String dn,
                                  final String... attributeNames)
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
  public static List<String> getMissingAttributeNames(final LDAPInterface conn,
                                  final String dn,
                                  final Collection<String> attributeNames)
         throws LDAPException
  {
    final List<String> missingAttrs =
         new ArrayList<String>(attributeNames.size());

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
  public static void assertAttributeExists(final LDAPInterface conn,
                                           final String dn,
                                           final String... attributeNames)
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
  public static void assertAttributeExists(final LDAPInterface conn,
                          final String dn,
                          final Collection<String> attributeNames)
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

    final List<String> msgList = new ArrayList<String>(missingAttrs.size());
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
  public static List<String> getMissingAttributeValues(final LDAPInterface conn,
                                  final String dn, final String attributeName,
                                  final String... attributeValues)
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
  public static List<String> getMissingAttributeValues(final LDAPInterface conn,
                                  final String dn, final String attributeName,
                                  final Collection<String> attributeValues)
       throws LDAPException
  {
    final List<String> missingValues =
         new ArrayList<String>(attributeValues.size());

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
  public static void assertValueExists(final LDAPInterface conn,
                                       final String dn,
                                       final String attributeName,
                                       final String... attributeValues)
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
  public static void assertValueExists(final LDAPInterface conn,
                                       final String dn,
                                       final String attributeName,
                                       final Collection<String> attributeValues)
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

    // See if the target attribute exists in the entry at all.
    final SearchResult searchResult = conn.search(dn, SearchScope.BASE,
         Filter.createPresenceFilter(attributeName), "1.1");
    if (searchResult.getEntryCount() == 0)
    {
      throw new AssertionError(ERR_TEST_ATTR_MISSING.get(dn, attributeName));
    }

    final List<String> messages = new ArrayList<String>(missingValues.size());
    for (final String value : missingValues)
    {
      messages.add(ERR_TEST_VALUE_MISSING.get(dn, attributeName, value));
    }

    throw new AssertionError(StaticUtils.concatenateStrings(messages));
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
  public static void assertEntryMissing(final LDAPInterface conn,
                                        final String dn)
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
  public static void assertAttributeMissing(final LDAPInterface conn,
                                            final String dn,
                                            final String... attributeNames)
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
  public static void assertAttributeMissing(final LDAPInterface conn,
                          final String dn,
                          final Collection<String> attributeNames)
         throws LDAPException, AssertionError
  {
    final List<String> messages = new ArrayList<String>(attributeNames.size());
    for (final String attrName : attributeNames)
    {
      try
      {
        final SearchResult searchResult = conn.search(dn, SearchScope.BASE,
             Filter.createPresenceFilter(attrName), "1.1");
        if (searchResult.getEntryCount() == 1)
        {
          messages.add(ERR_TEST_ATTR_EXISTS.get(dn, attrName));
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
  public static void assertValueMissing(final LDAPInterface conn,
                          final String dn, final String attributeName,
                          final String... attributeValues)
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
  public static void assertValueMissing(final LDAPInterface conn,
                          final String dn, final String attributeName,
                          final Collection<String> attributeValues)
         throws LDAPException, AssertionError
  {
    final List<String> messages = new ArrayList<String>(attributeValues.size());
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
   * Ensures that the result code for the provided result matches the expected
   * value.
   *
   * @param  result      The LDAP result to examine.
   * @param  resultCode  The expected result code for the given result.
   *
   * @throws  AssertionError  If the result code from the provided result did
   *                          not match the expected value.
   */
  public static void expectResultCode(final LDAPResult result,
                                      final ResultCode resultCode)
         throws AssertionError
  {
    if (result.getResultCode() != resultCode)
    {
      throw new AssertionError(ERR_TEST_RESULT_CODE_MISMATCH.get(
           resultCode.toString(), result.toString()));
    }
  }



  /**
   * Ensures that the result code for the provided LDAP exception matches the
   * expected value.
   *
   * @param  exception   The LDAP exception to examine.
   * @param  resultCode  The expected result code for the given result.
   *
   * @throws  AssertionError  If the result code from the provided result did
   *                          not match the expected value.
   */
  public static void expectResultCode(final LDAPException exception,
                                      final ResultCode resultCode)
       throws AssertionError
  {
    if (exception.getResultCode() != resultCode)
    {
      throw new AssertionError(ERR_TEST_RESULT_CODE_MISMATCH.get(
           resultCode.toString(), StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Processes the provided request using the given connection and ensures that
   * the result code matches the expected value.
   *
   * @param  conn        The connection to use to communicate with the
   *                     directory server.
   * @param  request     The request to be processed.
   * @param  resultCode  The expected result code for the provided operation.
   *
   * @return  The result returned from processing the requested operation.
   *
   * @throws  AssertionError  If the result code returned by the server does not
   *                          match the expected value.
   */
  public static LDAPResult expectResultCode(final LDAPConnection conn,
                                            final LDAPRequest request,
                                            final ResultCode resultCode)
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

    if (result.getResultCode() != resultCode)
    {
      throw new AssertionError(
           ERR_TEST_PROCESSING_RESULT_CODE_MISMATCH.get(resultCode.toString(),
                request.toString(), result.toString()));
    }

    return result;
  }



  /**
   * Ensures that the provided result includes the specified matched DN value.
   *
   * @param  result     The LDAP result to examine.
   * @param  matchedDN  The expected matched DN value.  It may be {@code null}
   *                    if no matched DN should be present.
   *
   * @throws  LDAPException  If either the provided matched DN or the value
   *                         found in the result could not be parsed as a valid
   *                         DN.
   *
   * @throws  AssertionError  If the provided result did not have the expected
   *                          matched DN.
   */
  public static void expectMatchedDN(final LDAPResult result,
                                     final String matchedDN)
         throws LDAPException, AssertionError
  {
    final String foundMatchedDN = result.getMatchedDN();
    if (matchedDN == null)
    {
      if (foundMatchedDN == null)
      {
        return;
      }
      else
      {
        throw new AssertionError(ERR_TEST_RESULT_UNEXPECTED_MATCHED_DN.get(
             result.toString()));
      }
    }
    else if (foundMatchedDN == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MATCHED_DN_MISMATCH.get(
           matchedDN, result.toString()));
    }

    final DN parsedExpected = new DN(matchedDN);
    final DN parsedFound    = new DN(foundMatchedDN);
    if (! parsedExpected.equals(parsedFound))
    {
      throw new AssertionError(ERR_TEST_RESULT_MATCHED_DN_MISMATCH.get(
           matchedDN, result.toString()));
    }
  }



  /**
   * Ensures that the provided LDAP exception includes the specified matched DN
   * value.
   *
   * @param  exception  The LDAP exception to examine.
   * @param  matchedDN  The expected matched DN value.  It may be {@code null}
   *                    if no matched DN should be present.
   *
   * @throws  LDAPException  If either the provided matched DN or the value
   *                         found in the exception could not be parsed as a
   *                         valid DN.
   *
   * @throws  AssertionError  If the provided result did not have the expected
   *                          matched DN.
   */
  public static void expectMatchedDN(final LDAPException exception,
                                     final String matchedDN)
         throws LDAPException, AssertionError
  {
    final String foundMatchedDN = exception.getMatchedDN();
    if (matchedDN == null)
    {
      if (foundMatchedDN == null)
      {
        return;
      }
      else
      {
        throw new AssertionError(ERR_TEST_RESULT_UNEXPECTED_MATCHED_DN.get(
             StaticUtils.getExceptionMessage(exception)));
      }
    }
    else if (foundMatchedDN == null)
    {
      throw new AssertionError(ERR_TEST_RESULT_MATCHED_DN_MISMATCH.get(
           matchedDN, StaticUtils.getExceptionMessage(exception)));
    }

    final DN parsedExpected = new DN(matchedDN);
    final DN parsedFound    = new DN(foundMatchedDN);
    if (! parsedExpected.equals(parsedFound))
    {
      throw new AssertionError(ERR_TEST_RESULT_MATCHED_DN_MISMATCH.get(
           matchedDN, StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Ensures that the provided result includes one or more referral URLs.
   *
   * @param  result  The LDAP result to examine.
   *
   * @throws  AssertionError  If the provided result did not have any referral
   *                          URLs.
   */
  public static void expectReferral(final LDAPResult result)
         throws AssertionError
  {
    final String[] refs = result.getReferralURLs();
    if ((refs == null) || (refs.length == 0))
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_REFERRAL.get(
           result.toString()));
    }
  }



  /**
   * Ensures that the provided LDAP exception includes one or more referral
   * URLs.
   *
   * @param  exception  The LDAP exception to examine.
   *
   * @throws  AssertionError  If the provided exception did not have any
   *                          referral URLs.
   */
  public static void expectReferral(final LDAPException exception)
         throws AssertionError
  {
    final String[] refs = exception.getReferralURLs();
    if ((refs == null) || (refs.length == 0))
    {
      throw new AssertionError(ERR_TEST_RESULT_MISSING_REFERRAL.get(
           StaticUtils.getExceptionMessage(exception)));
    }
  }



  /**
   * Ensures that the provided result includes a response control with the
   * specified OID.
   *
   * @param  result  The LDAP result to examine.
   * @param  oid     The OID of the expected response control.
   *
   * @return  The first control found with the provided OID.
   *
   * @throws  AssertionError  If the provided result did not have a response
   *                          control with a given OID.
   */
  public static Control expectResponseControl(final LDAPResult result,
                                              final String oid)
         throws AssertionError
  {
    for (final Control c : result.getResponseControls())
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    throw new AssertionError(ERR_TEST_RESULT_MISSING_CONTROL.get(oid,
         result.toString()));
  }



  /**
   * Ensures that the provided LDAP exception includes a response control with
   * the specified OID.
   *
   * @param  exception  The LDAP result to examine.
   * @param  oid     The OID of the expected response control.
   *
   * @return  The first control found with the provided OID.
   *
   * @throws  AssertionError  If the provided result did not have a response
   *                          control with a given OID.
   */
  public static Control expectResponseControl(final LDAPException exception,
                                              final String oid)
         throws AssertionError
  {
    for (final Control c : exception.getResponseControls())
    {
      if (c.getOID().equals(oid))
      {
        return c;
      }
    }

    throw new AssertionError(ERR_TEST_RESULT_MISSING_CONTROL.get(oid,
         StaticUtils.getExceptionMessage(exception)));
  }
}
