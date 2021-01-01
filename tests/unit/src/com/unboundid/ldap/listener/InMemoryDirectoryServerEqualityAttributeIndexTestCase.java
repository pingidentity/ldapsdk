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
package com.unboundid.ldap.listener;



import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.TreeSet;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the
 * InMemoryDirectoryServerEqualityAttributeIndex class.
 */
public final class InMemoryDirectoryServerEqualityAttributeIndexTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to create an index when no schema is
   * available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testIndexWithoutSchema()
         throws Exception
  {
    new InMemoryDirectoryServerEqualityAttributeIndex("uid", null);
  }



  /**
   * Tests the behavior when trying to create an index for an undefined
   * attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testIndexWithUndefinedAttribute()
         throws Exception
  {
    new InMemoryDirectoryServerEqualityAttributeIndex("undefined",
         Schema.getDefaultStandardSchema());
  }



  /**
   * Tests the behavior when interacting with entries that don't have any
   * values for the associated attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIndexEntryWithoutAttribute()
         throws Exception
  {
    final InMemoryDirectoryServerEqualityAttributeIndex index =
         new InMemoryDirectoryServerEqualityAttributeIndex("uid",
              Schema.getDefaultStandardSchema());

    final ArrayList<Entry> entryList = new ArrayList<Entry>();
    for (int i=0; i < 10;  i++)
    {
      entryList.add(new Entry(
           "dn: ou=Test " + i + ",dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: Test " + i));
    }

    for (final Entry e : entryList)
    {
      index.processAdd(e);
    }

    Map<ASN1OctetString,TreeSet<DN>> indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertTrue(indexMap.isEmpty());

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    for (int i=0; i < 10;  i++)
    {
      assertEmpty(index.getMatchingEntries(
           new ASN1OctetString("Test " + i)));
    }

    for (final Entry e : entryList)
    {
      index.processDelete(e);
    }

    indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertTrue(indexMap.isEmpty());

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    for (int i=0; i < 10;  i++)
    {
      assertEmpty(index.getMatchingEntries(
           new ASN1OctetString("Test " + i)));
    }
  }



  /**
   * Tests the behavior when interacting with entries that have a single value
   * for the indexed attribute, and all the values are unique.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIndexEntrySingleUniqueValue()
         throws Exception
  {
    final InMemoryDirectoryServerEqualityAttributeIndex index =
         new InMemoryDirectoryServerEqualityAttributeIndex("ou",
              Schema.getDefaultStandardSchema());

    final ArrayList<Entry> entryList = new ArrayList<Entry>();
    for (int i=0; i < 10;  i++)
    {
      entryList.add(new Entry(
           "dn: ou=Test " + i + ",dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: Test " + i));
    }

    for (final Entry e : entryList)
    {
      index.processAdd(e);
    }

    Map<ASN1OctetString,TreeSet<DN>> indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertFalse(indexMap.isEmpty());
    assertEquals(indexMap.size(), 10);

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    for (int i=0; i < 10;  i++)
    {
      final ASN1OctetString v = new ASN1OctetString("Test " + i);

      assertNotNull(index.getMatchingEntries(v));
      assertFalse(index.getMatchingEntries(v).isEmpty());
      assertEquals(index.getMatchingEntries(v).size(), 1);
      assertEquals(index.getMatchingEntries(v).iterator().next(),
           new DN("ou=Test " + i + ",dc=example,dc=com"));
    }

    for (final Entry e : entryList)
    {
      index.processDelete(e);
    }

    indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertTrue(indexMap.isEmpty());

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    for (int i=0; i < 10;  i++)
    {
      assertEmpty(index.getMatchingEntries(
           new ASN1OctetString("Test " + i)));
    }
  }



  /**
   * Tests the behavior when interacting with entries that have a single value
   * for the indexed attribute, but multiple entries all have that same value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIndexEntrySingleCommonValue()
         throws Exception
  {
    final InMemoryDirectoryServerEqualityAttributeIndex index =
         new InMemoryDirectoryServerEqualityAttributeIndex("description",
              Schema.getDefaultStandardSchema());

    final ArrayList<Entry> entryList = new ArrayList<Entry>();
    for (int i=0; i < 10;  i++)
    {
      entryList.add(new Entry(
           "dn: ou=Test " + i + ",dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: Test " + i,
           "description: foo"));
    }

    for (final Entry e : entryList)
    {
      index.processAdd(e);
    }

    Map<ASN1OctetString,TreeSet<DN>> indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertFalse(indexMap.isEmpty());
    assertEquals(indexMap.size(), 1);

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    assertNotNull(index.getMatchingEntries(new ASN1OctetString("foo")));
    assertFalse(index.getMatchingEntries(new ASN1OctetString("foo")).isEmpty());
    assertEquals(index.getMatchingEntries(new ASN1OctetString("foo")).size(),
         10);

    for (int i=0; i < 10;  i++)
    {
      assertTrue(index.getMatchingEntries(new ASN1OctetString("foo")).contains(
           new DN("ou=Test " + i + ",dc=example,dc=com")));
    }

    for (int i=0; i < 10;  i++)
    {
      index.processDelete(entryList.get(i));

      if (i == 9)
      {
        assertEmpty(index.getMatchingEntries(new ASN1OctetString("foo")));
      }
      else
      {
        assertNotNull(index.getMatchingEntries(new ASN1OctetString("foo")));
        assertFalse(index.getMatchingEntries(new ASN1OctetString("foo")).
             isEmpty());
      }
    }

    indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertTrue(indexMap.isEmpty());

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    for (int i=0; i < 10;  i++)
    {
      assertEmpty(index.getMatchingEntries(
           new ASN1OctetString("Test " + i)));
    }
  }



  /**
   * Tests the behavior when interacting with entries that have a single value
   * for the indexed attribute, and all the values are unique.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testIndexEntryMultipleValues()
         throws Exception
  {
    final InMemoryDirectoryServerEqualityAttributeIndex index =
         new InMemoryDirectoryServerEqualityAttributeIndex("description",
              Schema.getDefaultStandardSchema());

    final Entry e = new Entry(
         "dn: ou=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: Test",
         "description: foo",
         "description: bar");

    index.processAdd(e);

    Map<ASN1OctetString,TreeSet<DN>> indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertFalse(indexMap.isEmpty());
    assertEquals(indexMap.size(), 2);

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    assertNotNull(index.getMatchingEntries(new ASN1OctetString("foo")));
    assertTrue(index.getMatchingEntries(new ASN1OctetString("foo")).contains(
         new DN("ou=Test,dc=example,dc=com")));

    assertNotNull(index.getMatchingEntries(new ASN1OctetString("bar")));
    assertTrue(index.getMatchingEntries(new ASN1OctetString("bar")).contains(
         new DN("ou=Test,dc=example,dc=com")));

    index.processDelete(e);

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("top")));
    assertEmpty(index.getMatchingEntries(
         new ASN1OctetString("organizationalUnit")));

    assertEmpty(index.getMatchingEntries(new ASN1OctetString("foo")));
    assertEmpty(index.getMatchingEntries(new ASN1OctetString("bar")));

    indexMap = index.copyMap();
    assertNotNull(indexMap);
    assertTrue(indexMap.isEmpty());
  }



  /**
   * Asserts that the provided collection is not {@code null} but is empty.
   *
   * @param  c  The collection to examine.
   *
   * @throws  AssertionError  If the collection is {@code null} or non-empty.
   */
  private static void assertEmpty(final Collection<?> c)
          throws AssertionError
  {
    assertNotNull(c);
    assertTrue(c.isEmpty());
  }
}
