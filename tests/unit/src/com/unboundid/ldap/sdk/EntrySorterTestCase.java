/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.SortedSet;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.controls.SortKey;
import com.unboundid.ldap.sdk.schema.Schema;



/**
 * This class provides a set of test cases for the {@code EntrySorter} class.
 */
public class EntrySorterTestCase
       extends LDAPSDKTestCase
{
  // The list of entries to be sorted.
  private LinkedList<Entry> entryList;

  // The schema to use, if available.
  private Schema schema;



  /**
   * Create the list of test entries and retrieve the server schema, if
   * possible.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    entryList = new LinkedList<Entry>();
    entryList.add(new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2"));

    entryList.add(new Entry(
         "dn: ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalUnit",
         "ou: People"));

    entryList.add(new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1"));

    entryList.add(new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example"));

    schema = getTestDS().getSchema();
  }



  /**
   * Performs a test using the first constructor, which only provides
   * hierarchical ordering.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with a single sort key and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleKeyHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, new SortKey("uid"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with no sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2NoKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true);
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with a single sort key in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleKeyReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, new SortKey("uid", true));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with a single sort key and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleKeyNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false, new SortKey("uid"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with multiple sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, new SortKey("givenName"),
                                              new SortKey("sn"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with multiple sort keys in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleKeysReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true,
                                              new SortKey("givenName", true),
                                              new SortKey("sn", true));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the second constructor with multiple sort keys and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleKeysNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false, new SortKey("givenName"),
                                              new SortKey("sn"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with a single sort key and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleKeyHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema, new SortKey("uid"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with no sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3NoKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema);
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with a single sort key in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleKeyReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
                                              new SortKey("uid", true));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with a single sort key and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleKeyNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false, schema,
                                              new SortKey("uid"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with multiple sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultipleKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
                                              new SortKey("givenName"),
                                              new SortKey("sn"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with multiple sort keys in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultipleKeysReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
                                              new SortKey("givenName", true),
                                              new SortKey("sn", true));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the third constructor with multiple sort keys and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultipleKeysNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false, schema,
                                              new SortKey("givenName"),
                                              new SortKey("sn"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with a single sort key and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4SingleKeyHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true,
         Arrays.asList(new SortKey("uid")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with a {@code null} list of
   * sort keys and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NullKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, (LinkedList<SortKey>) null);
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with no sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4NoKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, Arrays.<SortKey>asList());
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with a single sort key in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructo42SingleKeyReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true,
         Arrays.asList(new SortKey("uid", true)));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with a single sort key and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4SingleKeyNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false,
         Arrays.asList(new SortKey("uid")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with multiple sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultipleKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true,
         Arrays.asList(new SortKey("givenName"), new SortKey("sn")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with multiple sort keys in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultipleKeysReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true,
         Arrays.asList(new SortKey("givenName", true),
                       new SortKey("sn", true)));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fourth constructor with multiple sort keys and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultipleKeysNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false,
         Arrays.asList(new SortKey("givenName"), new SortKey("sn")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with a single sort key and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5SingleKeyHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
         Arrays.asList(new SortKey("uid")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with no sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NoKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
                                              Arrays.<SortKey>asList());
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with a {@code null} sort keys
   * and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5NullKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
                                              (LinkedList<SortKey>) null);
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with a single sort key in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5SingleKeyReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
         Arrays.asList(new SortKey("uid", true)));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with a single sort key and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5SingleKeyNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false, schema,
         Arrays.asList(new SortKey("uid")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with multiple sort keys and
   * hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5MultipleKeysHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
         Arrays.asList(new SortKey("givenName"), new SortKey("sn")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with multiple sort keys in
   * reverse order and hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5MultipleKeysReverseHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(true, schema,
         Arrays.asList(new SortKey("givenName", true),
                       new SortKey("sn", true)));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test using the fifth constructor with multiple sort keys and
   * not using hierarchical sorting.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5MultipleKeysNotHierarchical()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter(false, schema,
         Arrays.asList(new SortKey("givenName"), new SortKey("sn")));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    SortedSet<Entry> sortedEntries = entrySorter.sort(entryList);

    Iterator<Entry> iterator = sortedEntries.iterator();

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.1,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("uid=child.2,ou=People,dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("dc=example,dc=com"));

    assertTrue(iterator.hasNext());
    assertEquals(iterator.next().getParsedDN(),
                 new DN("ou=People,dc=example,dc=com"));

    assertFalse(iterator.hasNext());
  }



  /**
   * Performs a test with a single sort attribute that does not exist in any of
   * the entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortNoSuchAttribute()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2");

    EntrySorter entrySorter = new EntrySorter(false,
                                              new SortKey("description"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) < 0);
  }



  /**
   * Performs a test with multiple sort attributes in which the first does not
   * exist in any of the entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortMultipleNoSuchFirstAttribute()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2");

    EntrySorter entrySorter = new EntrySorter(false,
                                              new SortKey("description"),
                                              new SortKey("uid"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) < 0);
  }



  /**
   * Performs a test with multiple sort attributes in which the none of the
   * attributes exist in either entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortMultipleNoSuchAnyAttribute()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2");

    EntrySorter entrySorter = new EntrySorter(false,
                                              new SortKey("description"),
                                              new SortKey("displayName"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) < 0);
  }



  /**
   * Performs a test in which only the first entry has the sort attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortAttributeOnlyInFirst()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1",
         "description: test");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2");

    EntrySorter entrySorter = new EntrySorter(false,
                                              new SortKey("description"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) < 0);
  }



  /**
   * Performs a test in which only the second entry has the sort attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortAttributeOnlyInSecond()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2",
         "description: test");

    EntrySorter entrySorter = new EntrySorter(false,
                                              new SortKey("description"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) > 0);
  }



  /**
   * Performs a test in which there are multiple values for the target attribute
   * and the sort is to be done in ascending order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortMultiValuedAscending()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1",
         "description: f 1",
         "description: a 1",
         "description: z 1",
         "description: m 1");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2",
         "description: f 2",
         "description: a 2",
         "description: z 2",
         "description: m 2");

    EntrySorter entrySorter = new EntrySorter(false,
                                              new SortKey("description"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) < 0);
  }



  /**
   * Performs a test in which there are multiple values for the target attribute
   * and the sort is to be done in descending order.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortMultiValuedDescending()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1",
         "description: f 1",
         "description: a 1",
         "description: z 1",
         "description: m 1");

    Entry e2 = new Entry(
         "dn: uid=child.2,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2",
         "description: f 2",
         "description: a 2",
         "description: z 2",
         "description: m 2");

    EntrySorter entrySorter = new EntrySorter(false,
         new SortKey("description", true));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) > 0);
  }



  /**
   * Performs a test in which the second entry has a malformed DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSortMalformedDN()
         throws Exception
  {
    Entry e1 = new Entry(
         "dn: uid=child.1,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.1",
         "givenName: Child",
         "sn: 1",
         "cn: Child 1");

    Entry e2 = new Entry(
         "dn: malformed",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: child.2",
         "givenName: Child",
         "sn: 2",
         "cn: Child 2");

    EntrySorter entrySorter = new EntrySorter(true, new SortKey("givenName"));
    entrySorter.hashCode();
    assertNotNull(entrySorter.toString());

    assertTrue(entrySorter.compare(e1, e2) > 0);
  }



  /**
   * Tests the {@code equals} method with a {@code null} object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();

    EntrySorter s = null;
    assertFalse(entrySorter.equals(s));
  }



  /**
   * Tests the {@code equals} method with the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();

    assertTrue(entrySorter.equals(entrySorter));
  }



  /**
   * Tests the {@code equals} method an object that is not an entry sorter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNotEntrySorter()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();

    assertFalse(entrySorter.equals("foo"));
  }



  /**
   * Tests the {@code equals} method with an equivalent entry sorter.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsEquivalent()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();

    assertTrue(entrySorter.equals(new EntrySorter(true)));
  }



  /**
   * Tests the {@code equals} method with an entry sorter that differs based on
   * whether to sort by hierarchy.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDiffersBySortByHierarchy()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();

    assertFalse(entrySorter.equals(new EntrySorter(false)));
  }



  /**
   * Tests the {@code equals} method with an entry sorter that differs based on
   * the set of sort keys.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsDiffersBySortKeys()
         throws Exception
  {
    EntrySorter entrySorter = new EntrySorter();

    assertFalse(entrySorter.equals(new EntrySorter(true, new SortKey("cn"))));
  }
}
