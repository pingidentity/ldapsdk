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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.LinkedList;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JoinedEntry} class.
 */
public class JoinedEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Performs a set of test cases with a joined entry that does not contain any
   * nested results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoNestedResults()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    JoinedEntry e = new JoinedEntry(entry, null);
    e = JoinedEntry.decode(e.encode());

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(e.getAttributes());
    assertEquals(e.getAttributes().size(), 2);

    assertNotNull(e.getNestedJoinResults());
    assertTrue(e.getNestedJoinResults().isEmpty());

    assertNotNull(e.toString());
  }



  /**
   * Performs a set of test cases with a joined entry that has a single level of
   * nested results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleLevelNesting()
         throws Exception
  {
    LinkedList<Attribute> nestedAttrs = new LinkedList<Attribute>();
    nestedAttrs.add(new Attribute("objectClass", "top", "organizationalUnit"));
    nestedAttrs.add(new Attribute("ou", "nested1"));

    LinkedList<JoinedEntry> nestedEntries = new LinkedList<JoinedEntry>();
    nestedEntries.add(new JoinedEntry("ou=nested1,dc=example,dc=com",
         nestedAttrs, new LinkedList<JoinedEntry>()));

    nestedAttrs = new LinkedList<Attribute>();
    nestedAttrs.add(new Attribute("objectClass", "top", "organizationalUnit"));
    nestedAttrs.add(new Attribute("ou", "nested2"));
    nestedEntries.add(new JoinedEntry("ou=nested2,dc=example,dc=com",
         nestedAttrs, new LinkedList<JoinedEntry>()));


    LinkedList<Attribute> attrList = new LinkedList<Attribute>();
    attrList.add(new Attribute("objectClass", "top", "domain"));
    attrList.add(new Attribute("dc", "example"));

    JoinedEntry e =
         new JoinedEntry("dc=example,dc=com", attrList, nestedEntries);
    e = JoinedEntry.decode(e.encode());

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
                 new DN("dc=example,dc=com"));

    assertNotNull(e.getAttributes());
    assertEquals(e.getAttributes().size(), 2);

    assertNotNull(e.getNestedJoinResults());
    assertFalse(e.getNestedJoinResults().isEmpty());
    assertEquals(e.getNestedJoinResults().size(), 2);
    for (JoinedEntry je : e.getNestedJoinResults())
    {
      assertNotNull(je.getNestedJoinResults());
      assertTrue(je.getNestedJoinResults().isEmpty());
    }

    assertNotNull(e.toString());
  }



  /**
   * Performs a set of test cases with a joined entry that has multiple levels
   * of nested results.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultiLevelNesting()
         throws Exception
  {
    LinkedList<Attribute> deepestAttrs = new LinkedList<Attribute>();
    deepestAttrs.add(new Attribute("objectClass", "top", "organizationalUnit"));
    deepestAttrs.add(new Attribute("ou", "deepest"));

    LinkedList<JoinedEntry> deepestEntries = new LinkedList<JoinedEntry>();
    deepestEntries.add(new JoinedEntry("ou=deepest,dc=example,dc=com",
         deepestAttrs, new LinkedList<JoinedEntry>()));


    LinkedList<Attribute> deeperAttrs = new LinkedList<Attribute>();
    deeperAttrs.add(new Attribute("objectClass", "top", "organizationalUnit"));
    deeperAttrs.add(new Attribute("ou", "deeper"));

    LinkedList<JoinedEntry> deeperEntries = new LinkedList<JoinedEntry>();
    deeperEntries.add(new JoinedEntry("ou=deeper,dc=example,dc=com",
         deeperAttrs, deepestEntries));


    LinkedList<Attribute> deepAttrs = new LinkedList<Attribute>();
    deepAttrs.add(new Attribute("objectClass", "top", "organizationalUnit"));
    deepAttrs.add(new Attribute("ou", "deep"));

    JoinedEntry e =
         new JoinedEntry("ou=deep,dc=example,dc=com", deepAttrs, deeperEntries);
    e = JoinedEntry.decode(e.encode());

    assertNotNull(e);

    assertNotNull(e.getDN());
    assertEquals(new DN(e.getDN()),
                 new DN("ou=deep,dc=example,dc=com"));

    assertNotNull(e.getAttributes());
    assertEquals(e.getAttributes().size(), 2);

    assertNotNull(e.getNestedJoinResults());
    assertFalse(e.getNestedJoinResults().isEmpty());
    assertEquals(e.getNestedJoinResults().size(), 1);
    for (JoinedEntry je : e.getNestedJoinResults())
    {
      assertEquals(new DN(je.getDN()),
                   new DN("ou=deeper,dc=example,dc=com"));

      assertNotNull(je.getNestedJoinResults());
      assertFalse(je.getNestedJoinResults().isEmpty());
      assertEquals(je.getNestedJoinResults().size(), 1);
      assertEquals(new DN(je.getNestedJoinResults().get(0).getDN()),
                   new DN("ou=deepest,dc=example,dc=com"));
    }

    assertNotNull(e.toString());
  }



  /**
   * Tests the behavior when attempting to decode a malformed joined entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeMalformed()
         throws Exception
  {
    JoinedEntry.decode(new ASN1Element((byte) 0x00, new byte[1]));
  }
}
