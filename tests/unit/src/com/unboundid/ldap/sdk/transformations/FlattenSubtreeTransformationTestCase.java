/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for flatten subtree transformations.
 */
public final class FlattenSubtreeTransformationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when ignoring all omitted RDNs and not excluding any
   * entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalFlattening()
         throws Exception
  {
    final FlattenSubtreeTransformation t = new FlattenSubtreeTransformation(
         null, new DN("ou=People,dc=example,dc=com"), false, false, null);

    Entry e = t.transformEntry(null);
    assertNull(e);

    e = t.transformEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    e = t.transformEntry(
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));

    e = t.transformEntry(
         new Entry(
              "dn: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: uid=john.doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.transformEntry(
         new Entry(
              "dn: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub1,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));

    e = t.transformEntry(
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East," +
                   "ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,ou=People,dc=example,dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when adding omitted RDN name-value pairs to the entry.
   * The original RDN will still be left unchanged.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddOmittedRDNAttributesToEntry()
         throws Exception
  {
    final FlattenSubtreeTransformation t = new FlattenSubtreeTransformation(
         null, new DN("ou=People,dc=example,dc=com"), true, false, null);

    Entry e = t.translate(null, 0);
    assertNull(e);

    e = t.translate(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    e = t.translate(
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));

    e = t.translate(
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));

    e = t.translate(
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));

    e = t.translate(
         new Entry(
              "dn: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: uid=john.doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe",
              "ou: East"));

    e = t.translate(
         new Entry(
              "dn: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe",
              "ou: East"));

    e = t.translate(
         new Entry(
              "dn: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub1,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1",
              "uid: john.doe",
              "ou: East"));

    e = t.translate(
         new Entry(
              "dn: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b",
              "givenName: John",
              "sn: Doe",
              "ou: East"));

    e = t.translate(
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));

    e = t.translate(
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East," +
                   "ou=People,dc=example,dc=com"),
         0);
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,ou=People,dc=example,dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when adding omitted RDN name-value pairs to the original
   * RDN.  The omitted RDN attributes will not be added to the entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddOmittedRDNAttributesToRDN()
         throws Exception
  {
    final FlattenSubtreeTransformation t = new FlattenSubtreeTransformation(
         null, new DN("ou=People,dc=example,dc=com"), false, true, null);

    Entry e = t.translateEntryToWrite(null);
    assertNull(e);

    e = t.translateEntryToWrite(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: uid=john.doe+ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: givenName=John+sn=Doe+ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub1+uid=john.doe+ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub2a+ou=sub2b+givenName=John+sn=Doe+ou=East,ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));

    e = t.translateEntryToWrite(
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East," +
                   "ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe+ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe+ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1+uid=john.doe+ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b+givenName=John+sn=Doe+ou=East," +
                   "ou=People,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when ignoring all omitted RDNs but excluding entries
   * with the organizationalUnit object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeOrganizationalUnits()
         throws Exception
  {
    final FlattenSubtreeTransformation t = new FlattenSubtreeTransformation(
         null, new DN("ou=People,dc=example,dc=com"), false, false,
         Filter.createEqualityFilter("objectClass", "organizationalUnit"));

    Entry e = t.transformEntry(null);
    assertNull(e);

    e = t.transformEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    e = t.transformEntry(
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));
    assertNull(e);

    e = t.transformEntry(
         new Entry(
              "dn: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: uid=john.doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.transformEntry(
         new Entry(
              "dn: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));
    assertNull(e);

    e = t.transformEntry(
         new Entry(
              "dn: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));
    assertNull(e);

    e = t.transformEntry(
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));

    e = t.transformEntry(
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East," +
                   "ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,ou=People,dc=example,dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com"));
  }



  /**
   * Tests the behavior when attempting to use the transformation with a
   * filter that isn't supported by the LDAP SDK.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testExcludeWithUnsupportedFilter()
         throws Exception
  {
    final FlattenSubtreeTransformation t = new FlattenSubtreeTransformation(
         null, new DN("ou=People,dc=example,dc=com"), false, false,
         Filter.createApproximateMatchFilter("foo", "bar"));

    Entry e = t.transformEntry(null);
    assertNull(e);

    e = t.transformEntry(
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: dc=example,dc=com",
              "objectClass: top",
              "objectClass: domain",
              "dc: example"));

    e = t.transformEntry(
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: malformed,dc=example,dc=com",
              "objectClass: top",
              "objectClass: whoKnows",
              "cn: malformed"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: People"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: East"));

    e = t.transformEntry(
         new Entry(
              "dn: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: uid=john.doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.transformEntry(
         new Entry(
              "dn: givenName=John+sn=Doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: person",
              "objectClass: organizationalPerson",
              "objectClass: inetOrgPerson",
              "uid: john.doe",
              "givenName: John",
              "sn: Doe",
              "cn: John Doe"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub1,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub1"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East,ou=People," +
                   "dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: sub2a",
              "ou: sub2b"));

    e = t.transformEntry(
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: organizationalUnit",
              "ou: Groups"));

    e = t.transformEntry(
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=East,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,uid=john.doe,ou=East,ou=People,dc=example," +
                   "dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,givenName=John+sn=Doe,ou=East," +
                   "ou=People,dc=example,dc=com"));
    assertNotNull(e);
    assertEquals(e,
         new Entry(
              "dn: cn=Group 1,ou=Groups,dc=example,dc=com",
              "objectClass: top",
              "objectClass: groupOfNames",
              "cn: Group 1",
              "member: not a DN 1",
              "member: uid=john.doe,ou=People,dc=example,dc=com",
              "member: ou=People,dc=example,dc=com",
              "member: givenName=John+sn=Doe,ou=People,dc=example,dc=com",
              "member: uid=admin,dc=example,dc=com",
              "member: ou=sub1,ou=People,dc=example,dc=com",
              "member: not a DN 2",
              "member: ou=sub2a+ou=sub2b,ou=People,dc=example,dc=com"));
  }
}
