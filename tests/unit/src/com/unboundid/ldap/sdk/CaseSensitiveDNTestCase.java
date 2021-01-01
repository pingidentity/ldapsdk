/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.io.File;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFReader;



/**
 * This class provides test coverage to ensure that DNs will properly work when
 * an RDN attribute is configured with a case-exact matching.
 */
public final class CaseSensitiveDNTestCase
       extends LDAPSDKTestCase
{
  // The schema to use for testing.
  private Schema schema = null;



  /**
   * Creates a schema to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    schema = new Schema(new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubEntry",
         "objectClass: subschema",
         "cn: schema",
         "attributeTypes: ( 2.5.4.0 " +
              "NAME 'objectClass' " +
              "EQUALITY objectIdentifierMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "attributeTypes: ( 0.9.2342.19200300.100.1.25 " +
              "NAME 'dc' " +
              "EQUALITY caseIgnoreIA5Match " +
              "SUBSTR caseIgnoreIA5SubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 " +
              "SINGLE-VALUE )",
         "attributeTypes: ( 1.2.3.4 " +
              "NAME 'testATWithOMR' " +
              "EQUALITY caseExactMatch " +
              "ORDERING caseExactOrderingMatch " +
              "SUBSTR caseExactSubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2.3.5 " +
              "NAME 'testATWithoutOMR' " +
              "EQUALITY caseExactMatch " +
              "SUBSTR caseExactSubstringsMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.3.6.1.1.20 " +
              "NAME 'entryDN' " +
              "EQUALITY distinguishedNameMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 " +
              "SINGLE-VALUE NO-USER-MODIFICATION " +
              "USAGE directoryOperation )",
         "objectClasses: ( 2.5.6.0 " +
              "NAME 'top' " +
              "ABSTRACT " +
              "MUST objectClass )",
         "objectClasses: ( 0.9.2342.19200300.100.4.13 " +
              "NAME 'domain' " +
              "SUP top " +
              "STRUCTURAL " +
              "MUST dc )",
         "objectClasses: ( 1.2.3.6 " +
              "NAME 'testOC' " +
              "SUP top " +
              "STRUCTURAL " +
              "MAY ( testATWithOMR $" +
              "      testATWithoutOMR ) )"));
  }



  /**
   * Tests to ensure that an attribute will behave properly when configured
   * with case-sensitive matching and an explicit ordering matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeWithOMR()
         throws Exception
  {
    final Attribute a1 = new Attribute("testATWithOMR", schema, "test");
    assertTrue(a1.equals(a1));
    assertTrue(a1.equals(a1));

    final Attribute a2 = new Attribute("testATWithOMR", schema, "test");
    assertTrue(a1.equals(a2));

    final Attribute a3 = new Attribute("testATWithOMR", schema, "Test");
    assertFalse(a1.equals(a3));
  }



  /**
   * Tests to ensure that an attribute will behave properly when configured
   * with case-sensitive matching and no explicit ordering matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAttributeWithoutOMR()
         throws Exception
  {
    final Attribute a1 = new Attribute("testATWithoutOMR", schema, "test");
    assertTrue(a1.equals(a1));
    assertTrue(a1.equals(a1));

    final Attribute a2 = new Attribute("testATWithoutOMR", schema, "test");
    assertTrue(a1.equals(a2));

    final Attribute a3 = new Attribute("testATWithoutOMR", schema, "Test");
    assertFalse(a1.equals(a3));
  }



  /**
   * Tests to ensure that a DN will behave properly when configured with
   * case-sensitive matching and an explicit ordering matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNWithOMR()
         throws Exception
  {
    final DN dn1 = new DN("testATWithOMR=test,dc=example,dc=com", schema);
    assertTrue(dn1.equals(dn1));
    assertTrue(dn1.compareTo(dn1) == 0);

    final DN dn2 = new DN("testATWithOMR=test,dc=example,dc=com", schema);
    assertTrue(dn1.equals(dn2));
    assertTrue(dn1.compareTo(dn2) == 0);

    final DN dn3 = new DN("testATWithOMR=Test,dc=example,dc=com", schema);
    assertFalse(dn1.equals(dn3));
    assertFalse(dn1.compareTo(dn3) == 0);
  }



  /**
   * Tests to ensure that a DN will behave properly when configured with
   * case-sensitive matching and no explicit ordering matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNWithoutOMR()
         throws Exception
  {
    final DN dn1 = new DN("testATWithoutOMR=test,dc=example,dc=com", schema);
    assertTrue(dn1.equals(dn1));
    assertTrue(dn1.compareTo(dn1) == 0);

    final DN dn2 = new DN("testATWithoutOMR=test,dc=example,dc=com", schema);
    assertTrue(dn1.equals(dn2));
    assertTrue(dn1.compareTo(dn2) == 0);

    final DN dn3 = new DN("testATWithoutOMR=Test,dc=example,dc=com", schema);
    assertFalse(dn1.equals(dn3));
    assertFalse(dn1.compareTo(dn3) == 0);
  }



  /**
   * Tests to ensure that a DN with a case-sensitive RDN attribute (with an
   * explicit ordering matching rule) will behave properly when it is created as
   * part of an entry created from its LDIF representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryFromLDIFLinesWithOMR()
         throws Exception
  {
    final Entry e1 = new Entry(schema,
         "dn: testATWithOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithOMR: test");
    assertTrue(e1.equals(e1));
    assertTrue(e1.getParsedDN().equals(e1.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e1.getParsedDN()) == 0);

    final Entry e2 = new Entry(schema,
         "dn: testATWithOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithOMR: test");
    assertTrue(e1.equals(e2));
    assertTrue(e1.getParsedDN().equals(e2.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e2.getParsedDN()) == 0);

    final Entry e3 = new Entry(schema,
         "dn: testATWithOMR=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithOMR: Test");
    assertFalse(e1.equals(e3));
    assertFalse(e1.getParsedDN().equals(e3.getParsedDN()));
    assertFalse(e1.getParsedDN().compareTo(e3.getParsedDN()) == 0);
  }



  /**
   * Tests to ensure that a DN with a case-sensitive RDN attribute (with no
   * explicit ordering matching rule) will behave properly when it is created as
   * part of an entry created from its LDIF representation.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryFromLDIFLinesWithoutOMR()
         throws Exception
  {
    final Entry e1 = new Entry(schema,
         "dn: testATWithoutOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithoutOMR: test");
    assertTrue(e1.equals(e1));
    assertTrue(e1.getParsedDN().equals(e1.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e1.getParsedDN()) == 0);

    final Entry e2 = new Entry(schema,
         "dn: testATWithoutOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithoutOMR: test");
    assertTrue(e1.equals(e2));
    assertTrue(e1.getParsedDN().equals(e2.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e2.getParsedDN()) == 0);

    final Entry e3 = new Entry(schema,
         "dn: testATWithoutOMR=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithoutOMR: Test");
    assertFalse(e1.equals(e3));
    assertFalse(e1.getParsedDN().equals(e3.getParsedDN()));
    assertFalse(e1.getParsedDN().compareTo(e3.getParsedDN()) == 0);
  }



  /**
   * Tests to ensure that a DN with a case-sensitive RDN attribute (with an
   * explicit ordering matching rule) will behave properly when it is created
   * with a DN and set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryFromDNAndAttributesWithOMR()
         throws Exception
  {
    final Entry e1 = new Entry("testATWithOMR=test,dc=example,dc=com", schema,
         new Attribute("objectClass", schema, "top", "testOC"),
         new Attribute("testATWithOMR", schema, "test"));
    assertTrue(e1.equals(e1));
    assertTrue(e1.getParsedDN().equals(e1.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e1.getParsedDN()) == 0);

    final Entry e2 = new Entry("testATWithOMR=test,dc=example,dc=com", schema,
         new Attribute("objectClass", schema, "top", "testOC"),
         new Attribute("testATWithOMR", schema, "test"));
    assertTrue(e1.equals(e2));
    assertTrue(e1.getParsedDN().equals(e2.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e2.getParsedDN()) == 0);

    final Entry e3 = new Entry("testATWithOMR=Test,dc=example,dc=com", schema,
         new Attribute("objectClass", schema, "top", "testOC"),
         new Attribute("testATWithOMR", schema, "Test"));
    assertFalse(e1.equals(e3));
    assertFalse(e1.getParsedDN().equals(e3.getParsedDN()));
    assertFalse(e1.getParsedDN().compareTo(e3.getParsedDN()) == 0);
  }



  /**
   * Tests to ensure that a DN with a case-sensitive RDN attribute (with no
   * explicit ordering matching rule) will behave properly when it is created
   * with a DN and set of attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryFromDNAndAttributesWithoutOMR()
         throws Exception
  {
    final Entry e1 = new Entry("testATWithoutOMR=test,dc=example,dc=com",
         schema,
         new Attribute("objectClass", schema, "top", "testOC"),
         new Attribute("testATWithoutOMR", schema, "test"));
    assertTrue(e1.equals(e1));
    assertTrue(e1.getParsedDN().equals(e1.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e1.getParsedDN()) == 0);

    final Entry e2 = new Entry("testATWithoutOMR=test,dc=example,dc=com",
         schema,
         new Attribute("objectClass", schema, "top", "testOC"),
         new Attribute("testATWithoutOMR", schema, "test"));
    assertTrue(e1.equals(e2));
    assertTrue(e1.getParsedDN().equals(e2.getParsedDN()));
    assertTrue(e1.getParsedDN().compareTo(e2.getParsedDN()) == 0);

    final Entry e3 = new Entry("testATWithoutOMR=Test,dc=example,dc=com",
         schema,
         new Attribute("objectClass", schema, "top", "testOC"),
         new Attribute("testATWithoutOMR", schema, "Test"));
    assertFalse(e1.equals(e3));
    assertFalse(e1.getParsedDN().equals(e3.getParsedDN()));
    assertFalse(e1.getParsedDN().compareTo(e3.getParsedDN()) == 0);
  }



  /**
   * Tests to ensure that a DN with a case-sensitive RDN attribute (with an
   * explicit ordering matching rule) will behave properly when it is read from
   * an LDIF file using an LDIF reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryReadFromLDIFWithOMR()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: testATWithOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithOMR: test",
         "",
         "dn: testATWithOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithOMR: test",
         "",
         "dn: testATWithOMR=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithOMR: Test");

    try (LDIFReader ldifReader = new LDIFReader(ldifFile))
    {
      ldifReader.setSchema(schema);

      final Entry e1 = ldifReader.readEntry();
      assertNotNull(e1);
      assertTrue(e1.equals(e1));
      assertTrue(e1.getParsedDN().equals(e1.getParsedDN()));
      assertTrue(e1.getParsedDN().compareTo(e1.getParsedDN()) == 0);

      final Entry e2 = ldifReader.readEntry();
      assertNotNull(e2);
      assertTrue(e1.equals(e2));
      assertTrue(e1.getParsedDN().equals(e2.getParsedDN()));
      assertTrue(e1.getParsedDN().compareTo(e2.getParsedDN()) == 0);

      final Entry e3 = ldifReader.readEntry();
      assertNotNull(e3);
      assertFalse(e1.equals(e3));
      assertFalse(e1.getParsedDN().equals(e3.getParsedDN()));
      assertFalse(e1.getParsedDN().compareTo(e3.getParsedDN()) == 0);

      assertNull(ldifReader.readEntry());
    }
  }



  /**
   * Tests to ensure that a DN with a case-sensitive RDN attribute (with no
   * explicit ordering matching rule) will behave properly when it is read from
   * an LDIF file using an LDIF reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryReadFromLDIFWithoutOMR()
         throws Exception
  {
    final File ldifFile = createTempFile(
         "dn: testATWithoutOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithoutOMR: test",
         "",
         "dn: testATWithoutOMR=test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithoutOMR: test",
         "",
         "dn: testATWithoutOMR=Test,dc=example,dc=com",
         "objectClass: top",
         "objectClass: testOC",
         "testATWithoutOMR: Test");

    try (LDIFReader ldifReader = new LDIFReader(ldifFile))
    {
      ldifReader.setSchema(schema);

      final Entry e1 = ldifReader.readEntry();
      assertNotNull(e1);
      assertTrue(e1.equals(e1));
      assertTrue(e1.getParsedDN().equals(e1.getParsedDN()));
      assertTrue(e1.getParsedDN().compareTo(e1.getParsedDN()) == 0);

      final Entry e2 = ldifReader.readEntry();
      assertNotNull(e2);
      assertTrue(e1.equals(e2));
      assertTrue(e1.getParsedDN().equals(e2.getParsedDN()));
      assertTrue(e1.getParsedDN().compareTo(e2.getParsedDN()) == 0);

      final Entry e3 = ldifReader.readEntry();
      assertNotNull(e3);
      assertFalse(e1.equals(e3));
      assertFalse(e1.getParsedDN().equals(e3.getParsedDN()));
      assertFalse(e1.getParsedDN().compareTo(e3.getParsedDN()) == 0);

      assertNull(ldifReader.readEntry());
    }
  }



  /**
   * Tests to ensure that the in-memory directory server behaves as expected
   * when dealing with entries that use case-sensitive RDN attributes that have
   * been created with LDAP add operations.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInMemoryDirectoryServerEntriesCreatedByAdd()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setSchema(schema);

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.startListening();

      try (LDAPConnection conn = ds.getConnection())
      {
        conn.add(
             "dn: dc=example,dc=com",
             "objectClass: top",
             "objectClass: domain",
             "dc: example");
        conn.add(
             "dn: testATWithOMR=test,dc=example,dc=com",
             "objectClass: top",
             "objectClass: testOC",
             "testATWithOMR: test");
        conn.add(
             "dn: testATWithoutOMR=test,dc=example,dc=com",
             "objectClass: top",
             "objectClass: testOC",
             "testATWithoutOMR: test");

        assertNotNull(conn.getEntry("testATWithOMR=test,dc=example,dc=com"));
        assertNull(conn.getEntry("testATWithOMR=Test,dc=example,dc=com"));

        assertNotNull(conn.getEntry("testATWithoutOMR=test,dc=example,dc=com"));
        assertNull(conn.getEntry("testATWithoutOMR=Test,dc=example,dc=com"));

        AddRequest addRequest = new AddRequest(
             "dn: testATWithOMR=test,dc=example,dc=com",
             "objectClass: top",
             "objectClass: testOC",
             "testATWithOMR: test");
        assertResultCodeEquals(conn, addRequest,
             ResultCode.ENTRY_ALREADY_EXISTS);

        addRequest = new AddRequest(
             "dn: testATWithoutOMR=test,dc=example,dc=com",
             "objectClass: top",
             "objectClass: testOC",
             "testATWithoutOMR: test");
        assertResultCodeEquals(conn, addRequest,
             ResultCode.ENTRY_ALREADY_EXISTS);

        addRequest = new AddRequest(
             "dn: testATWithOMR=Test,dc=example,dc=com",
             "objectClass: top",
             "objectClass: testOC",
             "testATWithOMR: Test");
        assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);
        assertNotNull(conn.getEntry("testATWithOMR=test,dc=example,dc=com"));
        assertNotNull(conn.getEntry("testATWithOMR=Test,dc=example,dc=com"));

        addRequest = new AddRequest(
             "dn: testATWithoutOMR=Test,dc=example,dc=com",
             "objectClass: top",
             "objectClass: testOC",
             "testATWithoutOMR: Test");
        assertResultCodeEquals(conn, addRequest, ResultCode.SUCCESS);
        assertNotNull(conn.getEntry("testATWithoutOMR=test,dc=example,dc=com"));
        assertNotNull(conn.getEntry("testATWithoutOMR=Test,dc=example,dc=com"));
      }
    }
  }



  /**
   * Tests to ensure that the in-memory directory server behaves as expected
   * when dealing with entries that use case-sensitive RDN attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInMemoryDirectoryServerEntriesImportedFromLDIF()
         throws Exception
  {
    final InMemoryDirectoryServerConfig dsCfg =
         new InMemoryDirectoryServerConfig("dc=example,dc=com");
    dsCfg.setSchema(schema);

    try (InMemoryDirectoryServer ds = new InMemoryDirectoryServer(dsCfg))
    {
      ds.importFromLDIF(true,
           createTempFile(
                "dn: dc=example,dc=com",
                "objectClass: top",
                "objectClass: domain",
                "dc: example",
                "",
                "dn: testATWithOMR=test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: testOC",
                "testATWithOMR: test",
                "",
                "dn: testATWithOMR=Test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: testOC",
                "testATWithOMR: Test",
                "",
                "dn: testATWithoutOMR=test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: testOC",
                "testATWithoutOMR: test",
                "",
                "dn: testATWithoutOMR=Test,dc=example,dc=com",
                "objectClass: top",
                "objectClass: testOC",
                "testATWithoutOMR: Test"));
      ds.startListening();

      try (LDAPConnection conn = ds.getConnection())
      {
        assertNotNull(conn.getEntry("testATWithOMR=test,dc=example,dc=com"));
        assertNotNull(conn.getEntry("testATWithOMR=Test,dc=example,dc=com"));

        assertNotNull(conn.getEntry("testATWithoutOMR=test,dc=example,dc=com"));
        assertNotNull(conn.getEntry("testATWithoutOMR=Test,dc=example,dc=com"));
      }
    }
  }
}
