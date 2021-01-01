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
package com.unboundid.ldap.sdk.schema;



import java.util.LinkedList;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.Entry;



/**
 * This class provides a set of test cases for the EntryValidator class.
 */
public class EntryValidatorTestCase
       extends LDAPSDKTestCase
{
  // The schema retrieved from the server, if available.
  private Schema serverSchema;

  // An extremely simple schema that may be used for testing purposes.
  private Schema testSchema;



  /**
   * Get the schema from the server, if possible.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  if an unexpected problem occurs.
   */
  @BeforeClass()
  public void getSchemas()
         throws Exception
  {
    if (isDirectoryInstanceAvailable())
    {
      LDAPConnection conn = getAdminConnection();
      serverSchema = conn.getSchema();
      conn.close();
    }
    else
    {
      serverSchema = Schema.getDefaultStandardSchema();
    }


    // Create a minimal schema for test purposes.
    Entry testSchemaEntry = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschemaSubentry",
         "attributeTypes: ( 2.5.4.0 NAME 'objectClass' EQUALITY " +
              "objectIdentifierMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
         "attributeTypes: ( 1.1 NAME 'a1' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.2 NAME 'a2' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.3 NAME 'a3' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.4 NAME 'a4' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 )",
         "attributeTypes: ( 1.5 NAME 'a5' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-ALLOWED-VALUE ( 'foo' 'bar' ) )",
         "attributeTypes: ( 1.6 NAME 'a6' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-VALUE-REGEX '^[1-9].*$' )",
         "attributeTypes: ( 1.7 NAME 'a7' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-MIN-VALUE-LENGTH '5' X-MAX-VALUE-LENGTH '10' )",
         "attributeTypes: ( 1.8 NAME 'a8' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-MIN-VALUE-COUNT '5' X-MAX-VALUE-COUNT '10' )",
         "attributeTypes: ( 1.9 NAME 'a9' SYNTAX " +
              "1.3.6.1.4.1.1466.115.121.1.15 " +
              "X-MIN-INT-VALUE '5' X-MAX-INT-VALUE '10' )",
         "objectClasses: ( 2.5.6.0 NAME 'top' ABSTRACT MUST objectClass )",
         "objectClasses: ( 1.3.6.1.4.1.1466.101.120.111 NAME " +
              "'extensibleObject' SUP top AUXILIARY )",
         "objectClasses: ( 2.1 NAME 'o1' SUP top STRUCTURAL MUST a1 MAY " +
              "( a2 $ a3 $ a5 $ a6 $ a7 $ a8 $ a9 ) )",
         "objectClasses: ( 2.2 NAME 'o2' ABSTRACT )",
         "objectClasses: ( 2.3 NAME 'o3' SUP nonexistent AUXILIARY MAY a2 )",
         "objectClasses: ( 2.4 NAME 'o4' AUXILIARY MAY a1 )",
         "objectClasses: ( 2.5 NAME 'o5' AUXILIARY MAY a2 )",
         "nameForms: ( 3.1 NAME 'n1' OC o1 MUST a1 MAY a4 )",
         "dITContentRules: ( 2.1 NAME 'd1' AUX ( o3 $ o4 $ " +
              "extensibleObject ) MUST a1 MAY a4 NOT a3 )");
    testSchema = new Schema(testSchemaEntry);

    assertNotNull(testSchema.getAttributeTypes());
    assertEquals(testSchema.getAttributeTypes().size(), 10);
    assertNotNull(testSchema.getAttributeType("a1"));
    assertNotNull(testSchema.getAttributeType("a2"));
    assertNotNull(testSchema.getAttributeType("a3"));
    assertNotNull(testSchema.getAttributeType("a4"));
    assertNotNull(testSchema.getAttributeType("a5"));
    assertNotNull(testSchema.getAttributeType("a6"));
    assertNotNull(testSchema.getAttributeType("a7"));
    assertNotNull(testSchema.getAttributeType("a8"));
    assertNotNull(testSchema.getAttributeType("a9"));

    assertNotNull(testSchema.getObjectClasses());
    assertEquals(testSchema.getObjectClasses().size(), 7);
    assertNotNull(testSchema.getObjectClass("o1"));
    assertNotNull(testSchema.getObjectClass("o2"));
    assertNotNull(testSchema.getObjectClass("o3"));
    assertNotNull(testSchema.getObjectClass("o4"));
    assertNotNull(testSchema.getObjectClass("o5"));

    assertNotNull(testSchema.getNameForms());
    assertEquals(testSchema.getNameForms().size(), 1);
    assertNotNull(testSchema.getNameFormByObjectClass("o1"));

    assertNotNull(testSchema.getDITContentRules());
    assertEquals(testSchema.getDITContentRules().size(), 1);
    assertNotNull(testSchema.getDITContentRule("2.1"));
  }



  /**
   * Performs a test with a valid entry using the server schema.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidSimpleEntries()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry[] entries =
    {
      new Entry(
           "dn: dc=example,dc=com",
           "objectClass: top",
           "objectClass: domain",
           "dc: example"),

      new Entry(
           "dn: ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: organizationalUnit",
           "ou: People"),

      new Entry(
           "dn: uid=test.user,ou=People,dc=example,dc=com",
           "objectClass: top",
           "objectClass: person",
           "objectClass: organizationalPerson",
           "objectClass: inetOrgPerson",
           "uid: test.user",
           "givenName: Test",
           "sn: User",
           "cn: Test User",
           "userPassword: password",
           "description:  This is a test user")
    };


    LinkedList<String> invalidReasons = new LinkedList<String>();
    for (Entry e : entries)
    {
      assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    }

    assertTrue(invalidReasons.isEmpty());

    assertEquals(validator.getEntriesExamined(), 3L);
    assertEquals(validator.getInvalidEntries(), 0L);
    assertEquals(validator.getMalformedDNs(), 0L);
    assertEquals(validator.getEntriesMissingRDNValues(), 0L);
    assertEquals(validator.getEntriesWithMultipleStructuralObjectClasses(), 0L);
    assertEquals(validator.getNameFormViolations(), 0L);
    assertEquals(validator.getTotalUndefinedObjectClasses(), 0L);
    assertNotNull(validator.getTotalUndefinedObjectClasses());
    assertTrue(validator.getUndefinedObjectClasses().isEmpty());
    assertEquals(validator.getTotalUndefinedAttributes(), 0L);
    assertNotNull(validator.getUndefinedAttributes());
    assertTrue(validator.getUndefinedAttributes().isEmpty());
    assertEquals(validator.getTotalProhibitedObjectClasses(), 0L);
    assertNotNull(validator.getProhibitedObjectClasses());
    assertTrue(validator.getProhibitedObjectClasses().isEmpty());
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNotNull(validator.getProhibitedAttributes());
    assertTrue(validator.getProhibitedAttributes().isEmpty());
    assertEquals(validator.getTotalMissingAttributes(), 0L);
    assertNotNull(validator.getMissingAttributes());
    assertTrue(validator.getMissingAttributes().isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);
    assertNotNull(validator.getAttributesViolatingSyntax());
    assertTrue(validator.getAttributesViolatingSyntax().isEmpty());
    assertEquals(validator.getTotalSingleValueViolations(), 0L);
    assertNotNull(validator.getSingleValueViolations());
    assertTrue(validator.getSingleValueViolations().isEmpty());


    validator.resetCounts();
    for (Entry e : entries)
    {
      assertTrue(validator.entryIsValid(e, null));
    }
    assertTrue(validator.getInvalidEntrySummary(false).isEmpty());

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());

    assertEquals(validator.getEntriesExamined(), 3L);
    assertEquals(validator.getInvalidEntries(), 0L);
    assertEquals(validator.getMalformedDNs(), 0L);
    assertEquals(validator.getEntriesMissingRDNValues(), 0L);
    assertEquals(validator.getEntriesWithMultipleStructuralObjectClasses(), 0L);
    assertEquals(validator.getNameFormViolations(), 0L);
    assertEquals(validator.getTotalUndefinedObjectClasses(), 0L);
    assertNotNull(validator.getTotalUndefinedObjectClasses());
    assertTrue(validator.getUndefinedObjectClasses().isEmpty());
    assertEquals(validator.getTotalUndefinedAttributes(), 0L);
    assertNotNull(validator.getUndefinedAttributes());
    assertTrue(validator.getUndefinedAttributes().isEmpty());
    assertEquals(validator.getTotalProhibitedObjectClasses(), 0L);
    assertNotNull(validator.getProhibitedObjectClasses());
    assertTrue(validator.getProhibitedObjectClasses().isEmpty());
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNotNull(validator.getProhibitedAttributes());
    assertTrue(validator.getProhibitedAttributes().isEmpty());
    assertEquals(validator.getTotalMissingAttributes(), 0L);
    assertNotNull(validator.getMissingAttributes());
    assertTrue(validator.getMissingAttributes().isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);
    assertNotNull(validator.getAttributesViolatingSyntax());
    assertTrue(validator.getAttributesViolatingSyntax().isEmpty());
    assertEquals(validator.getTotalSingleValueViolations(), 0L);
    assertNotNull(validator.getSingleValueViolations());
    assertTrue(validator.getSingleValueViolations().isEmpty());
  }



  /**
   * Performs a test with an entry that does not have any object classes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoObjectClasses()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "dc: example");

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getEntriesWithoutAnyObjectClasses(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that has multiple structural object classes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNoStructuralClass()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: dcObject",
         "dc: example");

    assertTrue(validator.checkStructuralObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getEntriesMissingStructuralObjectClass(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckStructuralObjectClasses(false);
    assertFalse(validator.checkStructuralObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getEntriesMissingStructuralObjectClass(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that has an undefined object class.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedObjectClass()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "objectClass: notDefinedInSchema",
         "dc: example");

    assertTrue(validator.checkUndefinedObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalUndefinedObjectClasses(), 1L);
    assertNotNull(
         validator.getUndefinedObjectClasses().get("notdefinedinschema"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckUndefinedObjectClasses(false);
    assertFalse(validator.checkUndefinedObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalUndefinedObjectClasses(), 0L);
    assertNull(validator.getUndefinedObjectClasses().get("notdefinedinschema"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that has an undefined attribute.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedAttribute()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example",
         "notDefinedInSchema: foo");

    assertTrue(validator.checkUndefinedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalUndefinedAttributes(), 1L);
    assertNotNull(validator.getUndefinedAttributes().get("notdefinedinschema"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckUndefinedAttributes(false);
    assertFalse(validator.checkUndefinedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalUndefinedAttributes(), 0L);
    assertNull(validator.getUndefinedAttributes().get("notdefinedinschema"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that has an undefined attribute in the DN but
   * not in the set of attributes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedAttributeInDN()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);
    validator.setCheckEntryMissingRDNValues(false);

    Entry e = new Entry(
         "dn: notDefinedInSchema=foo+dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    assertTrue(validator.checkUndefinedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalUndefinedAttributes(), 1L);
    assertNotNull(validator.getUndefinedAttributes().get("notdefinedinschema"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckUndefinedAttributes(false);
    assertFalse(validator.checkUndefinedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalUndefinedAttributes(), 0L);
    assertNull(validator.getUndefinedAttributes().get("notdefinedinschema"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that does not have any structural object
   * class.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleStructuralClasses()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "objectClass: groupOfNames",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "member: uid=test.user,ou=People,dc=example,dc=com");

    assertTrue(validator.checkStructuralObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getEntriesWithMultipleStructuralObjectClasses(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckStructuralObjectClasses(false);
    assertFalse(validator.checkStructuralObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getEntriesWithMultipleStructuralObjectClasses(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that is missing a superior object class.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingSuperiorClasses()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    final EntryValidator validator = new EntryValidator(serverSchema);

    final Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password");

    assertTrue(validator.checkMissingSuperiorObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getEntriesWithMissingSuperiorObjectClasses(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckMissingSuperiorObjectClasses(false);
    assertFalse(validator.checkMissingSuperiorObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getEntriesWithMissingSuperiorObjectClasses(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that is missing a required attribute.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingRequiredAttribute()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "userPassword: password",
         "description:  This is a test user");

    assertTrue(validator.checkMissingAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalMissingAttributes(), 1L);
    assertNotNull(validator.getMissingAttributes().get("cn"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckMissingAttributes(false);
    assertFalse(validator.checkMissingAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalMissingAttributes(), 0L);
    assertNull(validator.getMissingAttributes().get("cn"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that has a required attribute only in the DN
   * but not in the set of attributes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testRequiredAttributeOnlyInDN()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);
    validator.setCheckEntryMissingRDNValues(false);

    Entry e = new Entry(
         "dn: cn=Test User,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "userPassword: password",
         "description:  This is a test user");

    assertTrue(validator.checkMissingAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalMissingAttributes(), 0L);
    assertNull(validator.getMissingAttributes().get("cn"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that contains an attribute that is not
   * allowed, but not explicitly prohibited.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryContainsNotAllowedAttribute()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description:  This is a test user",
         "dc: not allowed");

    assertTrue(validator.checkProhibitedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 1L);
    assertNotNull(validator.getProhibitedAttributes().get("dc"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckProhibitedAttributes(false);
    assertFalse(validator.checkProhibitedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNull(validator.getProhibitedAttributes().get("dc"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that contains an attribute that is not
   * allowed directly but is allowed implicitly by the extensibleObject object
   * class and not explicitly prohibited.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryContainsNotAllowedAttributeWithExtensibleObject()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "objectClass: extensibleObject",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description:  This is a test user",
         "dc: not allowed");

    assertTrue(validator.checkProhibitedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNull(validator.getProhibitedAttributes().get("dc"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that contains a prohibited attribute that
   * exists only in the DN but not in the set of attributes.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEntryContainsProhibitedAttributeOnlyInDN()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);
    validator.setCheckEntryMissingRDNValues(false);

    Entry e = new Entry(
         "dn: dc=prohibited,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description:  This is a test user");

    assertTrue(validator.checkProhibitedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 1L);
    assertNotNull(validator.getProhibitedAttributes().get("dc"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckProhibitedAttributes(false);
    assertFalse(validator.checkProhibitedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNull(validator.getProhibitedAttributes().get("dc"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that has a malformed DN.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMalformedDN()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: invalid",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description:  This is a test user");

    assertTrue(validator.checkMalformedDNs());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getMalformedDNs(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckMalformedDNs(false);
    assertFalse(validator.checkMalformedDNs());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getMalformedDNs(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry that contains multiple values for a
   * single-valued attribute.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleValuedAttribute()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "displayName: First Value",
         "displayName: Second Value",
         "userPassword: password",
         "description:  This is a test user");

    assertTrue(validator.checkSingleValuedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalSingleValueViolations(), 1L);
    assertNotNull(validator.getSingleValueViolations().get("displayname"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckSingleValuedAttributes(false);
    assertFalse(validator.checkSingleValuedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalSingleValueViolations(), 0L);
    assertNull(validator.getSingleValueViolations().get("displayname"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an attribute value that violates its associated
   * syntax.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSyntaxViolation()
         throws Exception
  {
    if (serverSchema == null)
    {
      return;
    }

    EntryValidator validator = new EntryValidator(serverSchema);

    Entry e = new Entry(
         "dn: uid=test.user,ou=People,dc=example,dc=com",
         "objectClass: top",
         "objectClass: person",
         "objectClass: organizationalPerson",
         "objectClass: inetOrgPerson",
         "uid: test.user",
         "givenName: Test",
         "sn: User",
         "cn: Test User",
         "userPassword: password",
         "description:  This is a test user",
         "manager: not a dn");

    assertTrue(validator.checkAttributeSyntax());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);
    assertNotNull(validator.getAttributesViolatingSyntax().get("manager"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckAttributeSyntax(false);
    assertFalse(validator.checkAttributeSyntax());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);
    assertNull(validator.getAttributesViolatingSyntax().get("manager"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckAttributeSyntax(true);
    assertTrue(validator.checkAttributeSyntax());
    validator.setIgnoreSyntaxViolationAttributeTypes("manager");
    assertNotNull(validator.getIgnoreSyntaxViolationsAttributeTypes());
    assertFalse(validator.getIgnoreSyntaxViolationsAttributeTypes().isEmpty());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);
    assertNull(validator.getAttributesViolatingSyntax().get("manager"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckAttributeSyntax(true);
    assertTrue(validator.checkAttributeSyntax());
    validator.setIgnoreSyntaxViolationAttributeTypes(
         (AttributeTypeDefinition[]) null);
    assertNotNull(validator.getIgnoreSyntaxViolationsAttributeTypes());
    assertTrue(validator.getIgnoreSyntaxViolationsAttributeTypes().isEmpty());

    invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);
    assertNotNull(validator.getAttributesViolatingSyntax().get("manager"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckAttributeSyntax(true);
    assertTrue(validator.checkAttributeSyntax());
    validator.setIgnoreSyntaxViolationAttributeTypes(
         serverSchema.getAttributeType("manager"));
    assertNotNull(validator.getIgnoreSyntaxViolationsAttributeTypes());
    assertFalse(validator.getIgnoreSyntaxViolationsAttributeTypes().isEmpty());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);
    assertNull(validator.getAttributesViolatingSyntax().get("manager"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an attribute value that violates UnboundID-specific
   * attribute type constraints.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testViolatesUnboundIDAttributeTypeConstraints()
         throws Exception
  {
    final EntryValidator validator = new EntryValidator(testSchema);


    // First, test a valid entry.
    Entry e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test");

    final LinkedList<String> invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons));
    assertTrue(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);


    // Test the X-ALLOWED-VALUE constraint with an allowed value.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a5: foo");

    validator.resetCounts();
    invalidReasons.clear();
    assertTrue(validator.entryIsValid(e, invalidReasons));
    assertTrue(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);


    // Test the X-ALLOWED-VALUE constraint with a disallowed value.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a5: disallowed");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-VALUE-REGEX constraint with an allowed value.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a6: 1StartsWithDigit");

    validator.resetCounts();
    invalidReasons.clear();
    assertTrue(validator.entryIsValid(e, invalidReasons));
    assertTrue(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);


    // Test the X-VALUE-REGEX constraint with a disallowed value.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a6: DoesNotStartWithDigit");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-VALUE-LENGTH and X-MAX-VALUE-LENGTH constraints with an
    // acceptable value.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a7: OKLength");

    validator.resetCounts();
    invalidReasons.clear();
    assertTrue(validator.entryIsValid(e, invalidReasons));
    assertTrue(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);


    // Test the X-MIN-VALUE-LENGTH and X-MAX-VALUE-LENGTH constraints with a
    // value that is too short.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a7: ts");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-VALUE-LENGTH and X-MAX-VALUE-LENGTH constraints with a
    // value that is too long.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a7: this-value-is-too-long");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-VALUE-COUNT and X-MAX-VALUE-COUNT constraints with an
    // entry that has an acceptable number of values.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a8: value1",
         "a8: value2",
         "a8: value3",
         "a8: value4",
         "a8: value5",
         "a8: value6",
         "a8: value7");

    validator.resetCounts();
    invalidReasons.clear();
    assertTrue(validator.entryIsValid(e, invalidReasons));
    assertTrue(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);


    // Test the X-MIN-VALUE-COUNT and X-MAX-VALUE-COUNT constraints with an
    // entry that has too few values.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a8: value1",
         "a8: value2",
         "a8: value3");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-VALUE-COUNT and X-MAX-VALUE-COUNT constraints with an
    // entry that has too many values.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a8: value1",
         "a8: value2",
         "a8: value3",
         "a8: value4",
         "a8: value5",
         "a8: value6",
         "a8: value7",
         "a8: value8",
         "a8: value9",
         "a8: value10",
         "a8: value11",
         "a8: value12",
         "a8: value13");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-INT-VALUE and X-MAX-INT-VALUE constraints with an
    // acceptable value.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a9: 6");

    validator.resetCounts();
    invalidReasons.clear();
    assertTrue(validator.entryIsValid(e, invalidReasons));
    assertTrue(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);


    // Test the X-MIN-INT-VALUE and X-MAX-INT-VALUE constraints with a value
    // that is too small.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a9: 2");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-INT-VALUE and X-MAX-INT-VALUE constraints with a value
    // that is too large.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a9: 20");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 1L);


    // Test the X-MIN-INT-VALUE and X-MAX-INT-VALUE constraints with a value
    // that cannot be parsed as an integer.
    e = new Entry(
         "dn: a1=test",
         "objectClass: top",
         "objectClass: o1",
         "a1: test",
         "a9: not-an-integer");

    validator.resetCounts();
    invalidReasons.clear();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(invalidReasons.isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 2L);
  }



  /**
   * Performs a test with a valid entry using the test schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEntryTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);
    validator.setCheckEntryMissingRDNValues(false);

    Entry e = new Entry(
         "dn: a1=foo+a4=baz",
         "objectClass: top",
         "objectClass: o1",
         "objectClass: o4",
         "a1: foo",
         "a2: bar");

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
         e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertTrue(validator.checkAttributeSyntax());

    assertTrue(validator.getInvalidEntrySummary(false).isEmpty());

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());

    assertEquals(validator.getEntriesExamined(), 1L);
    assertEquals(validator.getInvalidEntries(), 0L);
    assertEquals(validator.getMalformedDNs(), 0L);
    assertEquals(validator.getEntriesWithMultipleStructuralObjectClasses(), 0L);
    assertEquals(validator.getNameFormViolations(), 0L);
    assertEquals(validator.getTotalUndefinedObjectClasses(), 0L);
    assertNotNull(validator.getTotalUndefinedObjectClasses());
    assertTrue(validator.getUndefinedObjectClasses().isEmpty());
    assertEquals(validator.getTotalUndefinedAttributes(), 0L);
    assertNotNull(validator.getUndefinedAttributes());
    assertTrue(validator.getUndefinedAttributes().isEmpty());
    assertEquals(validator.getTotalProhibitedObjectClasses(), 0L);
    assertNotNull(validator.getProhibitedObjectClasses());
    assertTrue(validator.getProhibitedObjectClasses().isEmpty());
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNotNull(validator.getProhibitedAttributes());
    assertTrue(validator.getProhibitedAttributes().isEmpty());
    assertEquals(validator.getTotalMissingAttributes(), 0L);
    assertNotNull(validator.getMissingAttributes());
    assertTrue(validator.getMissingAttributes().isEmpty());
    assertEquals(validator.getTotalAttributesViolatingSyntax(), 0L);
    assertNotNull(validator.getAttributesViolatingSyntax());
    assertTrue(validator.getAttributesViolatingSyntax().isEmpty());
    assertEquals(validator.getTotalSingleValueViolations(), 0L);
    assertNotNull(validator.getSingleValueViolations());
    assertTrue(validator.getSingleValueViolations().isEmpty());
  }



  /**
   * Performs a test with an entry containing an object class with a superior
   * class not defined in the schema.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testUndefinedSuperiorClassTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo",
         "objectClass: top",
         "objectClass: o1",
         "objectClass: o3",
         "objectClass: o4",
         "a1: foo",
         "a2: bar");

    assertTrue(validator.checkUndefinedObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalUndefinedObjectClasses(), 1L);
    assertNotNull(validator.getUndefinedObjectClasses().get("nonexistent"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckUndefinedObjectClasses(false);
    assertFalse(validator.checkUndefinedObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalUndefinedObjectClasses(), 0L);
    assertNull(validator.getUndefinedObjectClasses().get("nonexistent"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry containing an auxiliary object class that is
   * not allowed by a DIT structure rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testProhibitedAuxiliaryClassTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo",
         "objectClass: top",
         "objectClass: o1",
         "objectClass: o5",
         "a1: foo");

    assertTrue(validator.checkProhibitedObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalProhibitedObjectClasses(), 1L);
    assertNotNull(validator.getProhibitedObjectClasses().get("o5"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckProhibitedObjectClasses(false);
    assertFalse(validator.checkProhibitedObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedObjectClasses(), 0L);
    assertNull(validator.getProhibitedObjectClasses().get("o5"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry containing a stray abstract class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStrayAbstractClassTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo",
         "objectClass: top",
         "objectClass: o1",
         "objectClass: o2",
         "a1: foo");

    assertTrue(validator.checkProhibitedObjectClasses());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalProhibitedObjectClasses(), 1L);
    assertNotNull(validator.getProhibitedObjectClasses().get("o2"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckProhibitedObjectClasses(false);
    assertFalse(validator.checkProhibitedObjectClasses());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedObjectClasses(), 0L);
    assertNull(validator.getProhibitedObjectClasses().get("o2"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry containing an attribute that is prohibited
   * by a DIT content rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDCRProhibitedAttributeTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo",
         "objectClass: top",
         "objectClass: o1",
         "a1: foo",
         "a3: bar");

    assertTrue(validator.checkProhibitedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 2L);
    assertNotNull(validator.getProhibitedAttributes().get("a3"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckProhibitedAttributes(false);
    assertFalse(validator.checkProhibitedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNull(validator.getProhibitedAttributes().get("a3"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry containing an attribute that is prohibited
   * by a DIT content rule, even when the entry contains the extensibleObject
   * class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDCRProhibitedAttributeTestSchemaWithExtensibleObject()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo",
         "objectClass: top",
         "objectClass: o1",
         "objectClass: extensibleObject",
         "a1: foo",
         "a3: bar");

    assertTrue(validator.checkProhibitedAttributes());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 2L);
    assertNotNull(validator.getProhibitedAttributes().get("a3"));

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckProhibitedAttributes(false);
    assertFalse(validator.checkProhibitedAttributes());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getTotalProhibitedAttributes(), 0L);
    assertNull(validator.getProhibitedAttributes().get("a3"));

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry containing a DN with an attribute not allowed
   * by the associated name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNIncludesAttributeNotAllowedByNameFormTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo+a2=bar",
         "objectClass: top",
         "objectClass: o1",
         "a1: foo",
         "a2: bar");

    assertTrue(validator.checkNameForms());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getNameFormViolations(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckNameForms(false);
    assertFalse(validator.checkNameForms());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getNameFormViolations(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Performs a test with an entry containing a DN missing an attribute required
   * by the associated name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNMissingAttributeRequiredByNameFormTestSchema()
         throws Exception
  {
    EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a4=bar",
         "objectClass: top",
         "objectClass: o1",
         "a1: foo",
         "a4: bar");

    assertTrue(validator.checkNameForms());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getNameFormViolations(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckNameForms(false);
    assertFalse(validator.checkNameForms());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getNameFormViolations(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Tests the entry validator's ability to flag entries that use attribute
   * values in their RDN that are not present in the set of entry attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMissingRDNValues()
         throws Exception
  {
    final EntryValidator validator = new EntryValidator(testSchema);

    Entry e = new Entry(
         "dn: a1=foo+a4=bar",
         "objectClass: top",
         "objectClass: o1",
         "a1: foo");

    assertTrue(validator.checkEntryMissingRDNValues());

    LinkedList<String> invalidReasons = new LinkedList<String>();
    assertFalse(validator.entryIsValid(e, invalidReasons));
    assertEquals(validator.getEntriesMissingRDNValues(), 1L);

    assertFalse(validator.getInvalidEntrySummary(true).isEmpty());


    validator.resetCounts();
    validator.setCheckEntryMissingRDNValues(false);
    assertFalse(validator.checkEntryMissingRDNValues());

    invalidReasons = new LinkedList<String>();
    assertTrue(validator.entryIsValid(e, invalidReasons),
           e.getDN() + " invalid reasons:\n" + listToString(invalidReasons));
    assertEquals(validator.getEntriesMissingRDNValues(), 0L);

    assertTrue(validator.getInvalidEntrySummary(true).isEmpty());
  }



  /**
   * Creates a single string from the provided list of strings.
   *
   * @param  l  The list of strings to process.
   *
   * @return  The single string created from the provided list.
   */
  private static String listToString(final LinkedList<String> l)
  {
    StringBuilder buffer = new StringBuilder();
    for (String s : l)
    {
      buffer.append(s);
      buffer.append('\n');
    }

    return buffer.toString();
  }
}
