/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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



import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.persist.PersistUtils;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the Schema class.
 */
public class SchemaTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the constructor with an empty entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorEmptyEntry()
         throws Exception
  {
    Schema schema = new Schema(new Entry("cn=schema"));

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the constructor with an entry that contains all types of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorTestEntry()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschemaSubentry",
         "ldapSyntaxes: ( 1.2.3.5 )",
         "matchingRules: ( 1.2.3.6 SYNTAX 1.2.3.5 )",
         "attributeTypes: ( 1.2.3.7 NAME 'testAttr' )",
         "objectClasses: (1.2.3.8 NAME 'testOC' MUST testATTR )",
         "dITContentRules: ( 1.2.3.8 )",
         "dITStructureRules: ( 1 FORM testForm )",
         "nameForms: ( 1.2.3.9 OC testOC MUST testATTR )",
         "matchingRuleUse: ( 1.2.3.6 APPLIES cn )");

    Schema schema = new Schema(e);

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the constructor with an entry that contains all types of elements
   * but with invalid definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorTestEntryInvalid()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=schema",
         "ldapSyntaxes: invalid",
         "matchingRules: invalid",
         "attributeTypes: invalid",
         "objectClasses: invalid",
         "dITContentRules: invalid",
         "dITStructureRules: invalid",
         "nameForms: invalid",
         "matchingRuleUse: invalid");

    Schema schema = new Schema(e);

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the constructor with an empty entry and a bunch of maps.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorEmptyEntryAndMaps()
         throws Exception
  {
    final LinkedHashMap<String,LDAPException> unparsableAttributeSyntaxes =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableMatchingRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableAttributeTypes =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableObjectClasses =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableDITContentRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableDITStructureRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableNameForms =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableMatchingRuleUses =
         new LinkedHashMap<>(10);

    Schema schema = new Schema(new Entry("cn=schema"),
         unparsableAttributeSyntaxes, unparsableMatchingRules,
         unparsableAttributeTypes, unparsableObjectClasses,
         unparsableDITContentRules, unparsableDITStructureRules,
         unparsableNameForms, unparsableMatchingRuleUses);

    assertNotNull(schema);

    assertTrue(unparsableAttributeSyntaxes.isEmpty());
    assertTrue(unparsableMatchingRules.isEmpty());
    assertTrue(unparsableAttributeTypes.isEmpty());
    assertTrue(unparsableObjectClasses.isEmpty());
    assertTrue(unparsableDITContentRules.isEmpty());
    assertTrue(unparsableDITStructureRules.isEmpty());
    assertTrue(unparsableNameForms.isEmpty());
    assertTrue(unparsableMatchingRuleUses.isEmpty());

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the constructor with an entry that contains all types of elements
   * and a bunch of maps.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorTestEntryAndMaps()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschemaSubentry",
         "ldapSyntaxes: ( 1.2.3.5 )",
         "matchingRules: ( 1.2.3.6 SYNTAX 1.2.3.5 )",
         "attributeTypes: ( 1.2.3.7 NAME 'testAttr' )",
         "objectClasses: (1.2.3.8 NAME 'testOC' MUST testATTR )",
         "dITContentRules: ( 1.2.3.8 )",
         "dITStructureRules: ( 1 FORM testForm )",
         "nameForms: ( 1.2.3.9 OC testOC MUST testATTR )",
         "matchingRuleUse: ( 1.2.3.6 APPLIES cn )");

    final LinkedHashMap<String,LDAPException> unparsableAttributeSyntaxes =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableMatchingRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableAttributeTypes =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableObjectClasses =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableDITContentRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableDITStructureRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableNameForms =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableMatchingRuleUses =
         new LinkedHashMap<>(10);

    Schema schema = new Schema(e, unparsableAttributeSyntaxes,
         unparsableMatchingRules, unparsableAttributeTypes,
         unparsableObjectClasses, unparsableDITContentRules,
         unparsableDITStructureRules, unparsableNameForms,
         unparsableMatchingRuleUses);

    assertNotNull(schema);

    assertTrue(unparsableAttributeSyntaxes.isEmpty());
    assertTrue(unparsableMatchingRules.isEmpty());
    assertTrue(unparsableAttributeTypes.isEmpty());
    assertTrue(unparsableObjectClasses.isEmpty());
    assertTrue(unparsableDITContentRules.isEmpty());
    assertTrue(unparsableDITStructureRules.isEmpty());
    assertTrue(unparsableNameForms.isEmpty());
    assertTrue(unparsableMatchingRuleUses.isEmpty());

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the constructor with an entry that contains all types of elements
   * but with invalid definitions and a bunch of maps.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorTestEntryInvalidAndMaps()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=schema",
         "ldapSyntaxes: invalid1",
         "ldapSyntaxes: invalid2",
         "matchingRules: invalid3",
         "matchingRules: invalid4",
         "attributeTypes: invalid5",
         "attributeTypes: invalid6",
         "objectClasses: invalid7",
         "objectClasses: invalid8",
         "dITContentRules: invalid9",
         "dITContentRules: invalid10",
         "dITStructureRules: invalid11",
         "dITStructureRules: invalid12",
         "nameForms: invalid13",
         "nameForms: invalid14",
         "matchingRuleUse: invalid15",
         "matchingRuleUse: invalid16");

    final LinkedHashMap<String,LDAPException> unparsableAttributeSyntaxes =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableMatchingRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableAttributeTypes =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableObjectClasses =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableDITContentRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableDITStructureRules =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableNameForms =
         new LinkedHashMap<>(10);
    final LinkedHashMap<String,LDAPException> unparsableMatchingRuleUses =
         new LinkedHashMap<>(10);

    Schema schema = new Schema(e, unparsableAttributeSyntaxes,
         unparsableMatchingRules, unparsableAttributeTypes,
         unparsableObjectClasses, unparsableDITContentRules,
         unparsableDITStructureRules, unparsableNameForms,
         unparsableMatchingRuleUses);

    assertNotNull(schema);

    assertFalse(unparsableAttributeSyntaxes.isEmpty());
    assertFalse(unparsableMatchingRules.isEmpty());
    assertFalse(unparsableAttributeTypes.isEmpty());
    assertFalse(unparsableObjectClasses.isEmpty());
    assertFalse(unparsableDITContentRules.isEmpty());
    assertFalse(unparsableDITStructureRules.isEmpty());
    assertFalse(unparsableNameForms.isEmpty());
    assertFalse(unparsableMatchingRuleUses.isEmpty());


    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the {@code parseSchemaEntry} method with an empty entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseSchemaEntryEmptyEntry()
         throws Exception
  {
    Schema schema = Schema.parseSchemaEntry(new Entry("cn=schema"));

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the {@code parseSchemaEntry} method with an entry that contains all
   * types of elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseSchemaEntryTestEntry()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschemaSubentry",
         "ldapSyntaxes: ( 1.2.3.5 )",
         "matchingRules: ( 1.2.3.6 SYNTAX 1.2.3.5 )",
         "attributeTypes: ( 1.2.3.7 NAME 'testAttr' )",
         "objectClasses: (1.2.3.8 NAME 'testOC' MUST testATTR )",
         "dITContentRules: ( 1.2.3.8 )",
         "dITStructureRules: ( 1 FORM testForm )",
         "nameForms: ( 1.2.3.9 OC testOC MUST testATTR )",
         "matchingRuleUse: ( 1.2.3.6 APPLIES cn )");

    Schema schema = Schema.parseSchemaEntry(e);

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the {@code parseSchemaEntry} method with an entry that contains all
   * types of elements but with invalid definitions.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = LDAPException.class)
  public void testParseSchemaEntryTestEntryInvalid()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=schema",
         "ldapSyntaxes: invalid1",
         "ldapSyntaxes: invalid2",
         "matchingRules: invalid3",
         "matchingRules: invalid4",
         "attributeTypes: invalid5",
         "attributeTypes: invalid6",
         "objectClasses: invalid7",
         "objectClasses: invalid8",
         "dITContentRules: invalid9",
         "dITContentRules: invalid10",
         "dITStructureRules: invalid11",
         "dITStructureRules: invalid12",
         "nameForms: invalid13",
         "nameForms: invalid14",
         "matchingRuleUse: invalid15",
         "matchingRuleUse: invalid16");

    Schema.parseSchemaEntry(e);
  }



  /**
   * Tests the {@code getSchema} method that doesn't take any arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchema1()
         throws Exception
  {
    LDAPConnection connection = getTestDS().getConnection();
    Schema schema = Schema.getSchema(connection);
    connection.close();

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the {@code getSchema} method that takes a DN argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchema2()
         throws Exception
  {
    LDAPConnection connection = getTestDS().getConnection();

    try
    {
      Schema schema = Schema.getSchema(connection, "");

      assertNotNull(schema);

      assertNotNull(schema.getAttributeSyntaxes());
      assertNull(schema.getAttributeSyntax("1.2.3.4"));
      assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

      assertNotNull(schema.getAttributeTypes());
      assertNotNull(schema.getOperationalAttributeTypes());
      assertNotNull(schema.getUserAttributeTypes());
      assertNull(schema.getAttributeType("1.2.3.4"));

      assertNotNull(schema.getDITContentRules());
      assertNull(schema.getDITContentRule("1.2.3.4"));

      assertNotNull(schema.getDITStructureRules());
      assertNull(schema.getDITStructureRuleByID(12345));
      assertNull(schema.getDITStructureRuleByName("foo"));
      assertNull(schema.getDITStructureRuleByNameForm("foo"));

      assertNotNull(schema.getMatchingRules());
      assertNull(schema.getMatchingRule("1.2.3.4"));

      assertNotNull(schema.getMatchingRuleUses());
      assertNull(schema.getMatchingRuleUse("1.2.3.4"));

      assertNotNull(schema.getNameForms());
      assertNull(schema.getNameFormByName("1.2.3.4"));
      assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

      assertNotNull(schema.getObjectClasses());
      assertNotNull(schema.getAbstractObjectClasses());
      assertNotNull(schema.getAuxiliaryObjectClasses());
      assertNotNull(schema.getStructuralObjectClasses());
      assertNull(schema.getObjectClass("1.2.3.4"));

      schema.hashCode();
      assertTrue(schema.equals(schema));
      assertFalse(schema.equals(null));
      assertFalse(schema.equals("foo"));
      assertNotNull(schema.toString());
    }
    finally
    {
      connection.close();
    }
  }



  /**
   * Tests the {@code getSchema} method that takes a DN argument, using a
   * {@code null} value.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchema2Null()
         throws Exception
  {
    LDAPConnection connection = getTestDS().getConnection();
    Schema schema = Schema.getSchema(connection, null);
    connection.close();

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the {@code getSchema} method that retrieves the schema from a server,
   * throwing an exception if the schema contains any unparsable elements.  This
   * method is not expected to throw an exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchemaThrowingOnInvalidWithValidSchema()
         throws Exception
  {
    LDAPConnection connection = getTestDS().getConnection();

    try
    {
      Schema schema = Schema.getSchema(connection, "", true);

      assertNotNull(schema);

      assertNotNull(schema.getAttributeSyntaxes());
      assertNull(schema.getAttributeSyntax("1.2.3.4"));
      assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

      assertNotNull(schema.getAttributeTypes());
      assertNotNull(schema.getOperationalAttributeTypes());
      assertNotNull(schema.getUserAttributeTypes());
      assertNull(schema.getAttributeType("1.2.3.4"));

      assertNotNull(schema.getDITContentRules());
      assertNull(schema.getDITContentRule("1.2.3.4"));

      assertNotNull(schema.getDITStructureRules());
      assertNull(schema.getDITStructureRuleByID(12345));
      assertNull(schema.getDITStructureRuleByName("foo"));
      assertNull(schema.getDITStructureRuleByNameForm("foo"));

      assertNotNull(schema.getMatchingRules());
      assertNull(schema.getMatchingRule("1.2.3.4"));

      assertNotNull(schema.getMatchingRuleUses());
      assertNull(schema.getMatchingRuleUse("1.2.3.4"));

      assertNotNull(schema.getNameForms());
      assertNull(schema.getNameFormByName("1.2.3.4"));
      assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

      assertNotNull(schema.getObjectClasses());
      assertNotNull(schema.getAbstractObjectClasses());
      assertNotNull(schema.getAuxiliaryObjectClasses());
      assertNotNull(schema.getStructuralObjectClasses());
      assertNull(schema.getObjectClass("1.2.3.4"));

      schema.hashCode();
      assertTrue(schema.equals(schema));
      assertFalse(schema.equals(null));
      assertFalse(schema.equals("foo"));
      assertNotNull(schema.toString());
    }
    finally
    {
      connection.close();
    }
  }



  /**
   * Tests the {@code getSchema} method that reads schema information from an
   * input stream.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchemaFromInputStream()
         throws Exception
  {
    final File schemaFile = createTempFile(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschemaSubentry",
         "ldapSyntaxes: ( 1.2.3.5 )",
         "matchingRules: ( 1.2.3.6 SYNTAX 1.2.3.5 )",
         "attributeTypes: ( 1.2.3.7 NAME 'testAttr' )",
         "objectClasses: (1.2.3.8 NAME 'testOC' MUST testATTR )",
         "dITContentRules: ( 1.2.3.8 )",
         "dITStructureRules: ( 1 FORM testForm )",
         "nameForms: ( 1.2.3.9 OC testOC MUST testATTR )",
         "matchingRuleUse: ( 1.2.3.6 APPLIES cn )");

    final FileInputStream inputStream = new FileInputStream(schemaFile);

    final Schema schema = Schema.getSchema(inputStream);

    assertNotNull(schema);

    assertNotNull(schema.getAttributeSyntaxes());
    assertNull(schema.getAttributeSyntax("1.2.3.4"));
    assertNull(schema.getAttributeSyntax("1.2.3.4{123}"));

    assertNotNull(schema.getAttributeTypes());
    assertNotNull(schema.getOperationalAttributeTypes());
    assertNotNull(schema.getUserAttributeTypes());
    assertNull(schema.getAttributeType("1.2.3.4"));

    assertNotNull(schema.getDITContentRules());
    assertNull(schema.getDITContentRule("1.2.3.4"));

    assertNotNull(schema.getDITStructureRules());
    assertNull(schema.getDITStructureRuleByID(12345));
    assertNull(schema.getDITStructureRuleByName("foo"));
    assertNull(schema.getDITStructureRuleByNameForm("foo"));

    assertNotNull(schema.getMatchingRules());
    assertNull(schema.getMatchingRule("1.2.3.4"));

    assertNotNull(schema.getMatchingRuleUses());
    assertNull(schema.getMatchingRuleUse("1.2.3.4"));

    assertNotNull(schema.getNameForms());
    assertNull(schema.getNameFormByName("1.2.3.4"));
    assertNull(schema.getNameFormByObjectClass("1.2.3.4"));

    assertNotNull(schema.getObjectClasses());
    assertNotNull(schema.getAbstractObjectClasses());
    assertNotNull(schema.getAuxiliaryObjectClasses());
    assertNotNull(schema.getStructuralObjectClasses());
    assertNull(schema.getObjectClass("1.2.3.4"));

    schema.hashCode();
    assertTrue(schema.equals(schema));
    assertFalse(schema.equals(null));
    assertFalse(schema.equals("foo"));
    assertFalse(schema.equals(Schema.getDefaultStandardSchema()));
    assertFalse(Schema.getDefaultStandardSchema().equals(schema));
    assertNotNull(schema.toString());
  }



  /**
   * Tests the {@code getSchema} method that reads schema information from an
   * input stream that doesn't have any data to be read.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSchemaFromEmptyInputStream()
         throws Exception
  {
    assertNull(Schema.getSchema(new ByteArrayInputStream(new byte[0])));
  }



  /**
   * Tests the {@code getSubschemaSubentryDN} method with a {@code null}
   * argument.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSubschemaSubentryDNNull()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();
    assertNotNull(Schema.getSubschemaSubentryDN(connection, null));
    connection.close();
  }



  /**
   * Tests the {@code getSubschemaSubentryDN} method with an empty DN string.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSubschemaSubentryDNEmpty()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();
    assertNotNull(Schema.getSubschemaSubentryDN(connection, ""));
    connection.close();
  }



  /**
   * Tests the {@code getSubschemaSubentryDN} method with a non-empty DN string.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetSubschemaSubentryDNNonEmpty()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();
    connection.add(getTestBaseDN(), getBaseEntryAttributes());

    try
    {
      // Only perform the search if the target entry includes a
      // subschemaSubentry attribute.  It may not if the corresponding virtual
      // attribute in the server has been disabled.
      Entry e = connection.getEntry(getTestBaseDN(), "subschemaSubentry");
      if (e.hasAttribute("subSchemaSubentry"))
      {
        assertNotNull(Schema.getSubschemaSubentryDN(connection,
                                                    getTestBaseDN()));
      }
    }
    finally
    {
      connection.delete(getTestBaseDN());
      connection.close();
    }
  }



  /**
   * Tests the ability to read schema information from a single file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSchemaFromSingleFile()
         throws Exception
  {
    LDAPConnection conn = getTestDS().getConnection();
    Entry e = conn.getEntry("cn=schema", "attributeTypes", "objectClasses");
    conn.close();

    assertNotNull(e);
    assertTrue(e.hasAttribute("attributeTypes"));
    assertTrue(e.hasAttribute("objectClasses"));

    File entryFile = createTempFile();
    entryFile.delete();

    LDIFWriter entryWriter = new LDIFWriter(entryFile);
    entryWriter.writeEntry(e);
    entryWriter.close();

    Schema schema = Schema.getSchema(entryFile.getAbsolutePath());
    assertNotNull(schema);
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());

    schema = Schema.getSchema(entryFile);
    assertNotNull(schema);
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());

    List<File> fileList = Arrays.asList(entryFile);
    schema = Schema.getSchema(fileList);
    assertNotNull(schema);
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());
  }



  /**
   * Tests the ability to read schema information from multiple files.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSchemaFromMultipleFilesThrowOnUnparsableElement()
         throws Exception
  {
    LDAPConnection conn = getTestDS().getConnection();
    Entry e = conn.getEntry("cn=schema", "attributeTypes", "objectClasses");
    conn.close();

    assertNotNull(e);
    assertTrue(e.hasAttribute("attributeTypes"));
    assertTrue(e.hasAttribute("objectClasses"));

    Entry attrEntry = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectclass: subschemaSubentry",
         "cn: schema");
    attrEntry.addAttribute(e.getAttribute("attributeTypes"));

    Entry ocEntry = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectclass: subschemaSubentry",
         "cn: schema");
    ocEntry.addAttribute(e.getAttribute("objectClasses"));

    File attrFile = createTempFile();
    attrFile.delete();

    LDIFWriter attrFileWriter = new LDIFWriter(attrFile);
    attrFileWriter.writeEntry(attrEntry);
    attrFileWriter.close();

    File ocFile = createTempFile();
    ocFile.delete();

    LDIFWriter ocFileWriter = new LDIFWriter(ocFile);
    ocFileWriter.writeEntry(ocEntry);
    ocFileWriter.close();

    Schema schema = Schema.getSchema(attrFile.getAbsolutePath(),
                                     ocFile.getAbsolutePath());
    assertNotNull(schema);
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());

    schema = Schema.getSchema(attrFile, ocFile);
    assertNotNull(schema);
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());

    List<File> fileList = Arrays.asList(attrFile, ocFile);
    schema = Schema.getSchema(fileList);
    assertNotNull(schema);
    assertFalse(schema.getAttributeTypes().isEmpty());
    assertFalse(schema.getObjectClasses().isEmpty());
  }



  /**
   * Tests the ability to read schema information from files when throwing an
   * exception if any of the files contains unparsable elements.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSchemaFromFilesThrowOnUnparsable()
         throws Exception
  {
    final File validSchemaFile = createTempFile(
         Schema.getDefaultStandardSchema().getSchemaEntry().toLDIF());
    final File invalidSchemaFile = createTempFile(
         "dn: cn=schema",
         "ldapSyntaxes: invalid",
         "matchingRules: invalid",
         "attributeTypes: invalid",
         "objectClasses: invalid",
         "dITContentRules: invalid",
         "dITStructureRules: invalid",
         "nameForms: invalid",
         "matchingRuleUse: invalid");

    Schema.getSchema(Collections.singletonList(validSchemaFile), true);

    try
    {
      Schema.getSchema(Collections.singletonList(invalidSchemaFile), true);
      fail("Expected an exception when trying to read schema from a file " +
           "with invalid elements.");
    }
    catch (final LDIFException e)
    {
      // This was expected.
    }

    try
    {
      Schema.getSchema(Arrays.asList(validSchemaFile, invalidSchemaFile), true);
      fail("Expected an exception when trying to read schema from a file " +
           "with invalid elements.");
    }
    catch (final LDIFException e)
    {
      // This was expected
    }
  }



  /**
   * Tests the behavior when trying to read schema information when the
   * provided set of files is null.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSchemaNullFiles()
         throws Exception
  {
    try
    {
      Schema.getSchema((String[]) null);
      fail("Expected an exception when trying to read schema using a null " +
           "string array");
    }
    catch (LDAPSDKUsageException lsue)
    {
      // This was expected.
    }

    try
    {
      Schema.getSchema((File[]) null);
      fail("Expected an exception when trying to read schema using a null " +
           "file array");
    }
    catch (LDAPSDKUsageException lsue)
    {
      // This was expected.
    }

    try
    {
      Schema.getSchema((List<File>) null);
      fail("Expected an exception when trying to read schema using a null " +
           "file list");
    }
    catch (LDAPSDKUsageException lsue)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read schema information when no files
   * have been provided.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSchemaNoFiles()
         throws Exception
  {
    try
    {
      Schema.getSchema(new String[0]);
      fail("Expected an exception when trying to read schema using an " +
           "empty string array");
    }
    catch (LDAPSDKUsageException lsue)
    {
      // This was expected.
    }

    try
    {
      Schema.getSchema(new File[0]);
      fail("Expected an exception when trying to read schema using an " +
           "empty file array");
    }
    catch (LDAPSDKUsageException lsue)
    {
      // This was expected.
    }

    try
    {
      Schema.getSchema(Arrays.<File>asList());
      fail("Expected an exception when trying to read schema using an " +
           "empty file list");
    }
    catch (LDAPSDKUsageException lsue)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior when trying to read schema information from an empty
   * file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadSchemaFromEmptyFile()
         throws Exception
  {
    File emptyFile = createTempFile();

    Schema schema = Schema.getSchema(emptyFile.getAbsolutePath());
    assertNull(schema);

    schema = Schema.getSchema(emptyFile);
    assertNull(schema);

    List<File> fileList = Arrays.asList(emptyFile);
    schema = Schema.getSchema(fileList);
    assertNull(schema);
  }



  /**
   * Performs a number of tests to ensure that the default standard schema can
   * be retrieved and that it's valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultStandardSchema()
         throws Exception
  {
    final Schema schema = Schema.getDefaultStandardSchema();
    assertNotNull(schema);


    // Make sure that the schema entry only contains the following attributes:
    // - objectClass
    // - attributeTypes
    // - objectClasses
    // - cn
    final Entry schemaEntry = schema.getSchemaEntry();
    assertNotNull(schemaEntry);
    for (final Attribute a : schemaEntry.getAttributes())
    {
      final String name = StaticUtils.toLowerCase(a.getName());
      assertTrue(name.equals("objectclass") ||
           name.equals("attributetypes") ||
           name.equals("objectclasses") ||
           name.equals("ldapsyntaxes") ||
           name.equals("matchingrules") ||
           name.equals("cn"));
    }


    // Make sure that the number of attribute type definitions matches the
    // number of values for the attributeTypes attribute in the entry.
    assertEquals(schemaEntry.getAttribute("attributeTypes").size(),
         schema.getAttributeTypes().size());


    // Examine each attribute type defined in the schema to perform various
    // kinds of validation.
    for (final AttributeTypeDefinition at : schema.getAttributeTypes())
    {
      // Make sure that the attribute type OID is a valid numeric OID.
      final String oid = at.getOID();
      assertNotNull(oid);
      assertTrue(StaticUtils.isNumericOID(oid),
           "Attribute type " + at.toString() + " does not have a valid OID");

      // Make sure that each of the names is valid.
      for (final String name : at.getNames())
      {
        final StringBuilder invalidReason = new StringBuilder();
        assertTrue(PersistUtils.isValidLDAPName(name, invalidReason),
             "Attribute type " + at.toString() + " has an invalid name " +
                  name + ":  " + invalidReason);
      }

      // Make sure that for any attribute type with a superior type, that
      // superior type is also defined in the schema.
      final String superTypeName = at.getSuperiorType();
      if (superTypeName != null)
      {
        assertNotNull(schema.getAttributeType(superTypeName),
             "Attribute type " + at.toString() + " references superior type " +
                  superTypeName + " that is not defined in the schema.");
      }
    }


    // Make sure that the number of object class definitions matches the number
    // of values for the objectClasses attribute in the entry.
    assertEquals(schemaEntry.getAttribute("objectClasses").size(),
         schema.getObjectClasses().size());


    // Examine each of the object classes defined in the schema to perform
    // various kinds of validation.
    for (final ObjectClassDefinition oc : schema.getObjectClasses())
    {
      final String oid = oc.getOID();
      assertNotNull(oid);
      assertTrue(StaticUtils.isNumericOID(oid),
           "Object class " + oc.toString() + " does not have a valid OID");

      // Make sure that each of the names is valid.
      for (final String name : oc.getNames())
      {
        final StringBuilder invalidReason = new StringBuilder();
        assertTrue(PersistUtils.isValidLDAPName(name, invalidReason),
             "Object class " + oc.toString() + " has an invalid name " +
                  name + ":  " + invalidReason);
      }

      // Make sure that for any object class with a superior type, that superior
      // type is also defined in the schema.
      for (final String superClassName : oc.getSuperiorClasses())
      {
        assertNotNull(schema.getObjectClass(superClassName),
             "Object class " + oc.toString() + " references superior class " +
                  superClassName + " that is not defined in the schema.");
      }

      // Make sure that all of the required attribute types are defined in the
      // schema.
      for (final String attrName : oc.getRequiredAttributes())
      {
        assertNotNull(schema.getAttributeType(attrName),
             "Object class " + oc.toString() +
                  " references required attribute " + attrName +
                  " that is not defined in the schema.");
      }

      // Make sure that all of the optional attribute types are defined in the
      // schema.
      for (final String attrName : oc.getOptionalAttributes())
      {
        assertNotNull(schema.getAttributeType(attrName),
             "Object class " + oc.toString() +
                  " references optional attribute " + attrName +
                  " that is not defined in the schema.");
      }
    }
  }



  /**
   * Tests the behavior when trying to merge schemas.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMergeSchemas()
         throws Exception
  {
    Schema s = Schema.mergeSchemas((Schema[]) null);
    assertNull(s);

    assertNull(Schema.mergeSchemas());

    s = Schema.mergeSchemas(Schema.getDefaultStandardSchema());
    assertNotNull(s);
    assertNotNull(s.getAttributeType("cn"));
    assertNull(s.getAttributeType("1.2.3.3"));

    s = Schema.mergeSchemas(Schema.getDefaultStandardSchema(),
         Schema.getDefaultStandardSchema());
    assertNotNull(s);
    assertNotNull(s.getAttributeType("cn"));
    assertNull(s.getAttributeType("1.2.3.3"));

    final Entry e = new Entry(
         "dn: cn=schema",
         "ldapSyntaxes: ( 1.2.3.1 )",
         "matchingRules: ( 1.2.3.2 NAME 'test-mr' SYNTAX 1.2.3.1 )",
         "attributeTypes: ( 1.2.3.3 NAME 'test-at' )",
         "objectClasses: ( 1.2.3.4 NAME 'test-oc' STRUCTURAL MUST 1.2.3.3 )",
         "dITContentRules: ( 1.2.3.4 NAME 'test-dcr' )",
         "dITStructureRules: ( 5 FORM 1.2.3.6 )",
         "nameForms: ( 1.2.3.6 NAME 'test-nf' OC 1.2.3.4 MUST 1.2.3.3 )",
         "matchingRuleUse: ( 1.2.3.2 NAME 'test-mru' APPLIES 1.2.3.3 )");
    s = Schema.mergeSchemas(Schema.getDefaultStandardSchema(), new Schema(e));
    assertNotNull(s);
    assertNotNull(s.getAttributeType("cn"));
    assertNotNull(s.getAttributeType("1.2.3.3"));

    s = Schema.mergeSchemas(new Schema(e), Schema.getDefaultStandardSchema());
    assertNotNull(s);
    assertNotNull(s.getAttributeType("cn"));
    assertNotNull(s.getAttributeType("1.2.3.3"));
  }



  /**
   * Tests the behavior of the equals method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    final Schema emptySchemaEntry = new Schema(new Entry("cn=schema"));
    final Schema emptySchemaEntryWithDifferentDN =
         new Schema(new Entry("cn=subschema"));
    final Schema emptySchemaEntryWithMalformedDN =
         new Schema(new Entry("Malformed DN"));
    final Schema emptySchemaEntryWithDifferentMalformedDN =
         new Schema(new Entry("Different Malformed DN"));
    final Schema copyOfDefaultSchema = new Schema(
         Schema.getDefaultStandardSchema().getSchemaEntry());

    assertFalse(Schema.getDefaultStandardSchema().equals(null));
    assertFalse(Schema.getDefaultStandardSchema().equals("not schema"));
    assertTrue(Schema.getDefaultStandardSchema().equals(
         Schema.getDefaultStandardSchema()));
    assertTrue(Schema.getDefaultStandardSchema().equals(copyOfDefaultSchema));
    assertFalse(Schema.getDefaultStandardSchema().equals(emptySchemaEntry));
    assertFalse(Schema.getDefaultStandardSchema().equals(
         emptySchemaEntryWithDifferentDN));
    assertTrue(emptySchemaEntryWithMalformedDN.equals(
         new Schema(emptySchemaEntryWithMalformedDN.getSchemaEntry())));
    assertFalse(emptySchemaEntryWithMalformedDN.equals(
         emptySchemaEntryWithDifferentMalformedDN));

    Schema.getDefaultStandardSchema().hashCode();
    emptySchemaEntry.hashCode();
    emptySchemaEntryWithDifferentDN.hashCode();
    emptySchemaEntryWithMalformedDN.hashCode();
    emptySchemaEntryWithDifferentMalformedDN.hashCode();
  }
}
