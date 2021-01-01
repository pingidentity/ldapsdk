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



import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the AttributeTypeDefinition
 * class.
 */
public class AttributeTypeDefinitionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the minimal constructor with a minimal set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructorMinimalArguments()
         throws Exception
  {
    AttributeTypeDefinition at = new AttributeTypeDefinition("1.2.3.4", null,
         null, null, null, null, null, false, null);

    at = new AttributeTypeDefinition(at.toString());

    assertNotNull(at.getOID());
    assertEquals(at.getOID(), "1.2.3.4");

    assertNotNull(at.getNames());
    assertEquals(at.getNames().length, 0);

    assertNotNull(at.getNameOrOID());
    assertEquals(at.getNameOrOID(), "1.2.3.4");

    assertTrue(at.hasNameOrOID("1.2.3.4"));
    assertFalse(at.hasNameOrOID("some-name"));

    assertNull(at.getDescription());

    assertFalse(at.isObsolete());

    assertNull(at.getSuperiorType());

    assertNull(at.getEqualityMatchingRule());

    assertNull(at.getOrderingMatchingRule());

    assertNull(at.getSubstringMatchingRule());

    assertNull(at.getSyntaxOID());

    assertNull(at.getBaseSyntaxOID());

    assertEquals(at.getSyntaxMinimumUpperBound(), -1);

    assertFalse(at.isSingleValued());

    assertFalse(at.isCollective());

    assertFalse(at.isNoUserModification());

    assertNotNull(at.getUsage());
    assertEquals(at.getUsage(), AttributeUsage.USER_APPLICATIONS);

    assertFalse(at.isOperational());

    assertNotNull(at.getExtensions());
    assertTrue(at.getExtensions().isEmpty());

    assertNotNull(at.getSchemaElementType());
    assertEquals(at.getSchemaElementType(), SchemaElementType.ATTRIBUTE_TYPE);
  }



  /**
   * Tests the minimal constructor with a complete set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructorCompleteArguments()
         throws Exception
  {
    final LinkedHashMap<String,String[]> extensions =
         new LinkedHashMap<String,String[]>(2);
    extensions.put("X-EXT-1", new String[] { "a" });
    extensions.put("X-EXT-2", new String[] { "b", "c" });

    AttributeTypeDefinition at = new AttributeTypeDefinition("1.2.3.4",
         "the-name", "the description", "caseIgnoreMatch",
         "caseIgnoreOrderingMatch", "caseIgnoreSubstringsMatch", "1.2.3.5{678}",
         true, extensions);

    at = new AttributeTypeDefinition(at.toString());

    assertNotNull(at.getOID());
    assertEquals(at.getOID(), "1.2.3.4");

    assertNotNull(at.getNames());
    assertEquals(at.getNames().length, 1);
    assertEquals(at.getNames()[0], "the-name");

    assertNotNull(at.getNameOrOID());
    assertEquals(at.getNameOrOID(), "the-name");

    assertTrue(at.hasNameOrOID("1.2.3.4"));
    assertTrue(at.hasNameOrOID("the-name"));
    assertFalse(at.hasNameOrOID("some-other-name"));

    assertNotNull(at.getDescription());
    assertEquals(at.getDescription(), "the description");

    assertFalse(at.isObsolete());

    assertNull(at.getSuperiorType());

    assertNotNull(at.getEqualityMatchingRule());
    assertEquals(at.getEqualityMatchingRule(), "caseIgnoreMatch");

    assertNotNull(at.getOrderingMatchingRule());
    assertEquals(at.getOrderingMatchingRule(), "caseIgnoreOrderingMatch");

    assertNotNull(at.getSubstringMatchingRule());
    assertEquals(at.getSubstringMatchingRule(), "caseIgnoreSubstringsMatch");

    assertNotNull(at.getSyntaxOID());
    assertEquals(at.getSyntaxOID(), "1.2.3.5{678}");

    assertNotNull(at.getBaseSyntaxOID());
    assertEquals(at.getBaseSyntaxOID(), "1.2.3.5");

    assertEquals(at.getSyntaxMinimumUpperBound(), 678);

    assertTrue(at.isSingleValued());

    assertFalse(at.isCollective());

    assertFalse(at.isNoUserModification());

    assertNotNull(at.getUsage());
    assertEquals(at.getUsage(), AttributeUsage.USER_APPLICATIONS);

    assertFalse(at.isOperational());

    assertNotNull(at.getExtensions());
    assertEquals(at.getExtensions().size(), 2);
    assertEquals(at.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(at.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid attribute type definition
   * strings.
   *
   * @param  typeString    The string representation of the attribute type.
   * @param  oid           The OID for the attribute type.
   * @param  names         The set of names for the attribute type.
   * @param  description   The description for the attribute type.
   * @param  isObsolete    Indicates whether the attribute type is obsolete.
   * @param  superiorType  The name/OID of the superior type.
   * @param  eqRule        The equality matching rule for the attribute type.
   * @param  ordRule       The ordering matching rule for the attribute type.
   * @param  subRule       The substring matching rule for the attribute type.
   * @param  syntaxOID     The syntax OID for the attribute type.
   * @param  singleValued  Indicates whether the attribute type is
   *                       single-valued.
   * @param  collective    Indicates whether the attribute type is collective.
   * @param  noUserMod     Indicates whether the attribute type is
   *                       no-user-modification.
   * @param  usage         The usage for the attribute type.
   * @param  extensions    The set of extensions for the attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidTypeStrings")
  public void testConstructor1Valid(String typeString, String oid,
                                    String[] names, String description,
                                    boolean isObsolete, String superiorType,
                                    String eqRule, String ordRule,
                                    String subRule, String syntaxOID,
                                    boolean singleValued, boolean collective,
                                    boolean noUserMod, AttributeUsage usage,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    AttributeTypeDefinition at = new AttributeTypeDefinition(typeString);

    assertEquals(at.getOID(), oid);
    assertTrue(Arrays.equals(at.getNames(), names));
    assertNotNull(at.getNameOrOID());
    assertEquals(at.getDescription(), description);
    assertEquals(at.isObsolete(), isObsolete);
    assertEquals(at.getSuperiorType(), superiorType);
    assertEquals(at.getEqualityMatchingRule(), eqRule);
    assertEquals(at.getOrderingMatchingRule(), ordRule);
    assertEquals(at.getSubstringMatchingRule(), subRule);
    assertEquals(at.getSyntaxOID(), syntaxOID);
    assertEquals(at.isSingleValued(), singleValued);
    assertEquals(at.isCollective(), collective);
    assertEquals(at.isNoUserModification(), noUserMod);

    assertTrue(at.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(at.hasNameOrOID(name));
      }
    }
    assertFalse(at.hasNameOrOID("notAnAssignedName"));

    assertEquals(at.getUsage(), usage);
    if (usage == AttributeUsage.USER_APPLICATIONS)
    {
      assertFalse(at.isOperational());
    }
    else
    {
      assertTrue(at.isOperational());
    }

    assertEquals(at.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(at.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(at.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(at.toString(), typeString.trim());

    at.hashCode();
    assertTrue(at.equals(at));
  }



  /**
   * Tests the first constructor with a set of invalid attribute type definition
   * strings.
   *
   * @param  typeString  The invalid attribute type string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidTypeStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String typeString)
         throws Exception
  {
    new AttributeTypeDefinition(typeString);
  }



  /**
   * Tests the first constructor with {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1Null()
         throws Exception
  {
    new AttributeTypeDefinition(null);
  }



  /**
   * Tests the second constructor.
   *
   * @param  typeString    The string representation of the attribute type.
   * @param  oid           The OID for the attribute type.
   * @param  names         The set of names for the attribute type.
   * @param  description   The description for the attribute type.
   * @param  isObsolete    Indicates whether the attribute type is obsolete.
   * @param  superiorType  The name/OID of the superior type.
   * @param  eqRule        The equality matching rule for the attribute type.
   * @param  ordRule       The ordering matching rule for the attribute type.
   * @param  subRule       The substring matching rule for the attribute type.
   * @param  syntaxOID     The syntax OID for the attribute type.
   * @param  singleValued  Indicates whether the attribute type is
   *                       single-valued.
   * @param  collective    Indicates whether the attribute type is collective.
   * @param  noUserMod     Indicates whether the attribute type is
   *                       no-user-modification.
   * @param  usage         The usage for the attribute type.
   * @param  extensions    The set of extensions for the attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidTypeStrings")
  public void testConstructor2(String typeString, String oid,
                               String[] names, String description,
                               boolean isObsolete, String superiorType,
                               String eqRule, String ordRule, String subRule,
                               String syntaxOID, boolean singleValued,
                               boolean collective, boolean noUserMod,
                               AttributeUsage usage,
                               Map<String,String[]> extensions)
         throws Exception
  {
    AttributeTypeDefinition at =
         new AttributeTypeDefinition(oid, names, description, isObsolete,
                                     superiorType, eqRule, ordRule, subRule,
                                     syntaxOID, singleValued, collective,
                                     noUserMod, usage, extensions);

    assertEquals(at.getOID(), oid);
    assertTrue(Arrays.equals(at.getNames(), names));
    assertNotNull(at.getNameOrOID());
    assertEquals(at.getDescription(), description);
    assertEquals(at.isObsolete(), isObsolete);
    assertEquals(at.getSuperiorType(), superiorType);
    assertEquals(at.getEqualityMatchingRule(), eqRule);
    assertEquals(at.getOrderingMatchingRule(), ordRule);
    assertEquals(at.getSubstringMatchingRule(), subRule);
    assertEquals(at.getSyntaxOID(), syntaxOID);
    assertEquals(at.isSingleValued(), singleValued);
    assertEquals(at.isCollective(), collective);
    assertEquals(at.isNoUserModification(), noUserMod);

    assertTrue(at.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(at.hasNameOrOID(name));
      }
    }
    assertFalse(at.hasNameOrOID("notAnAssignedName"));

    assertEquals(at.getUsage(), usage);
    if (usage == AttributeUsage.USER_APPLICATIONS)
    {
      assertFalse(at.isOperational());
    }
    else
    {
      assertTrue(at.isOperational());
    }

    assertEquals(at.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(at.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(at.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(at.toString());

    AttributeTypeDefinition at2 = new AttributeTypeDefinition(at.toString());

    assertEquals(at2.getOID(), oid);
    assertTrue(Arrays.equals(at2.getNames(), names));
    assertNotNull(at2.getNameOrOID());
    assertEquals(at2.getDescription(), description);
    assertEquals(at2.isObsolete(), isObsolete);
    assertEquals(at2.getSuperiorType(), superiorType);
    assertEquals(at2.getEqualityMatchingRule(), eqRule);
    assertEquals(at2.getOrderingMatchingRule(), ordRule);
    assertEquals(at2.getSubstringMatchingRule(), subRule);
    assertEquals(at2.getSyntaxOID(), syntaxOID);
    assertEquals(at2.isSingleValued(), singleValued);
    assertEquals(at2.isCollective(), collective);
    assertEquals(at2.isNoUserModification(), noUserMod);

    assertEquals(at2.getUsage(), usage);
    if (usage == AttributeUsage.USER_APPLICATIONS)
    {
      assertFalse(at2.isOperational());
    }
    else
    {
      assertTrue(at2.isOperational());
    }

    assertEquals(at2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(at2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(at2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    at.hashCode();
    assertTrue(at.equals(at));
  }



  /**
   * Tests the second constructor, substituting {@code null} for the names,
   * usage, and extensions elements.
   *
   * @param  typeString    The string representation of the attribute type.
   * @param  oid           The OID for the attribute type.
   * @param  names         The set of names for the attribute type.
   * @param  description   The description for the attribute type.
   * @param  isObsolete    Indicates whether the attribute type is obsolete.
   * @param  superiorType  The name/OID of the superior type.
   * @param  eqRule        The equality matching rule for the attribute type.
   * @param  ordRule       The ordering matching rule for the attribute type.
   * @param  subRule       The substring matching rule for the attribute type.
   * @param  syntaxOID     The syntax OID for the attribute type.
   * @param  singleValued  Indicates whether the attribute type is
   *                       single-valued.
   * @param  collective    Indicates whether the attribute type is collective.
   * @param  noUserMod     Indicates whether the attribute type is
   *                       no-user-modification.
   * @param  usage         The usage for the attribute type.
   * @param  extensions    The set of extensions for the attribute type.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidTypeStrings")
  public void testConstructor2Nulls(String typeString, String oid,
                                    String[] names, String description,
                                    boolean isObsolete, String superiorType,
                                    String eqRule, String ordRule,
                                    String subRule, String syntaxOID,
                                    boolean singleValued, boolean collective,
                                    boolean noUserMod, AttributeUsage usage,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    AttributeTypeDefinition at =
         new AttributeTypeDefinition(oid, null, description, isObsolete,
                                     superiorType, eqRule, ordRule, subRule,
                                     syntaxOID, singleValued, collective,
                                     noUserMod, null, null);

    assertEquals(at.getOID(), oid);
    assertTrue(at.hasNameOrOID(oid));
    assertFalse(at.hasNameOrOID("notAnAssignedName"));
    assertNotNull(at.getNames());
    assertEquals(at.getNames().length, 0);
    assertNotNull(at.getNameOrOID());
    assertEquals(at.getDescription(), description);
    assertEquals(at.isObsolete(), isObsolete);
    assertEquals(at.getSuperiorType(), superiorType);
    assertEquals(at.getEqualityMatchingRule(), eqRule);
    assertEquals(at.getOrderingMatchingRule(), ordRule);
    assertEquals(at.getSubstringMatchingRule(), subRule);
    assertEquals(at.getSyntaxOID(), syntaxOID);
    assertEquals(at.isSingleValued(), singleValued);
    assertEquals(at.isCollective(), collective);
    assertEquals(at.isNoUserModification(), noUserMod);

    assertEquals(at.getUsage(), AttributeUsage.USER_APPLICATIONS);
    assertFalse(at.isOperational());

    assertNotNull(at.getExtensions());
    assertTrue(at.getExtensions().isEmpty());

    assertNotNull(at.toString());

    AttributeTypeDefinition at2 = new AttributeTypeDefinition(at.toString());

    assertEquals(at2.getOID(), oid);
    assertNotNull(at2.getNames());
    assertEquals(at2.getNames().length, 0);
    assertNotNull(at2.getNameOrOID());
    assertEquals(at2.getDescription(), description);
    assertEquals(at2.isObsolete(), isObsolete);
    assertEquals(at2.getSuperiorType(), superiorType);
    assertEquals(at2.getEqualityMatchingRule(), eqRule);
    assertEquals(at2.getOrderingMatchingRule(), ordRule);
    assertEquals(at2.getSubstringMatchingRule(), subRule);
    assertEquals(at2.getSyntaxOID(), syntaxOID);
    assertEquals(at2.isSingleValued(), singleValued);
    assertEquals(at2.isCollective(), collective);
    assertEquals(at2.isNoUserModification(), noUserMod);

    assertEquals(at2.getUsage(), AttributeUsage.USER_APPLICATIONS);
    assertFalse(at2.isOperational());

    assertNotNull(at2.getExtensions());
    assertTrue(at2.getExtensions().isEmpty());

    at.hashCode();
    assertTrue(at.equals(at));
  }



  /**
   * Performs a set of tests with attribute type definitions containing syntax
   * OIDs with a minimum upper bound component.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSyntaxWithMinUpperBound()
         throws Exception
  {
    String typeStr = "( 1.2.3.4 NAME ( 'firstName' 'secondName' ) " +
         "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
         "SUBSTR caseIgnoreSubstringsMatch USAGE distributedOperation " +
         "X-ONE-MULTI ( 'foo' 'bar' ) )";
    AttributeTypeDefinition at = new AttributeTypeDefinition(typeStr);

    assertNull(at.getSyntaxOID());

    assertNull(at.getBaseSyntaxOID());

    assertEquals(at.getSyntaxMinimumUpperBound(), -1);


    typeStr = "( 1.2.3.4 NAME ( 'firstName' 'secondName' ) " +
         "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
         "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 " +
         "USAGE distributedOperation " +
         "X-ONE-MULTI ( 'foo' 'bar' ) )";
    at = new AttributeTypeDefinition(typeStr);

    assertNotNull(at.getSyntaxOID());
    assertEquals(at.getSyntaxOID(), "1.2.3.5");

    assertNotNull(at.getBaseSyntaxOID());
    assertEquals(at.getBaseSyntaxOID(), "1.2.3.5");

    assertEquals(at.getSyntaxMinimumUpperBound(), -1);


    typeStr = "( 1.2.3.4 NAME ( 'firstName' 'secondName' ) " +
         "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
         "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5{123} " +
         "USAGE distributedOperation " +
         "X-ONE-MULTI ( 'foo' 'bar' ) )";
    at = new AttributeTypeDefinition(typeStr);

    assertNotNull(at.getSyntaxOID());
    assertEquals(at.getSyntaxOID(), "1.2.3.5{123}");

    assertNotNull(at.getBaseSyntaxOID());
    assertEquals(at.getBaseSyntaxOID(), "1.2.3.5");

    assertEquals(at.getSyntaxMinimumUpperBound(), 123);


    Entry schemaEntry = new Entry(
         "dn: cn=schema",
         "objectClass: top",
         "objectClass: ldapSubentry",
         "objectClass: subschemaSubentry",
         "attributeTypes: ( 1.2.3.4 NAME 'parent' SYNTAX 1.2.3.4.5{123} )",
         "attributeTypes: ( 1.2.3.5 NAME 'child' SUP parent )",
         "attributeTypes: ( 1.2.3.6 NAME 'minimal' )");
    Schema schema = new Schema(schemaEntry);

    at = schema.getAttributeType("parent");
    assertNotNull(at);

    assertNotNull(at.getSyntaxOID());
    assertEquals(at.getSyntaxOID(), "1.2.3.4.5{123}");

    assertNotNull(at.getBaseSyntaxOID());
    assertEquals(at.getBaseSyntaxOID(), "1.2.3.4.5");

    assertEquals(at.getSyntaxMinimumUpperBound(), 123);

    assertNotNull(at.getSyntaxOID(schema));
    assertEquals(at.getSyntaxOID(), "1.2.3.4.5{123}");

    assertNotNull(at.getBaseSyntaxOID(schema));
    assertEquals(at.getBaseSyntaxOID(), "1.2.3.4.5");

    assertEquals(at.getSyntaxMinimumUpperBound(schema), 123);


    at = schema.getAttributeType("child");
    assertNotNull(at);

    assertNull(at.getSyntaxOID());

    assertNull(at.getBaseSyntaxOID());

    assertEquals(at.getSyntaxMinimumUpperBound(), -1);

    assertNotNull(at.getSyntaxOID(schema));
    assertEquals(at.getSyntaxOID(schema), "1.2.3.4.5{123}");

    assertNotNull(at.getBaseSyntaxOID(schema));
    assertEquals(at.getBaseSyntaxOID(schema), "1.2.3.4.5");

    assertEquals(at.getSyntaxMinimumUpperBound(schema), 123);


    at = schema.getAttributeType("minimal");
    assertNotNull(at);

    assertNull(at.getSyntaxOID());

    assertNull(at.getBaseSyntaxOID());

    assertEquals(at.getSyntaxMinimumUpperBound(), -1);

    assertNull(at.getSyntaxOID(schema));

    assertNull(at.getBaseSyntaxOID(schema));

    assertEquals(at.getSyntaxMinimumUpperBound(), -1);


    String oid = "1.2.3.4";

    assertNotNull(AttributeTypeDefinition.getBaseSyntaxOID(oid));
    assertEquals(AttributeTypeDefinition.getBaseSyntaxOID(oid), "1.2.3.4");

    assertEquals(AttributeTypeDefinition.getSyntaxMinimumUpperBound(oid), -1);


    oid = "1.2.3.4{567}";

    assertNotNull(AttributeTypeDefinition.getBaseSyntaxOID(oid));
    assertEquals(AttributeTypeDefinition.getBaseSyntaxOID(oid), "1.2.3.4");

    assertEquals(AttributeTypeDefinition.getSyntaxMinimumUpperBound(oid), 567);


    oid = "1.2.3.4{}";

    assertNotNull(AttributeTypeDefinition.getBaseSyntaxOID(oid));
    assertEquals(AttributeTypeDefinition.getBaseSyntaxOID(oid), "1.2.3.4");

    assertEquals(AttributeTypeDefinition.getSyntaxMinimumUpperBound(oid), -1);


    oid = "1.2.3.4{";

    assertNotNull(AttributeTypeDefinition.getBaseSyntaxOID(oid));
    assertEquals(AttributeTypeDefinition.getBaseSyntaxOID(oid), "1.2.3.4");

    assertEquals(AttributeTypeDefinition.getSyntaxMinimumUpperBound(oid), -1);


    oid = "1.2.3.4{abc}";

    assertNotNull(AttributeTypeDefinition.getBaseSyntaxOID(oid));
    assertEquals(AttributeTypeDefinition.getBaseSyntaxOID(oid), "1.2.3.4");

    assertEquals(AttributeTypeDefinition.getSyntaxMinimumUpperBound(oid), -1);

    at.hashCode();
    assertTrue(at.equals(at));
  }



  /**
   * Retrieves a set of test data that may be used to create valid attribute
   * type definitions.
   *
   * @return  A set of test data that may be used to create valid attribute
   *          type definitions.
   */
  @DataProvider(name = "testValidTypeStrings")
  public Object[][] getTestValidTypeStrings()
  {
    LinkedHashMap<String,String[]> noExtensions =
         new LinkedHashMap<String,String[]>(0);

    LinkedHashMap<String,String[]> oneSingleValuedExtension =
         new LinkedHashMap<String,String[]>(1);
    oneSingleValuedExtension.put("X-ONE-SINGLE", new String[] { "foo" });

    LinkedHashMap<String,String[]> oneMultiValuedExtension =
         new LinkedHashMap<String,String[]>(1);
    oneMultiValuedExtension.put("X-ONE-MULTI", new String[] { "foo", "bar" });

    LinkedHashMap<String,String[]> twoSingleValuedExtensions =
         new LinkedHashMap<String,String[]>(2);
    twoSingleValuedExtensions.put("X-ONE-SINGLE", new String[] { "foo" });
    twoSingleValuedExtensions.put("X-TWO-SINGLE", new String[] { "bar" });

    LinkedHashMap<String,String[]> twoMultiValuedExtensions =
         new LinkedHashMap<String,String[]>(2);
    twoMultiValuedExtensions.put("X-ONE-MULTI", new String[] { "a", "b" });
    twoMultiValuedExtensions.put("X-TWO-MULTI", new String[] { "c", "d" });

    LinkedHashMap<String,String[]> twoMixedValuedExtensions =
         new LinkedHashMap<String,String[]>(2);
    twoMixedValuedExtensions.put("X-ONE-MULTI", new String[] { "a", "b" });
    twoMixedValuedExtensions.put("X-TWO-SINGLE", new String[] { "c" });

    return new Object[][]
    {
      new Object[]
      {
        "( 1.2.3.4 )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 OBSOLETE)",
        "1.2.3.4",
        new String[0],
        null,
        true,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 SINGLE-VALUE)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        true,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 COLLECTIVE)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        true,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 NO-USER-MODIFICATION)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        true,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 USAGE directoryOperation)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.DIRECTORY_OPERATION,
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
             "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
             "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 SINGLE-VALUE " +
             "COLLECTIVE NO-USER-MODIFICATION USAGE directoryOperation " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "superiorType",
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        true,
        true,
        true,
        AttributeUsage.DIRECTORY_OPERATION,
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
             "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
             "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 SINGLE-VALUE " +
             "COLLECTIVE NO-USER-MODIFICATION USAGE directoryOperation " +
             "X-ONE-MULTI ('a' 'b') X-TWO-SINGLE 'c')",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "superiorType",
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        true,
        true,
        true,
        AttributeUsage.DIRECTORY_OPERATION,
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'firstName' 'secondName' ) " +
             "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
             "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 " +
             "USAGE distributedOperation " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )",
        "1.2.3.4",
        new String[] { "firstName", "secondName" },
        null,
        false,
        null,
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        false,
        false,
        false,
        AttributeUsage.DISTRIBUTED_OPERATION,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'firstName' 'secondName') " +
             "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
             "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 " +
             "USAGE distributedOperation " +
             "X-ONE-MULTI ( 'foo' 'bar') )",
        "1.2.3.4",
        new String[] { "firstName", "secondName" },
        null,
        false,
        null,
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        false,
        false,
        false,
        AttributeUsage.DISTRIBUTED_OPERATION,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ('firstName' 'secondName' ) " +
             "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
             "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 " +
             "USAGE distributedOperation " +
             "X-ONE-MULTI ('foo' 'bar' ) )",
        "1.2.3.4",
        new String[] { "firstName", "secondName" },
        null,
        false,
        null,
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        false,
        false,
        false,
        AttributeUsage.DISTRIBUTED_OPERATION,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ('firstName' 'secondName') " +
             "EQUALITY caseIgnoreMatch ORDERING caseIgnoreOrderingMatch " +
             "SUBSTR caseIgnoreSubstringsMatch SYNTAX 1.2.3.5 " +
             "USAGE distributedOperation " +
             "X-ONE-MULTI ('foo' 'bar'))",
        "1.2.3.4",
        new String[] { "firstName", "secondName" },
        null,
        false,
        null,
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        false,
        false,
        false,
        AttributeUsage.DISTRIBUTED_OPERATION,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
             "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
             "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "superiorType",
        null,
        null,
        null,
        "1.2.3.5",
        true,
        true,
        true,
        AttributeUsage.DSA_OPERATION,
        twoSingleValuedExtensions
      },

      new Object[]
      {
        " ( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
             "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
             "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' ) ",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "superiorType",
        null,
        null,
        null,
        "1.2.3.5",
        true,
        true,
        true,
        AttributeUsage.DSA_OPERATION,
        twoSingleValuedExtensions
      },

      new Object[]
      {
        "(     1.2.3.4     NAME     'singleName'     DESC     'foo'     " +
             "OBSOLETE     SUP     superiorType     " +
             "EQUALITY     caseIgnoreMatch     " +
             "ORDERING     caseIgnoreOrderingMatch     " +
             "SUBSTR     caseIgnoreSubstringsMatch     " +
             "SYNTAX     1.2.3.5     SINGLE-VALUE     " +
             "COLLECTIVE     NO-USER-MODIFICATION     " +
             "USAGE     userApplications     " +
             "X-ONE-MULTI     (     'a'     'b'     )     " +
             "X-TWO-SINGLE     'c'     )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "superiorType",
        "caseIgnoreMatch",
        "caseIgnoreOrderingMatch",
        "caseIgnoreSubstringsMatch",
        "1.2.3.5",
        true,
        true,
        true,
        AttributeUsage.USER_APPLICATIONS,
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' )",
        "1.2.3.4",
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        null,
        null,
        null,
        null,
        null,
        false,
        false,
        false,
        AttributeUsage.USER_APPLICATIONS,
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid attribute
   * type definitions.
   *
   * @return  A set of test data that may not be used to create valid attribute
   *          type definitions.
   */
  @DataProvider(name = "testInvalidTypeStrings")
  public Object[][] getTestInvalidTypeStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "1.2.3.4"
      },

      new Object[]
      {
        "( 1.2.3.4"
      },

      new Object[]
      {
        "( 1.2.3.4 ) DESC 'foo' )"
      },

      new Object[]
      {
        "( 1.2.3.4 INVALID )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' DESC 'bar' )",
      },

      new Object[]
      {
        "( 1.2.3.4 X-FOO 'one' X-FOO 'two' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' INVALID )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' X-NO-VALUE )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' X-NO-VALUE ( ) )",
      },

      new Object[]
      {
        "( DESC 'foo' )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME '' )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( ) )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ("
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( "
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( )"
      },

      new Object[]
      {
        "( 1.2.3.4 USAGE invalid )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'first' NAME 'second' )",
      },

      new Object[]
      {
        "( 1.2.3.4 OBSOLETE OBSOLETE )",
      },

      new Object[]
      {
        "( 1.2.3.4 SUP first SUP second )",
      },

      new Object[]
      {
        "( 1.2.3.4 EQUALITY first EQUALITY second )",
      },

      new Object[]
      {
        "( 1.2.3.4 ORDERING first ORDERING second )",
      },

      new Object[]
      {
        "( 1.2.3.4 SUBSTR first SUBSTR second )",
      },

      new Object[]
      {
        "( 1.2.3.4 SYNTAX 1.2.3.5 SYNTAX 1.2.3.6 )",
      },

      new Object[]
      {
        "( 1.2.3.4 SINGLE-VALUE SINGLE-VALUE )",
      },

      new Object[]
      {
        "( 1.2.3.4 COLLECTIVE COLLECTIVE )",
      },

      new Object[]
      {
        "( 1.2.3.4 NO-USER-MODIFICATION NO-USER-MODIFICATION )",
      },

      new Object[]
      {
        "( 1.2.3.4 USAGE directoryOperation USAGE distributedOperation )",
      },
    };
  }



  /**
   * Provides test coverage for the {@code equals} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    final AttributeTypeDefinition at1 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");

    assertFalse(at1.equals(null));

    assertTrue(at1.equals(at1));

    assertFalse(at1.equals("foo"));

    AttributeTypeDefinition at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertTrue(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleNAME' DESC 'FOO' OBSOLETE SUP superiorTYPE " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertTrue(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.5 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'otherName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'bar' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP differentType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.6 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE " +
              "USAGE dSAOperation X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE userApplications X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));

    at2 = new AttributeTypeDefinition(
         "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SUP superiorType " +
              "SYNTAX 1.2.3.5 SINGLE-VALUE COLLECTIVE NO-USER-MODIFICATION " +
              "USAGE dSAOperation X-ONE-SINGLE 'bar' X-TWO-SINGLE 'bar' )");
    assertFalse(at1.equals(at2));
  }



  /**
   * Tests to ensure that empty descriptions can be allowed if the LDAP SDK is
   * configured to permit it.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAllowEmptyDescription()
         throws Exception
  {
    try
    {
      assertFalse(SchemaElement.allowEmptyDescription());
      new AttributeTypeDefinition("( 1.2.3.4 DESC '' )");
      fail("Expected an exception for a schema element with an empty " +
           "description");
    }
    catch (final LDAPException e)
    {
      // This was expected.
    }

    try
    {
      assertFalse(SchemaElement.allowEmptyDescription());
      SchemaElement.setAllowEmptyDescription(true);
      assertTrue(SchemaElement.allowEmptyDescription());

      final AttributeTypeDefinition definition =
           new AttributeTypeDefinition("( 1.2.3.4 DESC '' )");
      assertNotNull(definition.getDescription());
      assertEquals(definition.getDescription(), "");
    }
    finally
    {
      SchemaElement.setAllowEmptyDescription(false);
      assertFalse(SchemaElement.allowEmptyDescription());
    }
  }
}
