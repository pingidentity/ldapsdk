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
import java.util.List;
import java.util.Map;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the DITContentRuleDefinition
 * class.
 */
public class DITContentRuleDefinitionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the minimal constructor that uses arrays for
   * multivalued elements with a minimal set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalArrayConstructorMinimalArguments()
         throws Exception
  {
    DITContentRuleDefinition dcr = new DITContentRuleDefinition("1.2.3.4", null,
         null, (String[]) null, null, null, null, null);

    dcr = new DITContentRuleDefinition(dcr.toString());

    assertNotNull(dcr.getOID());
    assertEquals(dcr.getOID(), "1.2.3.4");

    assertNotNull(dcr.getNames());
    assertEquals(dcr.getNames().length, 0);

    assertNotNull(dcr.getNameOrOID());
    assertEquals(dcr.getNameOrOID(), "1.2.3.4");

    assertTrue(dcr.hasNameOrOID("1.2.3.4"));
    assertFalse(dcr.hasNameOrOID("some-name"));

    assertNull(dcr.getDescription());

    assertFalse(dcr.isObsolete());

    assertNotNull(dcr.getAuxiliaryClasses());
    assertEquals(dcr.getAuxiliaryClasses().length, 0);

    assertNotNull(dcr.getRequiredAttributes());
    assertEquals(dcr.getRequiredAttributes().length, 0);

    assertNotNull(dcr.getOptionalAttributes());
    assertEquals(dcr.getOptionalAttributes().length, 0);

    assertNotNull(dcr.getProhibitedAttributes());
    assertEquals(dcr.getProhibitedAttributes().length, 0);

    assertNotNull(dcr.getExtensions());
    assertTrue(dcr.getExtensions().isEmpty());

    assertNotNull(dcr.getSchemaElementType());
    assertEquals(dcr.getSchemaElementType(),
         SchemaElementType.DIT_CONTENT_RULE);
  }



  /**
   * Provides test coverage for the minimal constructor that uses collections
   * for multivalued elements with a minimal set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalCollectionConstructorMinimalArguments()
         throws Exception
  {
    DITContentRuleDefinition dcr = new DITContentRuleDefinition("1.2.3.4", null,
         null, (List<String>) null, null, null, null, null);

    dcr = new DITContentRuleDefinition(dcr.toString());

    assertNotNull(dcr.getOID());
    assertEquals(dcr.getOID(), "1.2.3.4");

    assertNotNull(dcr.getNames());
    assertEquals(dcr.getNames().length, 0);

    assertNotNull(dcr.getNameOrOID());
    assertEquals(dcr.getNameOrOID(), "1.2.3.4");

    assertTrue(dcr.hasNameOrOID("1.2.3.4"));
    assertFalse(dcr.hasNameOrOID("some-name"));

    assertNull(dcr.getDescription());

    assertFalse(dcr.isObsolete());

    assertNotNull(dcr.getAuxiliaryClasses());
    assertEquals(dcr.getAuxiliaryClasses().length, 0);

    assertNotNull(dcr.getRequiredAttributes());
    assertEquals(dcr.getRequiredAttributes().length, 0);

    assertNotNull(dcr.getOptionalAttributes());
    assertEquals(dcr.getOptionalAttributes().length, 0);

    assertNotNull(dcr.getProhibitedAttributes());
    assertEquals(dcr.getProhibitedAttributes().length, 0);

    assertNotNull(dcr.getExtensions());
    assertTrue(dcr.getExtensions().isEmpty());
  }



  /**
   * Provides test coverage for the minimal constructor that uses arrays for
   * multivalued elements with a full set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalArrayConstructorAllArguments()
         throws Exception
  {
    final LinkedHashMap<String,String[]> extensions =
         new LinkedHashMap<String,String[]>(2);
    extensions.put("X-EXT-1", new String[] { "a" });
    extensions.put("X-EXT-2", new String[] { "b", "c" });

    DITContentRuleDefinition dcr = new DITContentRuleDefinition("1.2.3.4",
         "the-name", "the description", new String[] { "a1", "a2" },
         new String[] { "r1", "r2" }, new String[] { "o1", "o2" },
         new String[] { "p1", "p2" }, extensions);

    dcr = new DITContentRuleDefinition(dcr.toString());

    assertNotNull(dcr.getOID());
    assertEquals(dcr.getOID(), "1.2.3.4");

    assertNotNull(dcr.getNames());
    assertEquals(dcr.getNames().length, 1);

    assertNotNull(dcr.getNameOrOID());
    assertEquals(dcr.getNameOrOID(), "the-name");

    assertTrue(dcr.hasNameOrOID("1.2.3.4"));
    assertTrue(dcr.hasNameOrOID("the-name"));
    assertFalse(dcr.hasNameOrOID("some-other-name"));

    assertNotNull(dcr.getDescription());
    assertEquals(dcr.getDescription(), "the description");

    assertFalse(dcr.isObsolete());

    assertNotNull(dcr.getAuxiliaryClasses());
    assertEquals(dcr.getAuxiliaryClasses(), new String[] { "a1", "a2" });

    assertNotNull(dcr.getRequiredAttributes());
    assertEquals(dcr.getRequiredAttributes(), new String[] { "r1", "r2" });

    assertNotNull(dcr.getOptionalAttributes());
    assertEquals(dcr.getOptionalAttributes(), new String[] { "o1", "o2" });

    assertNotNull(dcr.getProhibitedAttributes());
    assertEquals(dcr.getProhibitedAttributes(), new String[] { "p1", "p2" });

    assertNotNull(dcr.getExtensions());
    assertEquals(dcr.getExtensions().size(), 2);
    assertEquals(dcr.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(dcr.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Provides test coverage for the minimal constructor that uses collections
   * for multivalued elements with a full set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalCollectionConstructorAllArguments()
         throws Exception
  {
    final LinkedHashMap<String,String[]> extensions =
         new LinkedHashMap<String,String[]>(2);
    extensions.put("X-EXT-1", new String[] { "a" });
    extensions.put("X-EXT-2", new String[] { "b", "c" });

    DITContentRuleDefinition dcr = new DITContentRuleDefinition("1.2.3.4",
         "the-name", "the description", Arrays.asList("a1", "a2"),
         Arrays.asList("r1", "r2"), Arrays.asList("o1", "o2"),
         Arrays.asList("p1", "p2"), extensions);

    dcr = new DITContentRuleDefinition(dcr.toString());

    assertNotNull(dcr.getOID());
    assertEquals(dcr.getOID(), "1.2.3.4");

    assertNotNull(dcr.getNames());
    assertEquals(dcr.getNames().length, 1);

    assertNotNull(dcr.getNameOrOID());
    assertEquals(dcr.getNameOrOID(), "the-name");

    assertTrue(dcr.hasNameOrOID("1.2.3.4"));
    assertTrue(dcr.hasNameOrOID("the-name"));
    assertFalse(dcr.hasNameOrOID("some-other-name"));

    assertNotNull(dcr.getDescription());
    assertEquals(dcr.getDescription(), "the description");

    assertFalse(dcr.isObsolete());

    assertNotNull(dcr.getAuxiliaryClasses());
    assertEquals(dcr.getAuxiliaryClasses(), new String[] { "a1", "a2" });

    assertNotNull(dcr.getRequiredAttributes());
    assertEquals(dcr.getRequiredAttributes(), new String[] { "r1", "r2" });

    assertNotNull(dcr.getOptionalAttributes());
    assertEquals(dcr.getOptionalAttributes(), new String[] { "o1", "o2" });

    assertNotNull(dcr.getProhibitedAttributes());
    assertEquals(dcr.getProhibitedAttributes(), new String[] { "p1", "p2" });

    assertNotNull(dcr.getExtensions());
    assertEquals(dcr.getExtensions().size(), 2);
    assertEquals(dcr.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(dcr.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid DIT content rule definition
   * strings.
   *
   * @param  dcrString        The string representation for this rule.
   * @param  oid              The OID for this rule.
   * @param  names            The set of names for this rule.
   * @param  description      The description for this rule.
   * @param  obsolete         Indicates whether this rule is obsolete.
   * @param  auxClasses       The names/OIDs of the allowed auxiliary classes.
   * @param  requiredAttrs    The names/OIDs of the required attributes.
   * @param  optionalAttrs    The names/OIDs of the optional attributes.
   * @param  prohibitedAttrs  The names/OIDs of the prohibited attributes.
   * @param  extensions       The set of extensions for this rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDCRStrings")
  public void testConstructor1Valid(String dcrString, String oid,
                                    String[] names, String description,
                                    boolean obsolete, String[] auxClasses,
                                    String[] requiredAttrs,
                                    String[] optionalAttrs,
                                    String[] prohibitedAttrs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    DITContentRuleDefinition dcr = new DITContentRuleDefinition(dcrString);

    assertEquals(dcr.getOID(), oid);

    assertTrue(Arrays.equals(dcr.getNames(), names));
    assertNotNull(dcr.getNameOrOID());

    assertTrue(dcr.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(dcr.hasNameOrOID(name));
      }
    }
    assertFalse(dcr.hasNameOrOID("notAnAssignedName"));

    assertEquals(dcr.getDescription(), description);

    assertEquals(dcr.isObsolete(), obsolete);

    assertTrue(Arrays.equals(dcr.getAuxiliaryClasses(), auxClasses));

    assertTrue(Arrays.equals(dcr.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(dcr.getOptionalAttributes(), optionalAttrs));

    assertTrue(Arrays.equals(dcr.getProhibitedAttributes(), prohibitedAttrs));

    assertEquals(dcr.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(dcr.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(dcr.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(dcr.toString(), dcrString.trim());

    dcr.hashCode();
    assertTrue(dcr.equals(dcr));
  }



  /**
   * Tests the first constructor with a set of invalid DIT content rule
   * definition strings.
   *
   * @param  dcrString  The invalid DIT content rule string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidDCRStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String dcrString)
         throws Exception
  {
    new DITContentRuleDefinition(dcrString);
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
    new DITContentRuleDefinition(null);
  }



  /**
   * Tests the second constructor with a set of valid DIT content rule
   * definition strings.
   *
   * @param  dcrString        The string representation for this rule.
   * @param  oid              The OID for this rule.
   * @param  names            The set of names for this rule.
   * @param  description      The description for this rule.
   * @param  obsolete         Indicates whether this rule is obsolete.
   * @param  auxClasses       The names/OIDs of the allowed auxiliary classes.
   * @param  requiredAttrs    The names/OIDs of the required attributes.
   * @param  optionalAttrs    The names/OIDs of the optional attributes.
   * @param  prohibitedAttrs  The names/OIDs of the prohibited attributes.
   * @param  extensions       The set of extensions for this rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDCRStrings")
  public void testConstructor2(String dcrString, String oid, String[] names,
                               String description, boolean obsolete,
                               String[] auxClasses, String[] requiredAttrs,
                               String[] optionalAttrs, String[] prohibitedAttrs,
                               Map<String,String[]> extensions)
         throws Exception
  {
    DITContentRuleDefinition dcr =
         new DITContentRuleDefinition(oid, names, description, obsolete,
                                      auxClasses, requiredAttrs, optionalAttrs,
                                      prohibitedAttrs, extensions);

    assertEquals(dcr.getOID(), oid);

    assertTrue(Arrays.equals(dcr.getNames(), names));
    assertNotNull(dcr.getNameOrOID());

    assertTrue(dcr.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(dcr.hasNameOrOID(name));
      }
    }
    assertFalse(dcr.hasNameOrOID("notAnAssignedName"));

    assertEquals(dcr.getDescription(), description);

    assertEquals(dcr.isObsolete(), obsolete);

    assertTrue(Arrays.equals(dcr.getAuxiliaryClasses(), auxClasses));

    assertTrue(Arrays.equals(dcr.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(dcr.getOptionalAttributes(), optionalAttrs));

    assertTrue(Arrays.equals(dcr.getProhibitedAttributes(), prohibitedAttrs));

    assertEquals(dcr.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(dcr.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(dcr.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(dcr.toString());
    DITContentRuleDefinition dcr2 =
         new DITContentRuleDefinition(dcr.toString());

    assertEquals(dcr2.getOID(), oid);

    assertTrue(Arrays.equals(dcr2.getNames(), names));
    assertNotNull(dcr2.getNameOrOID());

    assertEquals(dcr2.getDescription(), description);

    assertEquals(dcr2.isObsolete(), obsolete);

    assertTrue(Arrays.equals(dcr2.getAuxiliaryClasses(), auxClasses));

    assertTrue(Arrays.equals(dcr2.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(dcr2.getOptionalAttributes(), optionalAttrs));

    assertTrue(Arrays.equals(dcr2.getProhibitedAttributes(), prohibitedAttrs));

    assertEquals(dcr2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(dcr2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(dcr2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    dcr.hashCode();
    assertTrue(dcr.equals(dcr));
  }



  /**
   * Tests the second constructor, substituting {@code null} values for the
   * names, auxClasses, requiredAttrs, optionalAttrs, prohibitedAttrs, and
   * extensions elements.
   *
   * @param  dcrString        The string representation for this rule.
   * @param  oid              The OID for this rule.
   * @param  names            The set of names for this rule.
   * @param  description      The description for this rule.
   * @param  obsolete         Indicates whether this rule is obsolete.
   * @param  auxClasses       The names/OIDs of the allowed auxiliary classes.
   * @param  requiredAttrs    The names/OIDs of the required attributes.
   * @param  optionalAttrs    The names/OIDs of the optional attributes.
   * @param  prohibitedAttrs  The names/OIDs of the prohibited attributes.
   * @param  extensions       The set of extensions for this rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDCRStrings")
  public void testConstructor2Nulls(String dcrString, String oid,
                                    String[] names, String description,
                                    boolean obsolete, String[] auxClasses,
                                    String[] requiredAttrs,
                                    String[] optionalAttrs,
                                    String[] prohibitedAttrs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    DITContentRuleDefinition dcr =
         new DITContentRuleDefinition(oid, null, description, obsolete, null,
                                      null, null, null, null);

    assertEquals(dcr.getOID(), oid);
    assertTrue(dcr.hasNameOrOID(oid));
    assertFalse(dcr.hasNameOrOID("notAnAssignedName"));

    assertNotNull(dcr.getNames());
    assertEquals(dcr.getNames().length, 0);

    assertEquals(dcr.getDescription(), description);

    assertEquals(dcr.isObsolete(), obsolete);

    assertNotNull(dcr.getAuxiliaryClasses());
    assertEquals(dcr.getAuxiliaryClasses().length, 0);

    assertNotNull(dcr.getRequiredAttributes());
    assertEquals(dcr.getRequiredAttributes().length, 0);

    assertNotNull(dcr.getOptionalAttributes());
    assertEquals(dcr.getOptionalAttributes().length, 0);

    assertNotNull(dcr.getProhibitedAttributes());
    assertEquals(dcr.getProhibitedAttributes().length, 0);

    assertNotNull(dcr.getExtensions());
    assertTrue(dcr.getExtensions().isEmpty());

    assertNotNull(dcr.toString());
    DITContentRuleDefinition dcr2 =
         new DITContentRuleDefinition(dcr.toString());

    assertEquals(dcr2.getOID(), oid);

    assertNotNull(dcr2.getNames());
    assertEquals(dcr2.getNames().length, 0);

    assertEquals(dcr2.getDescription(), description);

    assertEquals(dcr2.isObsolete(), obsolete);

    assertNotNull(dcr2.getAuxiliaryClasses());
    assertEquals(dcr2.getAuxiliaryClasses().length, 0);

    assertNotNull(dcr2.getRequiredAttributes());
    assertEquals(dcr2.getRequiredAttributes().length, 0);

    assertNotNull(dcr2.getOptionalAttributes());
    assertEquals(dcr2.getOptionalAttributes().length, 0);

    assertNotNull(dcr2.getProhibitedAttributes());
    assertEquals(dcr2.getProhibitedAttributes().length, 0);

    assertNotNull(dcr2.getExtensions());
    assertTrue(dcr2.getExtensions().isEmpty());

    dcr.hashCode();
    assertTrue(dcr.equals(dcr));
  }



  /**
   * Retrieves a set of test data that may be used to create valid DIT content
   * rule definitions.
   *
   * @return  A set of test data that may be used to create valid DIT content
   *          rule definitions.
   */
  @DataProvider(name = "testValidDCRStrings")
  public Object[][] getTestValidDCRStrings()
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
        new String[0],
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[0],
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[0],
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[0],
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 OBSOLETE)",
        "1.2.3.4",
        new String[0],
        null,
        true,
        new String[0],
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE AUX posixGroup " +
             "MUST cn MAY description NOT uid X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        new String[] { "posixGroup" },
        new String[] { "cn" },
        new String[] { "description" },
        new String[] { "uid" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE AUX posixGroup " +
             "MUST cn MAY description NOT uid X-ONE-SINGLE 'foo')",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        new String[] { "posixGroup" },
        new String[] { "cn" },
        new String[] { "description" },
        new String[] { "uid" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE AUX posixGroup " +
             "MUST cn MAY description NOT uid X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        new String[] { "posixGroup" },
        new String[] { "cn" },
        new String[] { "description" },
        new String[] { "uid" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE AUX posixGroup " +
             "MUST cn MAY description NOT uid X-ONE-SINGLE 'foo')",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        new String[] { "posixGroup" },
        new String[] { "cn" },
        new String[] { "description" },
        new String[] { "uid" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
             "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) NOT ( not1 $ not2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "aux1", "aux2" },
        new String[] { "must1", "must2" },
        new String[] { "may1", "may2" },
        new String[] { "not1", "not2" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(1.2.3.4 NAME ('first' 'second') AUX (aux1$aux2) " +
             "MUST (must1$must2) MAY (may1$may2) NOT (not1$not2) " +
             "X-ONE-MULTI ('a' 'b') X-TWO-SINGLE 'c')",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "aux1", "aux2" },
        new String[] { "must1", "must2" },
        new String[] { "may1", "may2" },
        new String[] { "not1", "not2" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        " ( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
             "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) NOT ( not1 $ not2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' ) ",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "aux1", "aux2" },
        new String[] { "must1", "must2" },
        new String[] { "may1", "may2" },
        new String[] { "not1", "not2" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(     1.2.3.4     NAME     (     'first'     'second'     )     " +
             "AUX     (     aux1     $     aux2     )     " +
             "MUST     (     must1     $     must2     )     " +
             "MAY     may1     " +
             "NOT     (     not1     $     not2     )     " +
             "X-ONE-MULTI     (     'foo'     'bar'     )     )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "aux1", "aux2" },
        new String[] { "must1", "must2" },
        new String[] { "may1" },
        new String[] { "not1", "not2" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' )",
        "1.2.3.4",
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        new String[0],
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 AUX 'quoted' )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "quoted" },
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 AUX 'quoted')",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "quoted" },
        new String[0],
        new String[0],
        new String[0],
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid DIT
   * content rule definitions.
   *
   * @return  A set of test data that may not be used to create valid DIT
   *          content rule definitions.
   */
  @DataProvider(name = "testInvalidDCRStrings")
  public Object[][] getTestInvalidDCRStrings()
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
        "( 1.2.3.4 NAME 'first' NAME 'second' )",
      },

      new Object[]
      {
        "( 1.2.3.4 OBSOLETE OBSOLETE )",
      },

      new Object[]
      {
        "( 1.2.3.4 AUX first AUX second )",
      },

      new Object[]
      {
        "( 1.2.3.4 MUST first MUST second )",
      },

      new Object[]
      {
        "( 1.2.3.4 MAY first MAY second )",
      },

      new Object[]
      {
        "( 1.2.3.4 NOT first NOT second )",
      },

      new Object[]
      {
        "( 1.2.3.4 AUX contains'a'quote )",
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
    final DITContentRuleDefinition dcr1 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");

    assertFalse(dcr1.equals(null));

    assertTrue(dcr1.equals(dcr1));

    assertFalse(dcr1.equals("foo"));

    DITContentRuleDefinition dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertTrue(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'FIRST' 'SECOND' ) AUX ( AUX1 $ AUX2 ) " +
              "MUST ( MUST1 $ MUST2 ) MAY ( MAY1 $ MAY2 ) " +
              "NOT ( NOT1 $ NOT2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertTrue(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.5 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'one' 'two' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux3 $ aux4 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must3 $ must4 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may3 $ may4 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not3 $ not4 ) X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));

    dcr2 = new DITContentRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) AUX ( aux1 $ aux2 ) " +
              "MUST ( must1 $ must2 ) MAY ( may1 $ may2 ) " +
              "NOT ( not1 $ not2 ) X-ONE-MULTI ( 'c' 'd' ) X-TWO-SINGLE 'c' )");
    assertFalse(dcr1.equals(dcr2));
  }
}
