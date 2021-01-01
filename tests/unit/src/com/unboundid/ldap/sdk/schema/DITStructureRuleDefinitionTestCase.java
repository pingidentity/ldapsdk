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

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the DITStructureRuleDefinition
 * class.
 */
public class DITStructureRuleDefinitionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the minimal constructor with a minimal set of
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructorMinimalArguments()
         throws Exception
  {
    DITStructureRuleDefinition dsr = new DITStructureRuleDefinition(1, null,
         null, "name-form", null, null);

    dsr = new DITStructureRuleDefinition(dsr.toString());

    assertEquals(dsr.getRuleID(), 1);

    assertNotNull(dsr.getNames());
    assertEquals(dsr.getNames().length, 0);

    assertNotNull(dsr.getNameOrRuleID());
    assertEquals(dsr.getNameOrRuleID(), "1");

    assertTrue(dsr.hasNameOrRuleID("1"));
    assertFalse(dsr.hasNameOrRuleID("some-name"));

    assertNull(dsr.getDescription());

    assertFalse(dsr.isObsolete());

    assertNotNull(dsr.getNameFormID());
    assertEquals(dsr.getNameFormID(), "name-form");

    assertNotNull(dsr.getSuperiorRuleIDs());
    assertEquals(dsr.getSuperiorRuleIDs().length, 0);

    assertNotNull(dsr.getExtensions());
    assertTrue(dsr.getExtensions().isEmpty());

    assertNotNull(dsr.getSchemaElementType());
    assertEquals(dsr.getSchemaElementType(),
         SchemaElementType.DIT_STRUCTURE_RULE);
  }



  /**
   * Provides test coverage for the minimal constructor with a full set of
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructorAllArguments()
         throws Exception
  {
    final LinkedHashMap<String,String[]> extensions =
         new LinkedHashMap<String,String[]>(2);
    extensions.put("X-EXT-1", new String[] { "a" });
    extensions.put("X-EXT-2", new String[] { "b", "c" });

    DITStructureRuleDefinition dsr = new DITStructureRuleDefinition(2,
         "the-name", "the description", "name-form", 1, extensions);

    dsr = new DITStructureRuleDefinition(dsr.toString());

    assertEquals(dsr.getRuleID(), 2);

    assertNotNull(dsr.getNames());
    assertEquals(dsr.getNames().length, 1);

    assertNotNull(dsr.getNameOrRuleID());
    assertEquals(dsr.getNameOrRuleID(), "the-name");

    assertTrue(dsr.hasNameOrRuleID("2"));
    assertTrue(dsr.hasNameOrRuleID("the-name"));
    assertFalse(dsr.hasNameOrRuleID("some-other-name"));

    assertNotNull(dsr.getDescription());
    assertEquals(dsr.getDescription(), "the description");

    assertFalse(dsr.isObsolete());

    assertNotNull(dsr.getNameFormID());
    assertEquals(dsr.getNameFormID(), "name-form");

    assertNotNull(dsr.getSuperiorRuleIDs());
    assertEquals(dsr.getSuperiorRuleIDs().length, 1);
    assertEquals(dsr.getSuperiorRuleIDs()[0], 1);

    assertNotNull(dsr.getExtensions());
    assertEquals(dsr.getExtensions().size(), 2);
    assertEquals(dsr.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(dsr.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid DIT structure rule
   * definition strings.
   *
   * @param  dsrString        The string representation for this rule.
   * @param  ruleID           The rule IDfor this rule.
   * @param  names            The set of names for this rule.
   * @param  description      The description for this rule.
   * @param  obsolete         Indicates whether this rule is obsolete.
   * @param  nameFormID       The name/OID for the associated name form.
   * @param  supIDs           The rule IDs for the superior rules.
   * @param  extensions       The set of extensions for this rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDSRStrings")
  public void testConstructor1Valid(String dsrString, int ruleID,
                                    String[] names, String description,
                                    boolean obsolete, String nameFormID,
                                    int[] supIDs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    DITStructureRuleDefinition dsr = new DITStructureRuleDefinition(dsrString);

    assertEquals(dsr.getRuleID(), ruleID);

    assertTrue(Arrays.equals(dsr.getNames(), names));
    assertNotNull(dsr.getNameOrRuleID());

    assertTrue(dsr.hasNameOrRuleID(String.valueOf(ruleID)));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(dsr.hasNameOrRuleID(name));
      }
    }
    assertFalse(dsr.hasNameOrRuleID("notAnAssignedName"));

    assertEquals(dsr.getDescription(), description);

    assertEquals(dsr.isObsolete(), obsolete);

    assertEquals(dsr.getNameFormID(), nameFormID);

    assertTrue(Arrays.equals(dsr.getSuperiorRuleIDs(), supIDs));

    assertEquals(dsr.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(dsr.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(dsr.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(dsr.toString(), dsrString.trim());

    dsr.hashCode();
    assertTrue(dsr.equals(dsr));
  }



  /**
   * Tests the first constructor with a set of invalid DIT structure rule
   * definition strings.
   *
   * @param  dsrString  The invalid DIT structure rule string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidDSRStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String dsrString)
         throws Exception
  {
    new DITStructureRuleDefinition(dsrString);
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
    new DITStructureRuleDefinition(null);
  }



  /**
   * Tests the second constructor with a set of valid DIT structure rule
   * definition strings.
   *
   * @param  dsrString        The string representation for this rule.
   * @param  ruleID           The rule IDfor this rule.
   * @param  names            The set of names for this rule.
   * @param  description      The description for this rule.
   * @param  obsolete         Indicates whether this rule is obsolete.
   * @param  nameFormID       The name/OID for the associated name form.
   * @param  supIDs           The rule IDs for the superior rules.
   * @param  extensions       The set of extensions for this rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDSRStrings")
  public void testConstructor2(String dsrString, int ruleID, String[] names,
                              String description, boolean obsolete,
                              String nameFormID, int[] supIDs,
                              Map<String,String[]> extensions)
         throws Exception
  {
    DITStructureRuleDefinition dsr =
         new DITStructureRuleDefinition(ruleID, names, description, obsolete,
                                        nameFormID, supIDs, extensions);

    assertEquals(dsr.getRuleID(), ruleID);

    assertTrue(Arrays.equals(dsr.getNames(), names));
    assertNotNull(dsr.getNameOrRuleID());

    assertTrue(dsr.hasNameOrRuleID(String.valueOf(ruleID)));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(dsr.hasNameOrRuleID(name));
      }
    }
    assertFalse(dsr.hasNameOrRuleID("notAnAssignedName"));

    assertEquals(dsr.getDescription(), description);

    assertEquals(dsr.isObsolete(), obsolete);

    assertEquals(dsr.getNameFormID(), nameFormID);

    assertTrue(Arrays.equals(dsr.getSuperiorRuleIDs(), supIDs));

    assertEquals(dsr.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(dsr.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(dsr.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(dsr.toString());
    DITStructureRuleDefinition dsr2 =
         new DITStructureRuleDefinition(dsr.toString());

    assertEquals(dsr2.getRuleID(), ruleID);

    assertTrue(Arrays.equals(dsr2.getNames(), names));
    assertNotNull(dsr2.getNameOrRuleID());

    assertEquals(dsr2.getDescription(), description);

    assertEquals(dsr2.isObsolete(), obsolete);

    assertEquals(dsr2.getNameFormID(), nameFormID);

    assertTrue(Arrays.equals(dsr2.getSuperiorRuleIDs(), supIDs));

    assertEquals(dsr2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(dsr2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(dsr2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    dsr.hashCode();
    assertTrue(dsr.equals(dsr));
  }



  /**
   * Tests the second constructor with null values for the names, supIDs, and
   * extensions elements.
   *
   * @param  dsrString        The string representation for this rule.
   * @param  ruleID           The rule IDfor this rule.
   * @param  names            The set of names for this rule.
   * @param  description      The description for this rule.
   * @param  obsolete         Indicates whether this rule is obsolete.
   * @param  nameFormID       The name/OID for the associated name form.
   * @param  supIDs           The rule IDs for the superior rules.
   * @param  extensions       The set of extensions for this rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidDSRStrings")
  public void testConstructor2Nulls(String dsrString, int ruleID,
                                    String[] names, String description,
                                    boolean obsolete, String nameFormID,
                                    int[] supIDs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    DITStructureRuleDefinition dsr =
         new DITStructureRuleDefinition(ruleID, null, description, obsolete,
                                        nameFormID, null, null);

    assertEquals(dsr.getRuleID(), ruleID);
    assertTrue(dsr.hasNameOrRuleID(String.valueOf(ruleID)));
    assertFalse(dsr.hasNameOrRuleID("notAnAssignedName"));

    assertNotNull(dsr.getNames());
    assertEquals(dsr.getNames().length, 0);
    assertNotNull(dsr.getNameOrRuleID());

    assertEquals(dsr.getDescription(), description);

    assertEquals(dsr.isObsolete(), obsolete);

    assertEquals(dsr.getNameFormID(), nameFormID);

    assertNotNull(dsr.getSuperiorRuleIDs());
    assertEquals(dsr.getSuperiorRuleIDs().length, 0);

    assertNotNull(dsr.getExtensions());
    assertTrue(dsr.getExtensions().isEmpty());

    assertNotNull(dsr.toString());
    DITStructureRuleDefinition dsr2 =
         new DITStructureRuleDefinition(dsr.toString());

    assertEquals(dsr2.getRuleID(), ruleID);

    assertNotNull(dsr2.getNames());
    assertEquals(dsr2.getNames().length, 0);
    assertNotNull(dsr2.getNameOrRuleID());

    assertEquals(dsr2.getDescription(), description);

    assertEquals(dsr2.isObsolete(), obsolete);

    assertEquals(dsr2.getNameFormID(), nameFormID);

    assertNotNull(dsr2.getSuperiorRuleIDs());
    assertEquals(dsr2.getSuperiorRuleIDs().length, 0);

    assertNotNull(dsr2.getExtensions());
    assertTrue(dsr2.getExtensions().isEmpty());

    dsr.hashCode();
    assertTrue(dsr.equals(dsr));
  }



  /**
   * Retrieves a set of test data that may be used to create valid DIT structure
   * rule definitions.
   *
   * @return  A set of test data that may be used to create valid DIT structure
   *          rule definitions.
   */
  @DataProvider(name = "testValidDSRStrings")
  public Object[][] getTestValidDSRStrings()
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
        "( 1 FORM testForm )",
        1,
        new String[0],
        null,
        false,
        "testForm",
        new int[0],
        noExtensions
      },

      new Object[]
      {
        "( 1 FORM testForm)",
        1,
        new String[0],
        null,
        false,
        "testForm",
        new int[0],
        noExtensions
      },

      new Object[]
      {
        "(1 FORM testForm )",
        1,
        new String[0],
        null,
        false,
        "testForm",
        new int[0],
        noExtensions
      },

      new Object[]
      {
        "(1 FORM testForm)",
        1,
        new String[0],
        null,
        false,
        "testForm",
        new int[0],
        noExtensions
      },

      new Object[]
      {
        "(1 FORM testForm OBSOLETE)",
        1,
        new String[0],
        null,
        true,
        "testForm",
        new int[0],
        noExtensions
      },

      new Object[]
      {
        "( 2 NAME 'singleName' DESC 'foo' OBSOLETE FORM testForm " +
             "SUP 1 X-ONE-SINGLE 'foo' )",
        2,
        new String[] { "singleName" },
        "foo",
        true,
        "testForm",
        new int[] { 1 },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(2 NAME 'singleName' DESC 'foo' OBSOLETE FORM testForm " +
             "SUP 1 X-ONE-SINGLE 'foo')",
        2,
        new String[] { "singleName" },
        "foo",
        true,
        "testForm",
        new int[] { 1 },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )",
        3,
        new String[] { "first", "second" },
        null,
        false,
        "testForm",
        new int[] { 1, 2 },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(3 NAME ('first' 'second') FORM testForm SUP (1$2) " +
             "X-ONE-MULTI ('a' 'b') X-TWO-SINGLE 'c')",
        3,
        new String[] { "first", "second" },
        null,
        false,
        "testForm",
        new int[] { 1, 2 },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        " ( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' ) ",
        3,
        new String[] { "first", "second" },
        null,
        false,
        "testForm",
        new int[] { 1, 2 },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' FORM testForm )",
        1,
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        "testForm",
        new int[0],
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid DIT
   * structure rule definitions.
   *
   * @return  A set of test data that may not be used to create valid DIT
   *          structure rule definitions.
   */
  @DataProvider(name = "testInvalidDSRStrings")
  public Object[][] getTestInvalidDSRStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "1 FORM testForm "
      },

      new Object[]
      {
        "( 1 FORM testForm"
      },

      new Object[]
      {
        "( 1 )"
      },

      new Object[]
      {
        "( 1 FORM testForm ) X-MORE-AFTER-PARENTHESIS )"
      },

      new Object[]
      {
        "( 1 FORM testForm INVALID )"
      },

      new Object[]
      {
        "( nonNumeric FORM testForm )"
      },

      new Object[]
      {
        "( 1 NAME 'name1' NAME 'name2' FORM testForm )"
      },

      new Object[]
      {
        "( 1 DESC 'desc1' DESC 'desc2' FORM testForm )"
      },

      new Object[]
      {
        "( 1 OBSOLETE OBSOLETE FORM testForm )"
      },

      new Object[]
      {
        "( 1 FORM testForm FORM form2 )"
      },

      new Object[]
      {
        "( 3 FORM testForm SUP 1 SUP 2)"
      },

      new Object[]
      {
        "( 1 FORM testForm SUP notNumeric )"
      },

      new Object[]
      {
        "( 1 FORM testForm SUP ( 1 2 ) )"
      },

      new Object[]
      {
        "( 1 FORM testForm SUP ( '1' '2' ) )"
      },

      new Object[]
      {
        "( 1 FORM testForm SUP ( 1 $ notNumeric ) )"
      },

      new Object[]
      {
        "( 1 FORM testForm X-TEST 'foo' X-TEST 'bar' )"
      },

      new Object[]
      {
        "( 1 FORM testForm X-NO-VALUE )"
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
    final DITStructureRuleDefinition dsr1 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");

    assertFalse(dsr1.equals(null));

    assertTrue(dsr1.equals(dsr1));

    assertFalse(dsr1.equals("foo"));

    DITStructureRuleDefinition dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertTrue(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'FIRST' 'SECOND' ) FORM testFORM SUP ( 2 $ 1 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertTrue(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 4 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'one' 'two' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'first' 'second' ) FORM otherForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 3 $ 4 ) " +
             "X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(dsr1.equals(dsr2));

    dsr2 = new DITStructureRuleDefinition(
         "( 3 NAME ( 'first' 'second' ) FORM testForm SUP ( 1 $ 2 ) " +
             "X-ONE-MULTI ( 'c' 'd' ) X-TWO-SINGLE 'c' )");
    assertFalse(dsr1.equals(dsr2));
  }
}
