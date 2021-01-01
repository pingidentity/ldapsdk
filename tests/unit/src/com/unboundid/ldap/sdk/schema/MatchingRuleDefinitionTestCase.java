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
 * This class provides a set of test cases for the MatchingRuleDefinition
 * class.
 */
public class MatchingRuleDefinitionTestCase
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
    MatchingRuleDefinition mr = new MatchingRuleDefinition("1.2.3.4", null,
         null, "1.2.3.5", null);

    mr = new MatchingRuleDefinition(mr.toString());

    assertNotNull(mr.getOID());
    assertEquals(mr.getOID(), "1.2.3.4");

    assertNotNull(mr.getNames());
    assertEquals(mr.getNames().length, 0);

    assertNotNull(mr.getNameOrOID());
    assertEquals(mr.getNameOrOID(), "1.2.3.4");

    assertTrue(mr.hasNameOrOID("1.2.3.4"));
    assertFalse(mr.hasNameOrOID("some-name"));

    assertNull(mr.getDescription());

    assertFalse(mr.isObsolete());

    assertNotNull(mr.getSyntaxOID());
    assertEquals(mr.getSyntaxOID(), "1.2.3.5");

    assertNotNull(mr.getExtensions());
    assertTrue(mr.getExtensions().isEmpty());

    assertNotNull(mr.getSchemaElementType());
    assertEquals(mr.getSchemaElementType(), SchemaElementType.MATCHING_RULE);
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

    MatchingRuleDefinition mr = new MatchingRuleDefinition("1.2.3.4",
         "the-name", "the description", "1.2.3.5", extensions);

    mr = new MatchingRuleDefinition(mr.toString());

    assertNotNull(mr.getOID());
    assertEquals(mr.getOID(), "1.2.3.4");

    assertNotNull(mr.getNames());
    assertEquals(mr.getNames().length, 1);

    assertNotNull(mr.getNameOrOID());
    assertEquals(mr.getNameOrOID(), "the-name");

    assertTrue(mr.hasNameOrOID("1.2.3.4"));
    assertTrue(mr.hasNameOrOID("the-name"));
    assertFalse(mr.hasNameOrOID("some-other-name"));

    assertNotNull(mr.getDescription());
    assertEquals(mr.getDescription(), "the description");

    assertFalse(mr.isObsolete());

    assertNotNull(mr.getSyntaxOID());
    assertEquals(mr.getSyntaxOID(), "1.2.3.5");

    assertNotNull(mr.getExtensions());
    assertEquals(mr.getExtensions().size(), 2);
    assertEquals(mr.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(mr.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid matching rule definition
   * strings.
   *
   * @param  mrString     The string representation of the matching rule.
   * @param  oid          The OID for the matching rule.
   * @param  names        The set of names for the matching rule.
   * @param  description  The description for the matching rule.
   * @param  obsolete     Indicates whether the matching rule is obsolete.
   * @param  syntax       The syntax OID for the matching rule.
   * @param  extensions   The set of extensions for the matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidMRStrings")
  public void testConstructor1Valid(String mrString, String oid, String[] names,
                                    String description, boolean obsolete,
                                    String syntax,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    MatchingRuleDefinition mr = new MatchingRuleDefinition(mrString);

    assertEquals(mr.getOID(), oid);

    assertTrue(Arrays.equals(mr.getNames(), names));
    assertNotNull(mr.getNameOrOID());

    assertTrue(mr.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(mr.hasNameOrOID(name));
      }
    }
    assertFalse(mr.hasNameOrOID("notAnAssignedName"));

    assertEquals(mr.getDescription(), description);

    assertEquals(mr.isObsolete(), obsolete);

    assertEquals(mr.getSyntaxOID(), syntax);

    assertEquals(mr.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(mr.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(mr.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(mr.toString(), mrString.trim());

    mr.hashCode();
    assertTrue(mr.equals(mr));
  }



  /**
   * Tests the first constructor with a set of invalid matching rule definition
   * strings.
   *
   * @param  mrString  The invalid matching rule string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidMRStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String mrString)
         throws Exception
  {
    new MatchingRuleDefinition(mrString);
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
    new MatchingRuleDefinition(null);
  }



  /**
   * Tests the second constructor.
   *
   * @param  mrString     The string representation of the matching rule.
   * @param  oid          The OID for the matching rule.
   * @param  names        The set of names for the matching rule.
   * @param  description  The description for the matching rule.
   * @param  obsolete     Indicates whether the matching rule is obsolete.
   * @param  syntax       The syntax OID for the matching rule.
   * @param  extensions   The set of extensions for the matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidMRStrings")
  public void testConstructor2(String mrString, String oid, String[] names,
                               String description, boolean obsolete,
                               String syntax, Map<String,String[]> extensions)
         throws Exception
  {
    MatchingRuleDefinition mr =
         new MatchingRuleDefinition(oid, names, description, obsolete, syntax,
                                    extensions);

    assertEquals(mr.getOID(), oid);

    assertTrue(Arrays.equals(mr.getNames(), names));
    assertNotNull(mr.getNameOrOID());

    assertTrue(mr.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(mr.hasNameOrOID(name));
      }
    }
    assertFalse(mr.hasNameOrOID("notAnAssignedName"));

    assertEquals(mr.getDescription(), description);

    assertEquals(mr.isObsolete(), obsolete);

    assertEquals(mr.getSyntaxOID(), syntax);

    assertEquals(mr.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(mr.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(mr.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(mr.toString());

    MatchingRuleDefinition mr2 = new MatchingRuleDefinition(mr.toString());

    assertEquals(mr2.getOID(), oid);

    assertTrue(Arrays.equals(mr2.getNames(), names));
    assertNotNull(mr2.getNameOrOID());

    assertEquals(mr2.getDescription(), description);

    assertEquals(mr2.isObsolete(), obsolete);

    assertEquals(mr2.getSyntaxOID(), syntax);

    assertEquals(mr2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(mr2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(mr2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    mr.hashCode();
    assertTrue(mr.equals(mr));
  }



  /**
   * Tests the second constructor with {@code null} values in place of the names
   * and extensions.
   *
   * @param  mrString     The string representation of the matching rule.
   * @param  oid          The OID for the matching rule.
   * @param  names        The set of names for the matching rule.
   * @param  description  The description for the matching rule.
   * @param  obsolete     Indicates whether the matching rule is obsolete.
   * @param  syntax       The syntax OID for the matching rule.
   * @param  extensions   The set of extensions for the matching rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidMRStrings")
  public void testConstructor2Nulls(String mrString, String oid,
                                    String[] names, String description,
                                    boolean obsolete, String syntax,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    MatchingRuleDefinition mr =
         new MatchingRuleDefinition(oid, null, description, obsolete, syntax,
                                    null);

    assertEquals(mr.getOID(), oid);
    assertTrue(mr.hasNameOrOID(oid));
    assertFalse(mr.hasNameOrOID("notAnAssignedName"));

    assertNotNull(mr.getNames());
    assertEquals(mr.getNames().length, 0);
    assertNotNull(mr.getNameOrOID());

    assertEquals(mr.getDescription(), description);

    assertEquals(mr.isObsolete(), obsolete);

    assertEquals(mr.getSyntaxOID(), syntax);

    assertNotNull(mr.getExtensions());
    assertTrue(mr.getExtensions().isEmpty());

    assertNotNull(mr.toString());

    MatchingRuleDefinition mr2 = new MatchingRuleDefinition(mr.toString());

    assertEquals(mr2.getOID(), oid);

    assertNotNull(mr2.getNames());
    assertEquals(mr2.getNames().length, 0);
    assertNotNull(mr2.getNameOrOID());

    assertEquals(mr2.getDescription(), description);

    assertEquals(mr2.isObsolete(), obsolete);

    assertEquals(mr2.getSyntaxOID(), syntax);

    assertNotNull(mr2.getExtensions());
    assertTrue(mr2.getExtensions().isEmpty());

    mr.hashCode();
    assertTrue(mr.equals(mr));
  }



  /**
   * Retrieves a set of test data that may be used to create valid matching rule
   * definitions.
   *
   * @return  A set of test data that may be used to create valid matching rule
   *          definitions.
   */
  @DataProvider(name = "testValidMRStrings")
  public Object[][] getTestValidMRStrings()
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
        "( 1.2.3.4 SYNTAX 1.2.3.5 )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "1.2.3.5",
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 SYNTAX 1.2.3.5)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "1.2.3.5",
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 SYNTAX 1.2.3.5 )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "1.2.3.5",
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 SYNTAX 1.2.3.5)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "1.2.3.5",
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 SYNTAX 1.2.3.5 OBSOLETE)",
        "1.2.3.4",
        new String[0],
        null,
        true,
        "1.2.3.5",
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SYNTAX 1.2.3.5 " +
             "X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "1.2.3.5",
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE SYNTAX 1.2.3.5 " +
             "X-ONE-SINGLE 'foo')",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "1.2.3.5",
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'first' 'second' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "1.2.3.5",
        oneMultiValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME ('first' 'second') SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ('foo' 'bar'))",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "1.2.3.5",
        oneMultiValuedExtension
      },

      new Object[]
      {
        " ( 1.2.3.4 NAME ( 'first' 'second' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) ) ",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "1.2.3.5",
        oneMultiValuedExtension
      },

      new Object[]
      {
        "(     1.2.3.4     NAME     (     'first'     'second'     )     " +
             "SYNTAX     1.2.3.5     " +
             "X-ONE-MULTI     (     'a'     'b'     )     " +
             "X-TWO-SINGLE   'c'   )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "1.2.3.5",
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' " +
             "SYNTAX 1.2.3.5 )",
        "1.2.3.4",
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        "1.2.3.5",
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid matching
   * rule definitions.
   *
   * @return  A set of test data that may not be used to create valid matching
   *          rule definitions.
   */
  @DataProvider(name = "testInvalidMRStrings")
  public Object[][] getTestInvalidMRStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "1.2.3.4 SYNTAX 1.2.3.5"
      },

      new Object[]
      {
        "( 1.2.3.4 SYNTAX 1.2.3.5"
      },

      new Object[]
      {
        "( 1.2.3.4 ) SYNTAX 1.2.3.5 )"
      },

      new Object[]
      {
        "( 1.2.3.4 )"
      },

      new Object[]
      {
        "( 1.2.3.4 SYNTAX 1.2.3.5 INVALID )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC SYNTAX 1.2.3.5 )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '' SYNTAX 1.2.3.5 )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'first' NAME 'second' SYNTAX 1.2.3.5 )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'first' DESC 'second' SYNTAX 1.2.3.5 )",
      },

      new Object[]
      {
        "( 1.2.3.4 OBSOLETE OBSOLETE SYNTAX 1.2.3.5 )",
      },

      new Object[]
      {
        "( 1.2.3.4 SYNTAX 1.2.3.5 SYNTAX 1.2.3.6 )",
      },

      new Object[]
      {
        "( 1.2.3.4 SYNTAX 1.2.3.5 X-DUPE 'foo' X-DUPE 'bar' )",
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
    final MatchingRuleDefinition mr1 = new MatchingRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");

    assertFalse(mr1.equals(null));

    assertTrue(mr1.equals(mr1));

    assertFalse(mr1.equals("foo"));

    MatchingRuleDefinition mr2 = new MatchingRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertTrue(mr1.equals(mr2));

    mr2 = new MatchingRuleDefinition(
         "( 1.2.3.4 NAME ( 'SECOND' 'FIRST' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertTrue(mr1.equals(mr2));

    mr2 = new MatchingRuleDefinition(
         "( 1.2.3.5 NAME ( 'first' 'second' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(mr1.equals(mr2));

    mr2 = new MatchingRuleDefinition(
         "( 1.2.3.4 NAME ( 'one' 'two' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(mr1.equals(mr2));

    mr2 = new MatchingRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) SYNTAX 1.2.3.6 " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(mr1.equals(mr2));

    mr2 = new MatchingRuleDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) SYNTAX 1.2.3.5 " +
             "X-ONE-MULTI ( 'baz' ) )");
    assertFalse(mr1.equals(mr2));
  }
}
