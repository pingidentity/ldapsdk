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
 * This class provides a set of test cases for the MatchingRuleUseDefinition
 * class.
 */
public class MatchingRuleUseDefinitionTestCase
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
    MatchingRuleUseDefinition mru = new MatchingRuleUseDefinition("1.2.3.4",
         null, null, new String[] { "t1", "t2" }, null);

    mru = new MatchingRuleUseDefinition(mru.toString());

    assertNotNull(mru.getOID());
    assertEquals(mru.getOID(), "1.2.3.4");

    assertNotNull(mru.getNames());
    assertEquals(mru.getNames().length, 0);

    assertNotNull(mru.getNameOrOID());
    assertEquals(mru.getNameOrOID(), "1.2.3.4");

    assertTrue(mru.hasNameOrOID("1.2.3.4"));
    assertFalse(mru.hasNameOrOID("some-name"));

    assertNull(mru.getDescription());

    assertFalse(mru.isObsolete());

    assertNotNull(mru.getApplicableAttributeTypes());
    assertEquals(mru.getApplicableAttributeTypes(),
         new String[] { "t1", "t2" });

    assertNotNull(mru.getExtensions());
    assertTrue(mru.getExtensions().isEmpty());

    assertNotNull(mru.getSchemaElementType());
    assertEquals(mru.getSchemaElementType(),
         SchemaElementType.MATCHING_RULE_USE);
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
    MatchingRuleUseDefinition mru = new MatchingRuleUseDefinition("1.2.3.4",
         null, null, Arrays.asList("t1", "t2"), null);

    mru = new MatchingRuleUseDefinition(mru.toString());

    assertNotNull(mru.getOID());
    assertEquals(mru.getOID(), "1.2.3.4");

    assertNotNull(mru.getNames());
    assertEquals(mru.getNames().length, 0);

    assertNotNull(mru.getNameOrOID());
    assertEquals(mru.getNameOrOID(), "1.2.3.4");

    assertTrue(mru.hasNameOrOID("1.2.3.4"));
    assertFalse(mru.hasNameOrOID("some-name"));

    assertNull(mru.getDescription());

    assertFalse(mru.isObsolete());

    assertNotNull(mru.getApplicableAttributeTypes());
    assertEquals(mru.getApplicableAttributeTypes(),
         new String[] { "t1", "t2" });

    assertNotNull(mru.getExtensions());
    assertTrue(mru.getExtensions().isEmpty());
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

    MatchingRuleUseDefinition mru = new MatchingRuleUseDefinition("1.2.3.4",
         "the-name", "the description", new String[] { "t1", "t2" },
         extensions);

    mru = new MatchingRuleUseDefinition(mru.toString());

    assertNotNull(mru.getOID());
    assertEquals(mru.getOID(), "1.2.3.4");

    assertNotNull(mru.getNames());
    assertEquals(mru.getNames().length, 1);

    assertNotNull(mru.getNameOrOID());
    assertEquals(mru.getNameOrOID(), "the-name");

    assertTrue(mru.hasNameOrOID("1.2.3.4"));
    assertTrue(mru.hasNameOrOID("the-name"));
    assertFalse(mru.hasNameOrOID("some-other-name"));

    assertNotNull(mru.getDescription());
    assertEquals(mru.getDescription(), "the description");

    assertFalse(mru.isObsolete());

    assertNotNull(mru.getApplicableAttributeTypes());
    assertEquals(mru.getApplicableAttributeTypes(),
         new String[] { "t1", "t2" });

    assertNotNull(mru.getExtensions());
    assertEquals(mru.getExtensions().size(), 2);
    assertEquals(mru.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(mru.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
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

    MatchingRuleUseDefinition mru = new MatchingRuleUseDefinition("1.2.3.4",
         "the-name", "the description", Arrays.asList("t1", "t2"), extensions);

    mru = new MatchingRuleUseDefinition(mru.toString());

    assertNotNull(mru.getOID());
    assertEquals(mru.getOID(), "1.2.3.4");

    assertNotNull(mru.getNames());
    assertEquals(mru.getNames().length, 1);

    assertNotNull(mru.getNameOrOID());
    assertEquals(mru.getNameOrOID(), "the-name");

    assertTrue(mru.hasNameOrOID("1.2.3.4"));
    assertTrue(mru.hasNameOrOID("the-name"));
    assertFalse(mru.hasNameOrOID("some-other-name"));

    assertNotNull(mru.getDescription());
    assertEquals(mru.getDescription(), "the description");

    assertFalse(mru.isObsolete());

    assertNotNull(mru.getApplicableAttributeTypes());
    assertEquals(mru.getApplicableAttributeTypes(),
         new String[] { "t1", "t2" });

    assertNotNull(mru.getExtensions());
    assertEquals(mru.getExtensions().size(), 2);
    assertEquals(mru.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(mru.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid matching rule use
   * definition strings.
   *
   * @param  mruString    The string representation of the matching rule use.
   * @param  oid          The OID for the matching rule use.
   * @param  names        The set of names for the matching rule use.
   * @param  description  The description for the matching rule use.
   * @param  obsolete     Indicates whether the matching rule use is obsolete.
   * @param  applies      The names/OIDs of the applicable types.
   * @param  extensions   The set of extensions for the matching rule use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidMRUStrings")
  public void testConstructor1Valid(String mruString, String oid,
                                    String[] names, String description,
                                    boolean obsolete, String[] applies,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    MatchingRuleUseDefinition mru = new MatchingRuleUseDefinition(mruString);

    assertEquals(mru.getOID(), oid);

    assertTrue(Arrays.equals(mru.getNames(), names));
    assertNotNull(mru.getNameOrOID());

    assertTrue(mru.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(mru.hasNameOrOID(name));
      }
    }
    assertFalse(mru.hasNameOrOID("notAnAssignedName"));

    assertEquals(mru.getDescription(), description);

    assertEquals(mru.isObsolete(), obsolete);

    assertTrue(Arrays.equals(mru.getApplicableAttributeTypes(), applies));

    assertEquals(mru.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(mru.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(mru.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(mru.toString(), mruString.trim());

    mru.hashCode();
    assertTrue(mru.equals(mru));
  }



  /**
   * Tests the first constructor with a set of invalid matching rule use
   * definition strings.
   *
   * @param  mruString  The invalid matching rule use string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidMRUStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String mruString)
         throws Exception
  {
    new MatchingRuleUseDefinition(mruString);
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
    new MatchingRuleUseDefinition(null);
  }



  /**
   * Tests the second constructor.
   *
   * @param  mruString    The string representation of the matching rule use.
   * @param  oid          The OID for the matching rule use.
   * @param  names        The set of names for the matching rule use.
   * @param  description  The description for the matching rule use.
   * @param  obsolete     Indicates whether the matching rule use is obsolete.
   * @param  applies      The names/OIDs of the applicable types.
   * @param  extensions   The set of extensions for the matching rule use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidMRUStrings")
  public void testConstructor2(String mruString, String oid, String[] names,
                               String description, boolean obsolete,
                               String[] applies,
                               Map<String,String[]> extensions)
         throws Exception
  {
    MatchingRuleUseDefinition mru =
         new MatchingRuleUseDefinition(oid, names, description, obsolete,
                                       applies, extensions);

    assertEquals(mru.getOID(), oid);

    assertTrue(Arrays.equals(mru.getNames(), names));
    assertNotNull(mru.getNameOrOID());

    assertTrue(mru.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(mru.hasNameOrOID(name));
      }
    }
    assertFalse(mru.hasNameOrOID("notAnAssignedName"));

    assertEquals(mru.getDescription(), description);

    assertEquals(mru.isObsolete(), obsolete);

    assertTrue(Arrays.equals(mru.getApplicableAttributeTypes(), applies));

    assertEquals(mru.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(mru.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(mru.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(mru.toString());

    MatchingRuleUseDefinition mru2 =
         new MatchingRuleUseDefinition(mru.toString());

    assertEquals(mru2.getOID(), oid);

    assertTrue(Arrays.equals(mru2.getNames(), names));
    assertNotNull(mru2.getNameOrOID());

    assertEquals(mru2.getDescription(), description);

    assertEquals(mru2.isObsolete(), obsolete);

    assertTrue(Arrays.equals(mru2.getApplicableAttributeTypes(), applies));

    assertEquals(mru2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(mru2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(mru2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    mru.hashCode();
    assertTrue(mru.equals(mru));
  }



  /**
   * Tests the second constructor, substituting {@code null} values for the
   * names and extensions.
   *
   * @param  mruString    The string representation of the matching rule use.
   * @param  oid          The OID for the matching rule use.
   * @param  names        The set of names for the matching rule use.
   * @param  description  The description for the matching rule use.
   * @param  obsolete     Indicates whether the matching rule use is obsolete.
   * @param  applies      The names/OIDs of the applicable types.
   * @param  extensions   The set of extensions for the matching rule use.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidMRUStrings")
  public void testConstructor2Nulls(String mruString, String oid,
                                    String[] names, String description,
                                    boolean obsolete, String[] applies,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    MatchingRuleUseDefinition mru =
         new MatchingRuleUseDefinition(oid, null, description, obsolete,
                                       applies, null);

    assertEquals(mru.getOID(), oid);
    assertTrue(mru.hasNameOrOID(oid));
    assertFalse(mru.hasNameOrOID("notAnAssignedName"));

    assertNotNull(mru.getNames());
    assertEquals(mru.getNames().length, 0);
    assertNotNull(mru.getNameOrOID());

    assertEquals(mru.getDescription(), description);

    assertEquals(mru.isObsolete(), obsolete);

    assertTrue(Arrays.equals(mru.getApplicableAttributeTypes(), applies));

    assertNotNull(mru.getExtensions());
    assertTrue(mru.getExtensions().isEmpty());

    assertNotNull(mru.toString());

    MatchingRuleUseDefinition mru2 =
         new MatchingRuleUseDefinition(mru.toString());

    assertEquals(mru2.getOID(), oid);

    assertNotNull(mru2.getNames());
    assertEquals(mru2.getNames().length, 0);
    assertNotNull(mru2.getNameOrOID());

    assertEquals(mru2.getDescription(), description);

    assertEquals(mru2.isObsolete(), obsolete);

    assertTrue(Arrays.equals(mru2.getApplicableAttributeTypes(), applies));

    assertNotNull(mru2.getExtensions());
    assertTrue(mru2.getExtensions().isEmpty());

    mru.hashCode();
    assertTrue(mru.equals(mru));
  }



  /**
   * Retrieves a set of test data that may be used to create valid matching rule
   * use definitions.
   *
   * @return  A set of test data that may be used to create valid matching rule
   *          use definitions.
   */
  @DataProvider(name = "testValidMRUStrings")
  public Object[][] getTestValidMRUStrings()
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
        "( 1.2.3.4 APPLIES cn )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "cn" },
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 APPLIES cn)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "cn" },
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 APPLIES cn )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "cn" },
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 APPLIES cn)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "cn" },
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 APPLIES cn OBSOLETE)",
        "1.2.3.4",
        new String[0],
        null,
        true,
        new String[] { "cn" },
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE APPLIES cn " +
             "X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        new String[] { "cn" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'first' 'second' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "cn", "sn" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME ('first' 'second') APPLIES (cn$sn) " +
             "X-ONE-MULTI ('foo' 'bar'))",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "cn", "sn" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        " ( 1.2.3.4 NAME ( 'first' 'second' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) ) ",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "cn", "sn" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        "(     1.2.3.4     NAME     (     'first'     'second'     )     " +
             "APPLIES     (     cn     $     sn     )     " +
             "X-ONE-MULTI     (     'a'     'b'     )     " +
             "X-TWO-SINGLE    'c'    )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        new String[] { "cn", "sn" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' " +
             "APPLIES cn )",
        "1.2.3.4",
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        new String[] { "cn" },
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid matching
   * rule use definitions.
   *
   * @return  A set of test data that may not be used to create valid matching
   *          rule use definitions.
   */
  @DataProvider(name = "testInvalidMRUStrings")
  public Object[][] getTestInvalidMRUStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "1.2.3.4 APPLIES cn"
      },

      new Object[]
      {
        "( 1.2.3.4 APPLIES cn"
      },

      new Object[]
      {
        "( 1.2.3.4 ) APPLIES cn )"
      },

      new Object[]
      {
        "( 1.2.3.4 )"
      },

      new Object[]
      {
        "( 1.2.3.4 APPLIES cn INVALID )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC APPLIES cn )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '' APPLIES cn )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'first' NAME 'second' APPLIES cn )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'first' DESC 'second' APPLIES cn )",
      },

      new Object[]
      {
        "( 1.2.3.4 OBSOLETE OBSOLETE APPLIES cn )",
      },

      new Object[]
      {
        "( 1.2.3.4 APPLIES cn APPLIES sn )",
      },

      new Object[]
      {
        "( 1.2.3.4 APPLIES cn X-DUPE 'foo' X-DUPE 'bar' )",
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
    final MatchingRuleUseDefinition mru1 = new MatchingRuleUseDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");

    assertFalse(mru1.equals(null));

    assertTrue(mru1.equals(mru1));

    assertFalse(mru1.equals("foo"));

    MatchingRuleUseDefinition mru2 = new MatchingRuleUseDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertTrue(mru1.equals(mru2));

    mru2 = new MatchingRuleUseDefinition(
         "( 1.2.3.4 NAME ( 'SECOND' 'FIRST' ) APPLIES ( SN $ CN ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertTrue(mru1.equals(mru2));

    mru2 = new MatchingRuleUseDefinition(
         "( 1.2.3.5 NAME ( 'first' 'second' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(mru1.equals(mru2));

    mru2 = new MatchingRuleUseDefinition(
         "( 1.2.3.4 NAME ( 'one' 'two' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(mru1.equals(mru2));

    mru2 = new MatchingRuleUseDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) APPLIES ( o $ l ) " +
             "X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(mru1.equals(mru2));

    mru2 = new MatchingRuleUseDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) APPLIES ( cn $ sn ) " +
             "X-ONE-MULTI ( 'baz' ) )");
    assertFalse(mru1.equals(mru2));
  }
}
