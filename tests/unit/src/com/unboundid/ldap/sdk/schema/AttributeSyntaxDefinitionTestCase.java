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
 * This class provides a set of test cases for the AttributeSyntaxDefinition
 * class.
 */
public class AttributeSyntaxDefinitionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a set of valid attribute syntax definition
   * strings.
   *
   * @param  syntaxString  The string representation of the syntax to create.
   * @param  oid           The OID for the syntax.
   * @param  description   The description for the syntax.
   * @param  extensions    The set of extensions for the syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidSyntaxStrings")
  public void testConstructor1Valid(String syntaxString, String oid,
                                    String description,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    AttributeSyntaxDefinition s = new AttributeSyntaxDefinition(syntaxString);

    assertEquals(s.getOID(), oid);

    assertEquals(s.getDescription(), description);

    assertEquals(s.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(s.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(s.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    s.hashCode();
    assertTrue(s.equals(s));

    assertEquals(s.toString(), syntaxString.trim());

    assertNotNull(s.getSchemaElementType());
    assertEquals(s.getSchemaElementType(), SchemaElementType.ATTRIBUTE_SYNTAX);
  }



  /**
   * Tests the first constructor with a set of invalid attribute syntax
   * definition strings.
   *
   * @param  syntaxString  The invalid attribute syntax string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidSyntaxStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String syntaxString)
         throws Exception
  {
    new AttributeSyntaxDefinition(syntaxString);
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
    new AttributeSyntaxDefinition(null);
  }



  /**
   * Tests the second constructor.
   *
   * @param  syntaxString  The string representation of the syntax to create.
   * @param  oid           The OID for the syntax.
   * @param  description   The description for the syntax.
   * @param  extensions    The set of extensions for the syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidSyntaxStrings")
  public void testConstructor2(String syntaxString, String oid,
                               String description,
                               Map<String,String[]> extensions)
         throws Exception
  {
    AttributeSyntaxDefinition s =
         new AttributeSyntaxDefinition(oid, description, extensions);

    assertEquals(s.getOID(), oid);

    assertEquals(s.getDescription(), description);

    assertEquals(s.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(s.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(s.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(s.toString());

    AttributeSyntaxDefinition s2 = new AttributeSyntaxDefinition(s.toString());

    assertEquals(s2.getOID(), oid);

    assertEquals(s2.getDescription(), description);

    assertEquals(s2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(s2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(s2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    s.hashCode();
    assertTrue(s.equals(s));
  }



  /**
   * Tests the second constructor, substituting {@code null} for all of the
   * extensions maps.
   *
   * @param  syntaxString  The string representation of the syntax to create.
   * @param  oid           The OID for the syntax.
   * @param  description   The description for the syntax.
   * @param  extensions    The set of extensions for the syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidSyntaxStrings")
  public void testConstructor2NullExtensions(String syntaxString, String oid,
                                             String description,
                                             Map<String,String[]> extensions)
         throws Exception
  {
    AttributeSyntaxDefinition s =
         new AttributeSyntaxDefinition(oid, description, null);

    assertEquals(s.getOID(), oid);

    assertEquals(s.getDescription(), description);

    assertNotNull(s.getExtensions());
    assertTrue(s.getExtensions().isEmpty());

    assertNotNull(s.toString());

    AttributeSyntaxDefinition s2 = new AttributeSyntaxDefinition(s.toString());

    assertEquals(s2.getOID(), oid);

    assertEquals(s2.getDescription(), description);

    assertNotNull(s2.getExtensions());
    assertTrue(s2.getExtensions().isEmpty());

    s.hashCode();
    assertTrue(s.equals(s));
  }



  /**
   * Retrieves a set of test data that may be used to create valid attribute
   * syntax definitions.
   *
   * @return  A set of test data that may be used to create valid attribute
   *          syntax definitions.
   */
  @DataProvider(name = "testValidSyntaxStrings")
  public Object[][] getTestValidSyntaxStrings()
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
        null,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 )",
        "1.2.3.4",
        null,
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4)",
        "1.2.3.4",
        null,
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4)",
        "1.2.3.4",
        null,
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' )",
        "1.2.3.4",
        "foo",
        noExtensions
      },

      new Object[]
      {
        "(     1.2.3.4     DESC     'foo'      )",
        "1.2.3.4",
        "foo",
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foobar' )",
        "1.2.3.4",
        "foobar",
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        null,
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-SINGLE ( 'foo' ) )",
        "1.2.3.4",
        null,
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-SINGLE ( 'foo') )",
        "1.2.3.4",
        null,
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-SINGLE ('foo' ) )",
        "1.2.3.4",
        null,
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-SINGLE ('foo') )",
        "1.2.3.4",
        null,
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 X-ONE-SINGLE ('foo'))",
        "1.2.3.4",
        null,
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-MULTI ( 'foo' 'bar' ) )",
        "1.2.3.4",
        null,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-MULTI ( 'foo' 'bar') )",
        "1.2.3.4",
        null,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-MULTI ('foo' 'bar' ) )",
        "1.2.3.4",
        null,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 X-ONE-MULTI ('foo' 'bar') )",
        "1.2.3.4",
        null,
        oneMultiValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' X-ONE-SINGLE 'foo' X-TWO-SINGLE 'bar' )",
        "1.2.3.4",
        "foo",
        twoSingleValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) " +
             "X-TWO-MULTI ( 'c' 'd' ) )",
        "1.2.3.4",
        "foo",
        twoMultiValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )",
        "1.2.3.4",
        "foo",
        twoMixedValuedExtensions
      },

      new Object[]
      {
        " ( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' ) ",
        "1.2.3.4",
        "foo",
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(     1.2.3.4     DESC     'foo'     X-ONE-MULTI     (     'a'     " +
             "'b'     )     X-TWO-SINGLE     'c'     )",
        "1.2.3.4",
        "foo",
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' )",
        "1.2.3.4",
        "Jos\u00e9 '\\' Jalape\u00f1o",
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid attribute
   * syntax definitions.
   *
   * @return  A set of test data that may not be used to create valid attribute
   *          syntax definitions.
   */
  @DataProvider(name = "testInvalidSyntaxStrings")
  public Object[][] getTestInvalidSyntaxStrings()
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
        "( 1.2.3.4 "
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
        "( 1.2.3.4 DESC 'foo )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo'",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'foo' ) )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\a' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\a)",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\xa' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\ax' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\aa\\' )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '\\00\\11\\22\\33\\44\\55\\66\\77\\88\\99\\aa\\AA" +
             "\\bb\\BB\\cc\\CC\\dd\\DD\\ee\\EE\\ff\\FF\\gg' )",
      },

      new Object[]
      {
        "( 1.2.3.4 X-MISSING-QUOTE ( 'foo' bar ) )",
      },

      new Object[]
      {
        "( 1.2.3.4 X-EMPTY-PARENS ( ) )",
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
    final AttributeSyntaxDefinition s1 = new AttributeSyntaxDefinition(
         "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");

    assertFalse(s1.equals(null));

    assertTrue(s1.equals(s1));

    assertFalse(s1.equals("foo"));

    AttributeSyntaxDefinition s2 = new AttributeSyntaxDefinition(
         "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertTrue(s1.equals(s2));

    s2 = new AttributeSyntaxDefinition(
         "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertTrue(s1.equals(s2));

    s2 = new AttributeSyntaxDefinition(
         "( 1.2.3.5 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(s1.equals(s2));

    s2 = new AttributeSyntaxDefinition(
         "( 1.2.3.4 DESC 'bar' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(s1.equals(s2));

    s2 = new AttributeSyntaxDefinition(
         "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'd' 'b' ) X-TWO-SINGLE 'c' )");
    assertFalse(s1.equals(s2));

    s2 = new AttributeSyntaxDefinition(
         "( 1.2.3.4 DESC 'foo' X-ONE-MULTI ( 'a' 'b' ) X-TWO-SINGLE 'd' )");
    assertFalse(s1.equals(s2));
  }
}
