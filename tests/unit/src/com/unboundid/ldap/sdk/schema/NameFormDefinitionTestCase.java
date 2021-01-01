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
 * This class provides a set of test cases for the NameFormDefinition class.
 */
public class NameFormDefinitionTestCase
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
    NameFormDefinition nf = new NameFormDefinition("1.2.3.4", null,
         null, "person", "cn", null);

    nf = new NameFormDefinition(nf.toString());

    assertNotNull(nf.getOID());
    assertEquals(nf.getOID(), "1.2.3.4");

    assertNotNull(nf.getNames());
    assertEquals(nf.getNames().length, 0);

    assertNotNull(nf.getNameOrOID());
    assertEquals(nf.getNameOrOID(), "1.2.3.4");

    assertTrue(nf.hasNameOrOID("1.2.3.4"));
    assertFalse(nf.hasNameOrOID("some-name"));

    assertNull(nf.getDescription());

    assertFalse(nf.isObsolete());

    assertNotNull(nf.getStructuralClass());
    assertEquals(nf.getStructuralClass(), "person");

    assertNotNull(nf.getRequiredAttributes());
    assertEquals(nf.getRequiredAttributes(), new String[] { "cn" });

    assertNotNull(nf.getOptionalAttributes());
    assertEquals(nf.getOptionalAttributes().length, 0);

    assertNotNull(nf.getExtensions());
    assertTrue(nf.getExtensions().isEmpty());

    assertNotNull(nf.getSchemaElementType());
    assertEquals(nf.getSchemaElementType(), SchemaElementType.NAME_FORM);
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

    NameFormDefinition nf = new NameFormDefinition("1.2.3.4", "the-name",
         "the description", "person", "cn", extensions);

    nf = new NameFormDefinition(nf.toString());

    assertNotNull(nf.getOID());
    assertEquals(nf.getOID(), "1.2.3.4");

    assertNotNull(nf.getNames());
    assertEquals(nf.getNames().length, 1);

    assertNotNull(nf.getNameOrOID());
    assertEquals(nf.getNameOrOID(), "the-name");

    assertTrue(nf.hasNameOrOID("1.2.3.4"));
    assertTrue(nf.hasNameOrOID("the-name"));
    assertFalse(nf.hasNameOrOID("some-other-name"));

    assertNotNull(nf.getDescription());
    assertEquals(nf.getDescription(), "the description");

    assertFalse(nf.isObsolete());

    assertNotNull(nf.getStructuralClass());
    assertEquals(nf.getStructuralClass(), "person");

    assertNotNull(nf.getRequiredAttributes());
    assertEquals(nf.getRequiredAttributes(), new String[] { "cn" });

    assertNotNull(nf.getOptionalAttributes());
    assertEquals(nf.getOptionalAttributes().length, 0);

    assertNotNull(nf.getExtensions());
    assertEquals(nf.getExtensions().size(), 2);
    assertEquals(nf.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(nf.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid name form definition
   * strings.
   *
   * @param  nfString       The string representation of the name form.
   * @param  oid            The OID for the name form.
   * @param  names          The set of names for the name form.
   * @param  description    The description for the name form.
   * @param  obsolete       Indicates whether the name form is marked obsolete.
   * @param  oc             The name/OID of the associated structural class.
   * @param  requiredAttrs  The names/OIDs of the required RDN attributes.
   * @param  optionalAttrs  The names/OIDs of the optional RDN attributes.
   * @param  extensions     The set of extensions for the name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidNFStrings")
  public void testConstructor1Valid(String nfString, String oid, String[] names,
                                    String description, boolean obsolete,
                                    String oc, String[] requiredAttrs,
                                    String[] optionalAttrs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    NameFormDefinition nf = new NameFormDefinition(nfString);

    assertEquals(nf.getOID(), oid);

    assertTrue(Arrays.equals(nf.getNames(), names));
    assertNotNull(nf.getNameOrOID());

    assertTrue(nf.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(nf.hasNameOrOID(name));
      }
    }
    assertFalse(nf.hasNameOrOID("notAnAssignedName"));

    assertEquals(nf.getDescription(), description);

    assertEquals(nf.isObsolete(), obsolete);

    assertEquals(nf.getStructuralClass(), oc);

    assertTrue(Arrays.equals(nf.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(nf.getOptionalAttributes(), optionalAttrs));

    assertEquals(nf.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(nf.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(nf.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(nf.toString(), nfString.trim());

    nf.hashCode();
    assertTrue(nf.equals(nf));
  }



  /**
   * Tests the first constructor with a set of invalid name form definition
   * strings.
   *
   * @param  nfString The invalid name form string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidNFStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String nfString)
         throws Exception
  {
    new NameFormDefinition(nfString);
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
    new NameFormDefinition(null);
  }



  /**
   * Tests the second constructor.
   *
   * @param  nfString       The string representation of the name form.
   * @param  oid            The OID for the name form.
   * @param  names          The set of names for the name form.
   * @param  description    The description for the name form.
   * @param  obsolete       Indicates whether the name form is marked obsolete.
   * @param  oc             The name/OID of the associated structural class.
   * @param  requiredAttrs  The names/OIDs of the required RDN attributes.
   * @param  optionalAttrs  The names/OIDs of the optional RDN attributes.
   * @param  extensions     The set of extensions for the name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidNFStrings")
  public void testConstructor2(String nfString, String oid, String[] names,
                               String description, boolean obsolete,
                               String oc, String[] requiredAttrs,
                               String[] optionalAttrs,
                               Map<String,String[]> extensions)
         throws Exception
  {
    NameFormDefinition nf =
         new NameFormDefinition(oid, names, description, obsolete, oc,
                                requiredAttrs, optionalAttrs, extensions);

    assertEquals(nf.getOID(), oid);

    assertTrue(Arrays.equals(nf.getNames(), names));
    assertNotNull(nf.getNameOrOID());

    assertTrue(nf.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(nf.hasNameOrOID(name));
      }
    }
    assertFalse(nf.hasNameOrOID("notAnAssignedName"));

    assertEquals(nf.getDescription(), description);

    assertEquals(nf.isObsolete(), obsolete);

    assertEquals(nf.getStructuralClass(), oc);

    assertTrue(Arrays.equals(nf.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(nf.getOptionalAttributes(), optionalAttrs));

    assertEquals(nf.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(nf.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(nf.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(nf.toString());
    NameFormDefinition nf2 = new NameFormDefinition(nf.toString());

    assertEquals(nf2.getOID(), oid);

    assertTrue(Arrays.equals(nf2.getNames(), names));
    assertNotNull(nf.getNameOrOID());

    assertEquals(nf2.getDescription(), description);

    assertEquals(nf2.isObsolete(), obsolete);

    assertEquals(nf2.getStructuralClass(), oc);

    assertTrue(Arrays.equals(nf2.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(nf2.getOptionalAttributes(), optionalAttrs));

    assertEquals(nf2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(nf2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(nf2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    nf.hashCode();
    assertTrue(nf.equals(nf));
  }



  /**
   * Tests the second constructor with {@code null} values for the names,
   * optional attributes, and extensions elements.
   *
   * @param  nfString       The string representation of the name form.
   * @param  oid            The OID for the name form.
   * @param  names          The set of names for the name form.
   * @param  description    The description for the name form.
   * @param  obsolete       Indicates whether the name form is marked obsolete.
   * @param  oc             The name/OID of the associated structural class.
   * @param  requiredAttrs  The names/OIDs of the required RDN attributes.
   * @param  optionalAttrs  The names/OIDs of the optional RDN attributes.
   * @param  extensions     The set of extensions for the name form.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidNFStrings")
  public void testConstructor2Nulls(String nfString, String oid, String[] names,
                                    String description, boolean obsolete,
                                    String oc, String[] requiredAttrs,
                                    String[] optionalAttrs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    NameFormDefinition nf =
         new NameFormDefinition(oid, null, description, obsolete, oc,
                                requiredAttrs, null, null);

    assertEquals(nf.getOID(), oid);
    assertTrue(nf.hasNameOrOID(oid));
    assertFalse(nf.hasNameOrOID("notAnAssignedName"));

    assertNotNull(nf.getNames());
    assertEquals(nf.getNames().length, 0);
    assertNotNull(nf.getNameOrOID());

    assertEquals(nf.getDescription(), description);

    assertEquals(nf.isObsolete(), obsolete);

    assertEquals(nf.getStructuralClass(), oc);

    assertTrue(Arrays.equals(nf.getRequiredAttributes(), requiredAttrs));

    assertNotNull(nf.getOptionalAttributes());
    assertEquals(nf.getOptionalAttributes().length, 0);

    assertNotNull(nf.getExtensions());
    assertTrue(nf.getExtensions().isEmpty());

    assertNotNull(nf.toString());
    NameFormDefinition nf2 = new NameFormDefinition(nf.toString());

    assertEquals(nf2.getOID(), oid);

    assertNotNull(nf2.getNames());
    assertEquals(nf2.getNames().length, 0);

    assertEquals(nf2.getDescription(), description);

    assertEquals(nf2.isObsolete(), obsolete);

    assertEquals(nf2.getStructuralClass(), oc);

    assertTrue(Arrays.equals(nf2.getRequiredAttributes(), requiredAttrs));

    assertNotNull(nf2.getOptionalAttributes());
    assertEquals(nf2.getOptionalAttributes().length, 0);

    assertNotNull(nf2.getExtensions());
    assertTrue(nf2.getExtensions().isEmpty());

    nf.hashCode();
    assertTrue(nf.equals(nf));
  }



  /**
   * Retrieves a set of test data that may be used to create valid attribute
   * syntax definitions.
   *
   * @return  A set of test data that may be used to create valid attribute
   *          syntax definitions.
   */
  @DataProvider(name = "testValidNFStrings")
  public Object[][] getTestValidNFStrings()
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
        "( 1.2.3.4 OC person MUST uid )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "person",
        new String[] { "uid" },
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 OC person MUST uid)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "person",
        new String[] { "uid" },
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 OC person MUST uid )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "person",
        new String[] { "uid" },
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 OC person MUST uid)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        "person",
        new String[] { "uid" },
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 OC person MUST uid OBSOLETE)",
        "1.2.3.4",
        new String[0],
        null,
        true,
        "person",
        new String[] { "uid" },
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE OC person MUST uid " +
             "MAY cn X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "person",
        new String[] { "uid" },
        new String[] { "cn" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' DESC 'foo' OBSOLETE OC person MUST uid " +
             "MAY cn X-ONE-SINGLE 'foo')",
        "1.2.3.4",
        new String[] { "singleName" },
        "foo",
        true,
        "person",
        new String[] { "uid" },
        new String[] { "cn" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "person",
        new String[] { "uid", "cn" },
        new String[] { "givenName", "sn" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME ('first' 'second') OC person MUST (uid$cn) " +
             "MAY (givenName$sn) X-ONE-MULTI ('foo' 'bar'))",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "person",
        new String[] { "uid", "cn" },
        new String[] { "givenName", "sn" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        " ( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) ) ",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "person",
        new String[] { "uid", "cn" },
        new String[] { "givenName", "sn" },
        oneMultiValuedExtension
      },

      new Object[]
      {
        "(     1.2.3.4     NAME     (     'first'     'second'     )     " +
             "OC     person     MUST     (     uid     $     cn     )     " +
             "MAY     (     givenName     $     sn     )     " +
             "X-ONE-MULTI     (     'a'     'b'     )     " +
             "X-TWO-SINGLE     'c'     )",
        "1.2.3.4",
        new String[] { "first", "second" },
        null,
        false,
        "person",
        new String[] { "uid", "cn" },
        new String[] { "givenName", "sn" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' " +
             "OC person MUST uid )",
        "1.2.3.4",
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        "person",
        new String[] { "uid" },
        new String[0],
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
  @DataProvider(name = "testInvalidNFStrings")
  public Object[][] getTestInvalidNFStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "1.2.3.4 OC person MUST uid"
      },

      new Object[]
      {
        "( 1.2.3.4 OC person MUST uid"
      },

      new Object[]
      {
        "( 1.2.3.4 ) OC person MUST uid )"
      },

      new Object[]
      {
        "( 1.2.3.4 OC person )",
      },

      new Object[]
      {
        "( 1.2.3.4 MUST uid )",
      },

      new Object[]
      {
        "( 1.2.3.4 OC person MUST uid INVALID )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC '' OC person MUST uid )",
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'first' NAME 'second' OC person MUST uid )",
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'first' DESC 'second' OC person MUST uid )",
      },

      new Object[]
      {
        "( 1.2.3.4 OBSOLETE OBSOLETE OC person MUST uid )",
      },

      new Object[]
      {
        "( 1.2.3.4 OC person OC groupOfNames MUST uid )",
      },

      new Object[]
      {
        "( 1.2.3.4 OC person MUST uid MUST cn )",
      },

      new Object[]
      {
        "( 1.2.3.4 OC person MUST uid MAY givenName MAY sn )",
      },

      new Object[]
      {
        "( 1.2.3.4 OC person MUST uid X-DUPLICATE 'foo' X-DUPLICATE 'bar' )",
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
    final NameFormDefinition nf1 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )");

    assertFalse(nf1.equals(null));

    assertTrue(nf1.equals(nf1));

    assertFalse(nf1.equals("foo"));

    NameFormDefinition nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertTrue(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'SECOND' 'FIRST' ) OC PERSON MUST ( CN $ UID ) " +
             "MAY ( SN $ GIVENNAME ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertTrue(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.5 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'one' 'two' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) OC other MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( one $ two ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( one $ two ) X-ONE-MULTI ( 'foo' 'bar' ) )");
    assertFalse(nf1.equals(nf2));

    nf2 = new NameFormDefinition(
         "( 1.2.3.4 NAME ( 'first' 'second' ) OC person MUST ( uid $ cn ) " +
             "MAY ( givenName $ sn ) X-ONE-MULTI ( 'baz' ) )");
    assertFalse(nf1.equals(nf2));
  }
}
