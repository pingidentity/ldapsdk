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

import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test cases for the ObjectClassDefinition
 * class.
 */
public class ObjectClassDefinitionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the minimal constructor that uses arrays for
   * required and optional attributes with a minimal set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalArrayConstructorMinimalArguments()
         throws Exception
  {
    ObjectClassDefinition oc = new ObjectClassDefinition("1.2.3.4", null, null,
         null, null, (String[]) null, null, null);

    oc = new ObjectClassDefinition(oc.toString());

    assertNotNull(oc.getOID());
    assertEquals(oc.getOID(), "1.2.3.4");

    assertNotNull(oc.getNames());
    assertEquals(oc.getNames().length, 0);

    assertNotNull(oc.getNameOrOID());
    assertEquals(oc.getNameOrOID(), "1.2.3.4");

    assertTrue(oc.hasNameOrOID("1.2.3.4"));
    assertFalse(oc.hasNameOrOID("some-name"));

    assertNull(oc.getDescription());

    assertFalse(oc.isObsolete());

    assertNotNull(oc.getSuperiorClasses());
    assertEquals(oc.getSuperiorClasses().length, 0);

    assertNull(oc.getObjectClassType());

    assertNotNull(oc.getRequiredAttributes());
    assertEquals(oc.getRequiredAttributes().length, 0);

    assertNotNull(oc.getOptionalAttributes());
    assertEquals(oc.getOptionalAttributes().length, 0);

    assertNotNull(oc.getExtensions());
    assertTrue(oc.getExtensions().isEmpty());

    assertNotNull(oc.getSchemaElementType());
    assertEquals(oc.getSchemaElementType(), SchemaElementType.OBJECT_CLASS);
  }



  /**
   * Provides test coverage for the minimal constructor that uses collections
   * for required and optional attributes with a minimal set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalCollectionConstructorMinimalArguments()
         throws Exception
  {
    ObjectClassDefinition oc = new ObjectClassDefinition("1.2.3.4", null, null,
         null, null, (List<String>) null, null, null);

    oc = new ObjectClassDefinition(oc.toString());

    assertNotNull(oc.getOID());
    assertEquals(oc.getOID(), "1.2.3.4");

    assertNotNull(oc.getNames());
    assertEquals(oc.getNames().length, 0);

    assertNotNull(oc.getNameOrOID());
    assertEquals(oc.getNameOrOID(), "1.2.3.4");

    assertTrue(oc.hasNameOrOID("1.2.3.4"));
    assertFalse(oc.hasNameOrOID("some-name"));

    assertNull(oc.getDescription());

    assertFalse(oc.isObsolete());

    assertNotNull(oc.getSuperiorClasses());
    assertEquals(oc.getSuperiorClasses().length, 0);

    assertNull(oc.getObjectClassType());

    assertNotNull(oc.getRequiredAttributes());
    assertEquals(oc.getRequiredAttributes().length, 0);

    assertNotNull(oc.getOptionalAttributes());
    assertEquals(oc.getOptionalAttributes().length, 0);

    assertNotNull(oc.getExtensions());
    assertTrue(oc.getExtensions().isEmpty());
  }



  /**
   * Provides test coverage for the minimal constructor that uses arrays for
   * required and optional attributes with a full set of values.
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

    ObjectClassDefinition oc = new ObjectClassDefinition("1.2.3.4", "the-name",
         "the description", "top", ObjectClassType.STRUCTURAL,
         new String[] { "r1", "r2" }, new String[] { "o1", "o2" }, extensions);

    oc = new ObjectClassDefinition(oc.toString());

    assertNotNull(oc.getOID());
    assertEquals(oc.getOID(), "1.2.3.4");

    assertNotNull(oc.getNames());
    assertEquals(oc.getNames().length, 1);

    assertNotNull(oc.getNameOrOID());
    assertEquals(oc.getNameOrOID(), "the-name");

    assertTrue(oc.hasNameOrOID("1.2.3.4"));
    assertTrue(oc.hasNameOrOID("the-name"));
    assertFalse(oc.hasNameOrOID("some-other-name"));

    assertNotNull(oc.getDescription());
    assertEquals(oc.getDescription(), "the description");

    assertFalse(oc.isObsolete());

    assertNotNull(oc.getSuperiorClasses());
    assertEquals(oc.getSuperiorClasses().length, 1);
    assertEquals(oc.getSuperiorClasses()[0], "top");

    assertNotNull(oc.getObjectClassType());
    assertEquals(oc.getObjectClassType(), ObjectClassType.STRUCTURAL);

    assertNotNull(oc.getRequiredAttributes());
    assertEquals(oc.getRequiredAttributes().length, 2);
    assertEquals(oc.getRequiredAttributes(), new String[] { "r1", "r2" });

    assertNotNull(oc.getOptionalAttributes());
    assertEquals(oc.getOptionalAttributes().length, 2);
    assertEquals(oc.getOptionalAttributes(), new String[] { "o1", "o2" });

    assertNotNull(oc.getExtensions());
    assertEquals(oc.getExtensions().size(), 2);
    assertEquals(oc.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(oc.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Provides test coverage for the minimal constructor that uses collections
   * for required and optional attributes with a full set of values.
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

    ObjectClassDefinition oc = new ObjectClassDefinition("1.2.3.4", "the-name",
         "the description", "top", ObjectClassType.STRUCTURAL,
         Arrays.asList("r1", "r2"), Arrays.asList("o1", "o2"), extensions);

    oc = new ObjectClassDefinition(oc.toString());

    assertNotNull(oc.getOID());
    assertEquals(oc.getOID(), "1.2.3.4");

    assertNotNull(oc.getNames());
    assertEquals(oc.getNames().length, 1);

    assertNotNull(oc.getNameOrOID());
    assertEquals(oc.getNameOrOID(), "the-name");

    assertTrue(oc.hasNameOrOID("1.2.3.4"));
    assertTrue(oc.hasNameOrOID("the-name"));
    assertFalse(oc.hasNameOrOID("some-other-name"));

    assertNotNull(oc.getDescription());
    assertEquals(oc.getDescription(), "the description");

    assertFalse(oc.isObsolete());

    assertNotNull(oc.getSuperiorClasses());
    assertEquals(oc.getSuperiorClasses().length, 1);
    assertEquals(oc.getSuperiorClasses()[0], "top");

    assertNotNull(oc.getObjectClassType());
    assertEquals(oc.getObjectClassType(), ObjectClassType.STRUCTURAL);

    assertNotNull(oc.getRequiredAttributes());
    assertEquals(oc.getRequiredAttributes().length, 2);
    assertEquals(oc.getRequiredAttributes(), new String[] { "r1", "r2" });

    assertNotNull(oc.getOptionalAttributes());
    assertEquals(oc.getOptionalAttributes().length, 2);
    assertEquals(oc.getOptionalAttributes(), new String[] { "o1", "o2" });

    assertNotNull(oc.getExtensions());
    assertEquals(oc.getExtensions().size(), 2);
    assertEquals(oc.getExtensions().get("X-EXT-1"), new String[] { "a" });
    assertEquals(oc.getExtensions().get("X-EXT-2"), new String[] { "b", "c" });
  }



  /**
   * Tests the first constructor with a set of valid object class definition
   * strings.
   *
   * @param  ocString       The string representation of the object class.
   * @param  oid            The OID for the object class.
   * @param  names          The names for the object class.
   * @param  description    The description for the object class.
   * @param  obsolete       Indicates whether the object class is obsolete.
   * @param  supClasses     The names/OIDs of the superior classes.
   * @param  ocType         The object class type for the object class.
   * @param  requiredAttrs  The names/OIDs of the required attributes.
   * @param  optionalAttrs  The names/OIDs of the optional attributes.
   * @param  extensions     The set of extensions for the object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidOCStrings")
  public void testConstructor1Valid(String ocString, String oid, String[] names,
                                    String description, boolean obsolete,
                                    String[] supClasses, ObjectClassType ocType,
                                    String[] requiredAttrs,
                                    String[] optionalAttrs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    ObjectClassDefinition oc = new ObjectClassDefinition(ocString);

    assertEquals(oc.getOID(), oid);

    assertTrue(Arrays.equals(oc.getNames(), names));
    assertNotNull(oc.getNameOrOID());

    assertTrue(oc.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(oc.hasNameOrOID(name));
      }
    }
    assertFalse(oc.hasNameOrOID("notAnAssignedName"));

    assertEquals(oc.getDescription(), description);

    assertEquals(oc.isObsolete(), obsolete);

    assertTrue(Arrays.equals(oc.getSuperiorClasses(), supClasses));

    assertEquals(oc.getObjectClassType(), ocType);

    assertTrue(Arrays.equals(oc.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(oc.getOptionalAttributes(), optionalAttrs));

    assertEquals(oc.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(oc.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(oc.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertEquals(oc.toString(), ocString.trim());

    oc.hashCode();
    assertTrue(oc.equals(oc));
  }



  /**
   * Tests the first constructor with a set of invalid object class definition
   * strings.
   *
   * @param  ocString  The invalid object class string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidOCStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor1Invalid(String ocString)
         throws Exception
  {
    new ObjectClassDefinition(ocString);
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
    new ObjectClassDefinition(null);
  }



  /**
   * Tests the second constructor with a set of valid object class definition
   * strings.
   *
   * @param  ocString       The string representation of the object class.
   * @param  oid            The OID for the object class.
   * @param  names          The names for the object class.
   * @param  description    The description for the object class.
   * @param  obsolete       Indicates whether the object class is obsolete.
   * @param  supClasses     The names/OIDs of the superior classes.
   * @param  ocType         The object class type for the object class.
   * @param  requiredAttrs  The names/OIDs of the required attributes.
   * @param  optionalAttrs  The names/OIDs of the optional attributes.
   * @param  extensions     The set of extensions for the object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidOCStrings")
  public void testConstructor2(String ocString, String oid, String[] names,
                               String description, boolean obsolete,
                               String[] supClasses, ObjectClassType ocType,
                               String[] requiredAttrs,
                               String[] optionalAttrs,
                               Map<String,String[]> extensions)
         throws Exception
  {
    ObjectClassDefinition oc =
         new ObjectClassDefinition(oid, names, description, obsolete,
                                   supClasses, ocType, requiredAttrs,
                                   optionalAttrs, extensions);

    assertEquals(oc.getOID(), oid);

    assertTrue(Arrays.equals(oc.getNames(), names));
    assertNotNull(oc.getNameOrOID());

    assertTrue(oc.hasNameOrOID(oid));
    if (names != null)
    {
      for (String name : names)
      {
        assertTrue(oc.hasNameOrOID(name));
      }
    }
    assertFalse(oc.hasNameOrOID("notAnAssignedName"));

    assertEquals(oc.getDescription(), description);

    assertEquals(oc.isObsolete(), obsolete);

    assertTrue(Arrays.equals(oc.getSuperiorClasses(), supClasses));

    assertEquals(oc.getObjectClassType(), ocType);

    assertTrue(Arrays.equals(oc.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(oc.getOptionalAttributes(), optionalAttrs));

    assertEquals(oc.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(oc.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(oc.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    assertNotNull(oc.toString());
    ObjectClassDefinition oc2 = new ObjectClassDefinition(oc.toString());

    assertEquals(oc2.getOID(), oid);

    assertTrue(Arrays.equals(oc2.getNames(), names));
    assertNotNull(oc.getNameOrOID());

    assertEquals(oc2.getDescription(), description);

    assertEquals(oc2.isObsolete(), obsolete);

    assertTrue(Arrays.equals(oc2.getSuperiorClasses(), supClasses));

    assertEquals(oc2.getObjectClassType(), ocType);

    assertTrue(Arrays.equals(oc2.getRequiredAttributes(), requiredAttrs));

    assertTrue(Arrays.equals(oc2.getOptionalAttributes(), optionalAttrs));

    assertEquals(oc2.getExtensions().size(), extensions.size());
    for (String extName : extensions.keySet())
    {
      assertTrue(oc2.getExtensions().containsKey(extName));
      assertTrue(Arrays.equals(oc2.getExtensions().get(extName),
                               extensions.get(extName)));
    }

    oc.hashCode();
    assertTrue(oc.equals(oc));
  }



  /**
   * Tests the second constructor with null elements in place of the names,
   * superior classes, required attributes, optional attributes, and extensions.
   *
   * @param  ocString       The string representation of the object class.
   * @param  oid            The OID for the object class.
   * @param  names          The names for the object class.
   * @param  description    The description for the object class.
   * @param  obsolete       Indicates whether the object class is obsolete.
   * @param  supClasses     The names/OIDs of the superior classes.
   * @param  ocType         The object class type for the object class.
   * @param  requiredAttrs  The names/OIDs of the required attributes.
   * @param  optionalAttrs  The names/OIDs of the optional attributes.
   * @param  extensions     The set of extensions for the object class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidOCStrings")
  public void testConstructor2Nulls(String ocString, String oid, String[] names,
                                    String description, boolean obsolete,
                                    String[] supClasses, ObjectClassType ocType,
                                    String[] requiredAttrs,
                                    String[] optionalAttrs,
                                    Map<String,String[]> extensions)
         throws Exception
  {
    ObjectClassDefinition oc =
         new ObjectClassDefinition(oid, null, description, obsolete, null,
                                   ocType, null, null, null);

    assertEquals(oc.getOID(), oid);
    assertTrue(oc.hasNameOrOID(oid));
    assertFalse(oc.hasNameOrOID("notAnAssignedName"));

    assertNotNull(oc.getNames());
    assertEquals(oc.getNames().length, 0);
    assertNotNull(oc.getNameOrOID());

    assertEquals(oc.getDescription(), description);

    assertEquals(oc.isObsolete(), obsolete);

    assertNotNull(oc.getSuperiorClasses());
    assertEquals(oc.getSuperiorClasses().length, 0);

    assertEquals(oc.getObjectClassType(), ocType);

    assertNotNull(oc.getRequiredAttributes());
    assertEquals(oc.getRequiredAttributes().length, 0);

    assertNotNull(oc.getOptionalAttributes());
    assertEquals(oc.getOptionalAttributes().length, 0);

    assertNotNull(oc.getExtensions());
    assertTrue(oc.getExtensions().isEmpty());

    assertNotNull(oc.toString());
    ObjectClassDefinition oc2 = new ObjectClassDefinition(oc.toString());

    assertEquals(oc2.getOID(), oid);

    assertNotNull(oc2.getNames());
    assertEquals(oc2.getNames().length, 0);
    assertNotNull(oc.getNameOrOID());

    assertEquals(oc2.getDescription(), description);

    assertEquals(oc2.isObsolete(), obsolete);

    assertNotNull(oc2.getSuperiorClasses());
    assertEquals(oc2.getSuperiorClasses().length, 0);

    assertEquals(oc2.getObjectClassType(), ocType);

    assertNotNull(oc2.getRequiredAttributes());
    assertEquals(oc2.getRequiredAttributes().length, 0);

    assertNotNull(oc2.getOptionalAttributes());
    assertEquals(oc2.getOptionalAttributes().length, 0);

    assertNotNull(oc2.getExtensions());
    assertTrue(oc2.getExtensions().isEmpty());

    oc.hashCode();
    assertTrue(oc.equals(oc));
  }



  /**
   * Tests the set of methods which require a Schema object.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMethodsRequiringSchema()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();

    try
    {
      Schema schema = Schema.getSchema(connection, "");

      assertNotNull(schema);

      for (ObjectClassDefinition d : schema.getObjectClasses())
      {
        d.getSuperiorClasses();
        d.getSuperiorClasses(schema, false);
        d.getSuperiorClasses(schema, true);

        d.getObjectClassType();
        d.getObjectClassType(schema);

        d.getRequiredAttributes();
        d.getRequiredAttributes(schema, false);
        d.getRequiredAttributes(schema, true);

        d.getOptionalAttributes();
        d.getOptionalAttributes(schema, false);
        d.getOptionalAttributes(schema, true);
      }
    }
    finally
    {
      connection.close();
    }
  }



  /**
   * Retrieves a set of test data that may be used to create valid object class
   * definitions.
   *
   * @return  A set of test data that may be used to create valid object class
   *          definitions.
   */
  @DataProvider(name = "testValidOCStrings")
  public Object[][] getTestValidOCStrings()
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
        null,
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
        null,
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
        null,
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
        null,
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
        null,
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "(1.2.3.4 STRUCTURAL)",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[0],
        ObjectClassType.STRUCTURAL,
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' SUP top AUXILIARY MUST cn " +
            "MAY description X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        null,
        false,
        new String[] { "top" },
        ObjectClassType.AUXILIARY,
        new String[] { "cn" },
        new String[] { "description" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME 'singleName' SUP top AUXILIARY MUST cn " +
            "MAY description X-ONE-SINGLE 'foo')",
        "1.2.3.4",
        new String[] { "singleName" },
        null,
        false,
        new String[] { "top" },
        ObjectClassType.AUXILIARY,
        new String[] { "cn" },
        new String[] { "description" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' SUP top AUXILIARY MUST cn " +
            "MAY description X-ONE-SINGLE 'foo' )",
        "1.2.3.4",
        new String[] { "singleName" },
        null,
        false,
        new String[] { "top" },
        ObjectClassType.AUXILIARY,
        new String[] { "cn" },
        new String[] { "description" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "(1.2.3.4 NAME 'singleName' SUP top AUXILIARY MUST cn " +
            "MAY description X-ONE-SINGLE 'foo')",
        "1.2.3.4",
        new String[] { "singleName" },
        null,
        false,
        new String[] { "top" },
        ObjectClassType.AUXILIARY,
        new String[] { "cn" },
        new String[] { "description" },
        oneSingleValuedExtension
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'first' 'second' ) DESC 'foo' OBSOLETE " +
             "SUP ( groupOfNames $ person ) STRUCTURAL MUST ( cn $ sn ) " +
             "MAY ( description $ givenName ) X-ONE-SINGLE 'foo' " +
             "X-TWO-SINGLE 'bar' )",
        "1.2.3.4",
        new String[] { "first", "second" },
        "foo",
        true,
        new String[] { "groupOfNames", "person" },
        ObjectClassType.STRUCTURAL,
        new String[] { "cn", "sn" },
        new String[] { "description", "givenName" },
        twoSingleValuedExtensions
      },

      new Object[]
      {
        "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
             "SUP (groupOfNames$person) STRUCTURAL MUST (cn$sn) " +
             "MAY (description$givenName) X-ONE-SINGLE 'foo' " +
             "X-TWO-SINGLE 'bar')",
        "1.2.3.4",
        new String[] { "first", "second" },
        "foo",
        true,
        new String[] { "groupOfNames", "person" },
        ObjectClassType.STRUCTURAL,
        new String[] { "cn", "sn" },
        new String[] { "description", "givenName" },
        twoSingleValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 NAME ( 'first' 'second' ) DESC 'foo' OBSOLETE " +
             "SUP ( groupOfNames $ person ) ABSTRACT MUST ( cn $ sn ) " +
             "MAY ( description $ givenName ) X-ONE-MULTI ( 'a' 'b' ) " +
             "X-TWO-SINGLE 'c' )",
        "1.2.3.4",
        new String[] { "first", "second" },
        "foo",
        true,
        new String[] { "groupOfNames", "person" },
        ObjectClassType.ABSTRACT,
        new String[] { "cn", "sn" },
        new String[] { "description", "givenName" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
             "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
             "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
             "X-TWO-SINGLE 'c')",
        "1.2.3.4",
        new String[] { "first", "second" },
        "foo",
        true,
        new String[] { "groupOfNames", "person" },
        ObjectClassType.STRUCTURAL,
        new String[] { "cn", "sn" },
        new String[] { "description", "givenName" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        " (1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
             "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
             "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
             "X-TWO-SINGLE 'c') ",
        "1.2.3.4",
        new String[] { "first", "second" },
        "foo",
        true,
        new String[] { "groupOfNames", "person" },
        ObjectClassType.STRUCTURAL,
        new String[] { "cn", "sn" },
        new String[] { "description", "givenName" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "(     1.2.3.4     NAME     (     'first'     'second'     )     " +
             "DESC     'foo'     OBSOLETE     " +
             "SUP     (     groupOfNames     $     person     )     " +
             "ABSTRACT     MUST     (     cn     $     sn     )     " +
             "MAY     (     description     $     givenName     )     " +
             "X-ONE-MULTI     (     'a'     'b'     )     " +
             "X-TWO-SINGLE     'c'     )",
        "1.2.3.4",
        new String[] { "first", "second" },
        "foo",
        true,
        new String[] { "groupOfNames", "person" },
        ObjectClassType.ABSTRACT,
        new String[] { "cn", "sn" },
        new String[] { "description", "givenName" },
        twoMixedValuedExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 DESC 'Jos\\c3\\a9 \\27\\5c\\27 Jalape\\c3\\b1o' )",
        "1.2.3.4",
        new String[0],
        "Jos\u00e9 '\\' Jalape\u00f1o",
        false,
        new String[0],
        null,
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 SUP 'quoted' )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[] { "quoted" },
        null,
        new String[0],
        new String[0],
        noExtensions
      },

      new Object[]
      {
        "( 1.2.3.4 MUST ( 'cn' $ 'sn' ) )",
        "1.2.3.4",
        new String[0],
        null,
        false,
        new String[0],
        null,
        new String[] { "cn", "sn" },
        new String[0],
        noExtensions
      },
    };
  }



  /**
   * Retrieves a set of test data that may not be used to create valid object
   * class definitions.
   *
   * @return  A set of test data that may not be used to create valid object
   *          class definitions.
   */
  @DataProvider(name = "testInvalidOCStrings")
  public Object[][] getTestInvalidOCStrings()
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
        "( 1.2.3.4 SUP first SUP second )",
      },

      new Object[]
      {
        "( 1.2.3.4 STRUCTURAL AUXILIARY )",
      },

      new Object[]
      {
        "( 1.2.3.4 STRUCTURAL ABSTRACT )",
      },

      new Object[]
      {
        "( 1.2.3.4 ABSTRACT STRUCTURAL )",
      },

      new Object[]
      {
        "( 1.2.3.4 MUST cn MUST sn )",
      },

      new Object[]
      {
        "( 1.2.3.4 MAY cn MAY sn )",
      },

      new Object[]
      {
        "( 1.2.3.4 MUST ( cn sn ) )",
      },

      new Object[]
      {
        "( 1.2.3.4 SUP contains'a'quote )",
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
    final ObjectClassDefinition oc1 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");

    assertFalse(oc1.equals(null));

    assertTrue(oc1.equals(oc1));

    assertFalse(oc1.equals("foo"));

    ObjectClassDefinition oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertTrue(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ( 'SECOND' 'FIRST') DESC 'FOO' OBSOLETE " +
              "SUP ( PERSON $ GROUPOFNAMES ) STRUCTURAL MUST ( SN $ CN ) " +
              "MAY ( GIVENNAME $ DESCRIPTION ) X-ONE-MULTI ( 'a' 'b' ) " +
              "X-TWO-SINGLE 'c')");
    assertTrue(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.5 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('third') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'bar' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( other ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) AUXILIARY MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (other) " +
              "MAY (description$givenName) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (other) X-ONE-MULTI ('a' 'b') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));

    oc2 = new ObjectClassDefinition(
         "(1.2.3.4 NAME ('first' 'second') DESC 'foo' OBSOLETE " +
              "SUP ( groupOfNames$person ) STRUCTURAL MUST (cn$sn) " +
              "MAY (description$givenName) X-ONE-MULTI ('c' 'd') " +
              "X-TWO-SINGLE 'c')");
    assertFalse(oc1.equals(oc2));
  }
}
