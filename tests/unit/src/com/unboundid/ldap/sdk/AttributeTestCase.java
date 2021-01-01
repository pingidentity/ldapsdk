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
package com.unboundid.ldap.sdk;



import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1Integer;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.matchingrules.IntegerMatchingRule;
import com.unboundid.ldap.matchingrules.CaseExactStringMatchingRule;
import com.unboundid.ldap.matchingrules.CaseIgnoreStringMatchingRule;
import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.LDAPSDKUsageException;

import static com.unboundid.util.StaticUtils.*;



/**
 * This class provides a set of test cases for the Attribute class.
 */
public class AttributeTestCase
       extends LDAPSDKTestCase
{
  /**
   * The matching rule instance that will be used for testing purposes.
   */
  private static final CaseIgnoreStringMatchingRule MATCHING_RULE =
                            CaseIgnoreStringMatchingRule.getInstance();



  // The server schema that will be used for tests in this class.
  private Schema schema;



  /**
   * Reads the schema from the directory server, if available.
   *
   * @throws  Exception  If a problem occurs while trying to read the server
   *                     schema.
   */
  @BeforeClass()
  public void getSchema()
         throws Exception
  {
    schema = getTestDS().getSchema();
  }



  /**
   * Tests the first constructor, which takes an attribute name, using a valid
   * name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    Attribute attr = new Attribute("cn");

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertNull(attr.getValue());
    assertNull(attr.getValueByteArray());
    assertFalse(attr.hasValue());
    assertEquals(attr.getValues().length, 0);
    assertEquals(attr.getValueByteArrays().length, 0);
    assertEquals(attr.size(), 0);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the first constructor by providing a {@code null} value for the
   * attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullType()
         throws Exception
  {
    new Attribute(null);
  }



  /**
   * Tests the second constructor, which takes an attribute name and a string
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    Attribute attr = new Attribute("cn", "John Doe");

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 1);
    assertEquals(attr.getValueByteArrays().length, 1);
    assertEquals(attr.size(), 1);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the second constructor by providing a {@code null} value for the
   * attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullType()
         throws Exception
  {
    new Attribute(null, "John Doe");
  }



  /**
   * Tests the second constructor by providing a {@code null} value for the
   * attribute value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullValue()
         throws Exception
  {
    new Attribute("cn", (String) null);
  }



  /**
   * Tests the third constructor, which takes an attribute name and a byte array
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3()
         throws Exception
  {
    Attribute attr = new Attribute("cn", "John Doe".getBytes("UTF-8"));

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 1);
    assertEquals(attr.getValueByteArrays().length, 1);
    assertEquals(attr.size(), 1);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the third constructor by providing a {@code null} value for the
   * attribute name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullType()
         throws Exception
  {
    new Attribute(null, "John Doe".getBytes("UTF-8"));
  }



  /**
   * Tests the third constructor by providing a {@code null} value for the
   * attribute value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullValue()
         throws Exception
  {
    new Attribute("cn", (byte[]) null);
  }



  /**
   * Tests the fourth constructor, which takes an attribute name and set of
   * string values, by providing the values as varargs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4Varargs()
         throws Exception
  {
    Attribute attr = new Attribute("cn", "John Doe", "Johnathan Doe");

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the fourth constructor, which takes an attribute name and set of
   * string values, by providing the values as a string array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4Array()
         throws Exception
  {
    Attribute attr = new Attribute("cn",
                                   new String[] { "John Doe", "Johnathan Doe"});

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the fifth constructor, which takes an attribute name and set of
   * byte array values, by providing the values as varargs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5Varargs()
         throws Exception
  {
    Attribute attr = new Attribute("cn", "John Doe".getBytes("UTF-8"),
                                   "Johnathan Doe".getBytes("UTF-8"));

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the fifth constructor, which takes an attribute name and set of
   * byte array values, by providing the values as an array of byte arrays.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor5Array()
         throws Exception
  {
    byte[][] values =
    {
      "John Doe".getBytes("UTF-8"),
      "Johnathan Doe".getBytes("UTF-8")
    };

    Attribute attr = new Attribute("cn", values);

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
         "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the sixth constructor, which takes an attribute name and collection
   * of string values, using an empty list.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6EmptyList()
         throws Exception
  {
    Attribute attr = new Attribute("cn", new LinkedList<String>());

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertNull(attr.getValue());
    assertNull(attr.getValueByteArray());
    assertFalse(attr.hasValue());
    assertEquals(attr.getValues().length, 0);
    assertEquals(attr.getValueByteArrays().length, 0);
    assertEquals(attr.size(), 0);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the sixth constructor, which takes an attribute name and collection
   * of string values, using a list with a single value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6SingleValueList()
         throws Exception
  {
    LinkedList<String> values = new LinkedList<String>();
    values.add("John Doe");

    Attribute attr = new Attribute("cn", values);

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
         "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 1);
    assertEquals(attr.getValueByteArrays().length, 1);
    assertEquals(attr.size(), 1);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the sixth constructor, which takes an attribute name and collection
   * of string values, using a list with multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor6MultiValueList()
         throws Exception
  {
    LinkedList<String> values = new LinkedList<String>();
    values.add("John Doe");
    values.add("Johnathan Doe");

    Attribute attr = new Attribute("cn", values);

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the seventh constructor, which takes an attribute name and matching
   * rule.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor7()
         throws Exception
  {
    Attribute attr = new Attribute("cn", MATCHING_RULE);

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertNull(attr.getValue());
    assertNull(attr.getValueByteArray());
    assertFalse(attr.hasValue());
    assertEquals(attr.getValues().length, 0);
    assertEquals(attr.getValueByteArrays().length, 0);
    assertEquals(attr.size(), 0);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the eighth constructor, which takes an attribute name, a matching
   * rule, and a string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor8()
         throws Exception
  {
    Attribute attr = new Attribute("cn", MATCHING_RULE, "John Doe");

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 1);
    assertEquals(attr.getValueByteArrays().length, 1);
    assertEquals(attr.size(), 1);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the ninth constructor, which takes an attribute name, matching rule,
   * and a byte array value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor9()
         throws Exception
  {
    Attribute attr = new Attribute("cn", MATCHING_RULE,
                                   "John Doe".getBytes("UTF-8"));

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 1);
    assertEquals(attr.getValueByteArrays().length, 1);
    assertEquals(attr.size(), 1);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the tenth constructor, which takes an attribute name, a matching
   * rule, and set of string values, by providing the values as  varargs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor10()
         throws Exception
  {
    Attribute attr = new Attribute("cn", MATCHING_RULE, "John Doe",
                                   "Johnathan Doe");

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the eleventh constructor, which takes an attribute name, a matching
   * rule, and set of byte array values, by providing the values as varargs.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor11()
         throws Exception
  {
    Attribute attr = new Attribute("cn", MATCHING_RULE,
                                   "John Doe".getBytes("UTF-8"),
                                   "Johnathan Doe".getBytes("UTF-8"));

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
                             "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the twelfth constructor, which takes an attribute name, a matching
   * rule, and a collection of string values, using a list with multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor12()
         throws Exception
  {
    LinkedList<String> values = new LinkedList<String>();
    values.add("John Doe");
    values.add("Johnathan Doe");

    Attribute attr = new Attribute("cn", MATCHING_RULE, values);

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
    assertNotNull(attr.getMatchingRule());
    assertEquals(attr.getMatchingRule(), MATCHING_RULE);
    assertEquals(attr.getValue(), "John Doe");
    assertTrue(Arrays.equals(attr.getValueByteArray(),
         "John Doe".getBytes("UTF-8")));

    assertTrue(attr.hasValue());
    assertTrue(attr.hasValue("John Doe"));
    assertTrue(attr.hasValue("John Doe".getBytes("UTF-8")));
    assertTrue(attr.hasValue("john doe"));
    assertTrue(attr.hasValue("  john   doe   "));
    assertTrue(attr.hasValue("johnathan  doe"));
    assertFalse(attr.hasValue("Johnny Doe"));

    assertEquals(attr.getValues().length, 2);
    assertEquals(attr.getValueByteArrays().length, 2);
    assertEquals(attr.size(), 2);

    ASN1Sequence attrSequence = attr.encode();
    Attribute attr2 = Attribute.decode(attrSequence);
    assertTrue(attr.equals(attr2));
    assertTrue(attr2.equals(attr));
    assertEquals(attr.hashCode(), attr2.hashCode());

    assertNotNull(attr.toString());
  }



  /**
   * Tests the constructor which takes a name, a {@code Schema} object, and an
   * array of string values.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNameSchemaAndStringArrayValues()
         throws Exception
  {
    // First, test with a null schema and verify that the case-ignore rule is
    // selected for any attribute.
    Attribute cnAttr = new Attribute("cn", (Schema) null, "foo", "bar");

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    Attribute memberAttr = new Attribute("member", (Schema) null,
         "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertFalse(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));


    // Next, test with a non-null schema and verify that the case-ignore rule is
    // selected for the cn attribute and .
    cnAttr = new Attribute("cn", schema, "foo", "bar");

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    memberAttr = new Attribute("member", schema,
         "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 DistinguishedNameMatchingRule.getInstance());

    assertTrue(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));
  }



  /**
   * Tests the constructor which takes a name, a {@code Schema} object, and an
   * array of byte values.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNameSchemaAndByteArrayValues()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // First, test with a null schema and verify that the case-ignore rule is
    // selected for any attribute.
    Attribute cnAttr = new Attribute("cn", (Schema) null,
         "foo".getBytes("UTF-8"), "bar".getBytes("UTF-8"));

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    Attribute memberAttr = new Attribute("member", (Schema) null,
         "uid=test.user,ou=People,dc=example,dc=com".getBytes("UTF-8"));

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertFalse(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));


    // Next, test with a non-null schema and verify that the case-ignore rule is
    // selected for the cn attribute and .
    cnAttr = new Attribute("cn", schema, "foo".getBytes("UTF-8"),
         "bar".getBytes("UTF-8"));

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    memberAttr = new Attribute("member", schema,
         "uid=test.user,ou=People,dc=example,dc=com".getBytes("UTF-8"));

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 DistinguishedNameMatchingRule.getInstance());

    assertTrue(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));
  }



  /**
   * Tests the constructor which takes a name, a {@code Schema} object, and a
   * collection of string values.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNameSchemaAndStringCollectionValues()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // First, test with a null schema and verify that the case-ignore rule is
    // selected for any attribute.
    Attribute cnAttr = new Attribute("cn", (Schema) null,
         Arrays.asList("foo", "bar"));

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
         CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    Attribute memberAttr = new Attribute("member", (Schema) null,
         Arrays.asList("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertFalse(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));


    // Next, test with a non-null schema and verify that the case-ignore rule is
    // selected for the cn attribute and .
    cnAttr = new Attribute("cn", schema, Arrays.asList("foo", "bar"));

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    memberAttr = new Attribute("member", schema,
         Arrays.asList("uid=test.user,ou=People,dc=example,dc=com"));

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 DistinguishedNameMatchingRule.getInstance());

    assertTrue(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));
  }



  /**
   * Tests the constructor which takes a name, a {@code Schema} object, and an
   * array of octet string values.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithNameSchemaAndOctetStringArrayValues()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    // First, test with a null schema and verify that the case-ignore rule is
    // selected for any attribute.
    ASN1OctetString[] cnValues =
    {
      new ASN1OctetString("foo"),
      new ASN1OctetString("bar")
    };
    Attribute cnAttr = new Attribute("cn", (Schema) null, cnValues);

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    ASN1OctetString[] memberValues =
    {
      new ASN1OctetString("uid=test.user,ou=People,dc=example,dc=com")
    };
    Attribute memberAttr = new Attribute("member", (Schema) null, memberValues);

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertFalse(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));


    // Next, test with a non-null schema and verify that the case-ignore rule is
    // selected for the cn attribute and .
    cnAttr = new Attribute("cn", schema, cnValues);

    assertNotNull(cnAttr);

    assertNotNull(cnAttr.getName());
    assertEquals(cnAttr.getName(), "cn");

    assertNotNull(cnAttr.getMatchingRule());
    assertEquals(cnAttr.getMatchingRule(),
                 CaseIgnoreStringMatchingRule.getInstance());

    assertTrue(cnAttr.hasValue("foo"));


    memberAttr = new Attribute("member", schema, memberValues);

    assertNotNull(memberAttr);

    assertNotNull(memberAttr.getName());
    assertEquals(memberAttr.getName(), "member");

    assertNotNull(memberAttr.getMatchingRule());
    assertEquals(memberAttr.getMatchingRule(),
                 DistinguishedNameMatchingRule.getInstance());

    assertTrue(memberAttr.hasValue(
         "uid = test.user, ou=People, dc=example, dc=com"));
  }



  /**
   * Tests the behavior of methods related to attribute options for an attribute
   * that does not contain any attribute options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOptionsNone()
         throws Exception
  {
    Attribute attr = new Attribute("cn", "John Doe");

    assertEquals(attr.getName(), "cn");
    assertEquals(attr.getBaseName(), "cn");
    assertFalse(attr.hasOptions());
    assertFalse(attr.hasOption("lang=en-US"));
    assertTrue(attr.getOptions().isEmpty());
  }



  /**
   * Tests the behavior of methods related to attribute options for an attribute
   * that has a single attribute option.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOptionsSingle()
         throws Exception
  {
    Attribute attr = new Attribute("cn;lang=en-US", "John Doe");

    assertEquals(attr.getName(), "cn;lang=en-US");
    assertEquals(attr.getBaseName(), "cn");
    assertTrue(attr.hasOptions());
    assertTrue(attr.hasOption("lang=en-US"));
    assertTrue(attr.hasOption("lang=en-us"));
    assertFalse(attr.hasOption("binary"));
    assertFalse(attr.getOptions().isEmpty());
    assertEquals(attr.getOptions().size(), 1);
  }



  /**
   * Tests the behavior of methods related to attribute options for an attribute
   * that has multiple attribute options.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOptionsMultiple()
         throws Exception
  {
    Attribute attr = new Attribute("cn;binary;lang=en-US", "John Doe");

    assertEquals(attr.getName(), "cn;binary;lang=en-US");
    assertEquals(attr.getBaseName(), "cn");
    assertTrue(attr.hasOptions());
    assertTrue(attr.hasOption("lang=en-US"));
    assertTrue(attr.hasOption("lang=en-us"));
    assertTrue(attr.hasOption("binary"));
    assertTrue(attr.hasOption("bInArY"));
    assertFalse(attr.getOptions().isEmpty());
    assertEquals(attr.getOptions().size(), 2);
  }



  /**
   * Provides test coverage for the {@code nameIsValid} method.
   *
   * @param  name   The string to test.
   * @param  valid  Indicates whether the provided name is expected to be valid.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testNames")
  public void testNameIsValid(final String name, final boolean valid)
         throws Exception
  {
    assertEquals(Attribute.nameIsValid(name), valid);

    if (name != null)
    {
      if (name.contains(";"))
      {
        assertFalse(Attribute.nameIsValid(name, false));
      }

      assertEquals(new Attribute(name).nameIsValid(), valid);
    }
  }



  /**
   * Provides a set of names to use when testing the {@code nameIsValid} method.
   *
   * @return  A set of names to use when testing the {@code nameIsValid} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testNames")
  public Object[][] getTestNames()
         throws Exception
  {
    return new Object[][]
    {
      new Object[] { null, false },
      new Object[] { "", false},
      new Object[] { "a", true },
      new Object[] { "b", true },
      new Object[] { "z", true },
      new Object[] { "A", true },
      new Object[] { "B", true },
      new Object[] { "Z", true },
      new Object[] { "0", false },
      new Object[] { "1", false },
      new Object[] { "9", false },
      new Object[] { "-", false },
      new Object[] { ";", false },
      new Object[] { " ", false },
      new Object[] { "_", false },
      new Object[] { "aa", true },
      new Object[] { "a0", true },
      new Object[] { "a1", true },
      new Object[] { "a9", true },
      new Object[] { "a9", true },
      new Object[] { "a-", true },
      new Object[] { "Aa", true },
      new Object[] { "aA", true },
      new Object[] { "AA", true },
      new Object[] { "A0", true },
      new Object[] { "A1", true },
      new Object[] { "A9", true },
      new Object[] { "A9", true },
      new Object[] { "A-", true },
      new Object[] { " a", false },
      new Object[] { "a ", false },
      new Object[] { "a_", false },
      new Object[] { "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                          "0123456789-",
                     true },
      new Object[] { "a;a", true },
      new Object[] { "b;B", true },
      new Object[] { "A;a", true },
      new Object[] { "B;B", true },
      new Object[] { "a;a0", true },
      new Object[] { "b;B1", true },
      new Object[] { "A;a2", true },
      new Object[] { "B;B3", true },
      new Object[] { "a;a0;a1", true },
      new Object[] { "b;B1;b2", true },
      new Object[] { "A;a2;A3", true },
      new Object[] { "B;B3;B4", true },
      new Object[] { "a;", false },
      new Object[] { "a;;a", false },
      new Object[] { "a;0", false },
      new Object[] { "a;a;0", false },
      new Object[] { "a; ", false },
      new Object[] { "a;a ", false },
    };
  }



  /**
   * Provides test coverage for the {@code mergeAttribute} method for the
   * case in which one the attributes have values that violate the associated
   * syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMergeAttributesIllegalValues()
         throws Exception
  {
    Attribute a = new Attribute("test",
         DistinguishedNameMatchingRule.getInstance(), "invalid1");
    Attribute b = new Attribute("test",
         DistinguishedNameMatchingRule.getInstance(), "invalid2");

    Attribute c = Attribute.mergeAttributes(a, b, null);
    assertNotNull(c);

    assertNotNull(c.getName());
    assertEquals(c.getName(), "test");

    assertEquals(c.size(), 2);
  }



  /**
   * Provides test coverage for the {@code hashCode} method when used with an
   * attribute whose value violates the associated syntax.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHashCodeIllegalValue()
         throws Exception
  {
    Attribute a = new Attribute("test",
         DistinguishedNameMatchingRule.getInstance(), "invalid");
    a.hashCode();
  }



  /**
   * Tests the {@code equals} method.
   */
  @Test()
  public void testEquals()
  {
    Attribute attr = new Attribute("cn");

    assertFalse(attr.equals(null));
    assertFalse(attr.equals("foo"));
    assertFalse(attr.equals(new Attribute("sn")));
    assertFalse(attr.equals(new Attribute("cn", "John Doe")));

    assertTrue(attr.equals(attr));
    assertTrue(attr.equals(new Attribute("cn")));
    assertTrue(attr.equals(new Attribute("CN")));
    assertTrue(attr.equals(new Attribute("cn", new String[0])));
    assertTrue(attr.equals(new Attribute("cn", new LinkedList<String>())));

    attr = new Attribute("cn", "John Doe", "Johnathan Doe");
    assertFalse(attr.equals(new Attribute("cn")));
    assertFalse(attr.equals(new Attribute("cn", "John Doe")));
    assertTrue(attr.equals(new Attribute("cn", "John Doe", "Johnathan Doe")));
    assertTrue(attr.equals(new Attribute("cn", "john doe", "johnathan doe")));
    assertFalse(attr.equals(new Attribute("cn", "john doe", "johnny doe")));
    assertFalse(attr.equals(new Attribute("cn", "John Doe", "Johnathan Doe",
                                          "Johnny Doe")));
  }



  /**
   * Tests the {@code equals} method with a large number of values that are
   * at least logically equivalent.
   *
   * @throws  Exception  if
   */
  @Test()
  public void testEqualsLargeNumberOfEquivalentValues()
         throws Exception
  {
    final String[] values1 = new String[50];
    final String[] values2 = new String[50];
    final String[] values3 = new String[50];
    final String[] values4 = new String[50];
    final String[] values5 = new String[50];
    for (int i=0; i < values1.length; i++)
    {
      values1[i] = "Value " + i;
      values2[i] = "Value " + i;
      values3[i] = "value " + i;
      values4[50-i-1] = "Value " + i;
      values5[50-i-1] = "Value " + i;
    }

    final Attribute a1 = new Attribute("a", values1);
    final Attribute a2 = new Attribute("a", values2);
    final Attribute a3 = new Attribute("a", values3);
    final Attribute a4 = new Attribute("a", values4);
    final Attribute a5 = new Attribute("a", values5);

    // Verify that attribute 1 equals itself.
    assertTrue(a1.equals(a1));

    // Attributes 1 and 2 have identical values in the same order.
    assertTrue(a1.equals(a2));
    assertTrue(a2.equals(a1));

    // Attributes 1 and 3 have logically-equivalent-but-not-identical values in
    // the same order.
    assertTrue(a1.equals(a3));
    assertTrue(a3.equals(a1));

    // Attributes 1 and 4 have identical values in different orders.
    assertTrue(a1.equals(a4));
    assertTrue(a4.equals(a1));

    // Attributes 1 and 3 have logically-equivalent-but-not-identical values in
    // different orders.
    assertTrue(a1.equals(a5));
    assertTrue(a5.equals(a1));

    // Verify equality among the other attributes.
    assertTrue(a2.equals(a2));
    assertTrue(a2.equals(a3));
    assertTrue(a2.equals(a4));
    assertTrue(a2.equals(a5));

    assertTrue(a3.equals(a2));
    assertTrue(a3.equals(a3));
    assertTrue(a3.equals(a4));
    assertTrue(a3.equals(a5));

    assertTrue(a4.equals(a2));
    assertTrue(a4.equals(a3));
    assertTrue(a4.equals(a4));
    assertTrue(a4.equals(a5));

    assertTrue(a5.equals(a2));
    assertTrue(a5.equals(a3));
    assertTrue(a5.equals(a4));
    assertTrue(a5.equals(a5));
  }



  /**
   * Tests the {@code equals} method with a large number of values that are
   * at not logically equivalent.
   *
   * @throws  Exception  if
   */
  @Test()
  public void testEqualsLargeNumberOfNonEquivalentValues()
         throws Exception
  {
    final String[] values1 = new String[50];
    final String[] values2 = new String[50];
    final String[] values3 = new String[50];
    final String[] values4 = new String[50];
    for (int i=0; i < values1.length; i++)
    {
      values1[i] = "Value " + i;
      values2[i] = "value " + i;
      values3[i] = "Value " + (i+1);
      values4[i] = "value " + (i+50);
    }

    final Attribute a1 = new Attribute("a", values1);
    final Attribute a2 = new Attribute("a", values2);
    final Attribute a3 = new Attribute("a", values3);
    final Attribute a4 = new Attribute("a", values4);

    assertTrue(a1.equals(a1));
    assertTrue(a1.equals(a2));
    assertFalse(a1.equals(a3));
    assertFalse(a1.equals(a4));

    assertTrue(a2.equals(a1));
    assertTrue(a2.equals(a2));
    assertFalse(a2.equals(a3));
    assertFalse(a2.equals(a4));

    assertFalse(a3.equals(a1));
    assertFalse(a3.equals(a2));
    assertTrue(a3.equals(a3));
    assertFalse(a3.equals(a4));

    assertFalse(a4.equals(a1));
    assertFalse(a4.equals(a2));
    assertFalse(a4.equals(a3));
    assertTrue(a4.equals(a4));
  }



  /**
   * Tests the behavior of the {@code equals} method with values that cannot be
   * normalized.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsValuesFailingNormalize()
         throws Exception
  {
    // Test attributes with a single value.
    final Attribute a1 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), "not a valid DN");
    final Attribute a2 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), "not a valid DN");
    assertTrue(a1.equals(a1));
    assertTrue(a1.equals(a2));
    assertTrue(a2.equals(a2));


    // Test attributes with a large number of values, in which none of them can
    // be normalized.
    final String[] values3 = new String[50];
    final String[] values4 = new String[50];
    final String[] values5 = new String[50];
    final String[] values6 = new String[50];
    for (int i=0; i < values3.length; i++)
    {
      values3[i] = "not a valid DN " + i;
      values4[i] = "not a valid DN " + i;
      values5[i] = "not a valid dn " + i;

      if (i == 49)
      {
        values6[i] = "not a valid dn " + i;
      }
      else
      {
        values6[i] = "not a valid DN " + i;
      }
    }

    final Attribute a3 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values3);
    final Attribute a4 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values4);
    final Attribute a5 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values5);
    final Attribute a6 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values6);

    assertTrue(a3.equals(a3));
    assertTrue(a3.equals(a4));
    assertFalse(a3.equals(a5));
    assertFalse(a3.equals(a6));

    assertTrue(a4.equals(a3));
    assertTrue(a4.equals(a4));
    assertFalse(a4.equals(a5));
    assertFalse(a4.equals(a6));

    assertFalse(a5.equals(a3));
    assertFalse(a5.equals(a4));
    assertTrue(a5.equals(a5));
    assertFalse(a5.equals(a6));

    assertFalse(a6.equals(a3));
    assertFalse(a6.equals(a4));
    assertFalse(a6.equals(a5));
    assertTrue(a6.equals(a6));


    // Test attributes with a large number of values, in which most of them
    // can be normalized.
    final String[] values7  = new String[50];
    final String[] values8  = new String[50];
    final String[] values9  = new String[50];
    final String[] values10 = new String[50];
    final String[] values11 = new String[50];
    for (int i=0; i < values7.length; i++)
    {
      if (i == 49)
      {
        values7[i] = "not a valid DN";
        values8[i] = "not a valid DN";
        values9[i] = "not a valid dn";
      }
      else
      {
        values7[i] = "cn=test." + i + ",dc=example,dc=com";
        values8[i] = "cn=test." + i + ",dc=example,dc=com";
        values9[i] = "CN=Test." + i + ", DC=Example,DC=Com";
      }

      values10[i] = "cn=test." + i + ",dc=example,dc=com";
      values11[i] = "CN=Test." + i + ", DC=Example,DC=Com";
    }

    final Attribute a7 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values7);
    final Attribute a8 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values8);
    final Attribute a9 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values9);
    final Attribute a10 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values10);
    final Attribute a11 = new Attribute("a",
         DistinguishedNameMatchingRule.getInstance(), values11);

    assertTrue(a7.equals(a7));
    assertTrue(a7.equals(a8));
    assertFalse(a7.equals(a9));
    assertFalse(a7.equals(a10));
    assertFalse(a7.equals(a11));

    assertTrue(a8.equals(a7));
    assertTrue(a8.equals(a8));
    assertFalse(a8.equals(a9));
    assertFalse(a8.equals(a10));
    assertFalse(a8.equals(a11));

    assertFalse(a9.equals(a7));
    assertFalse(a9.equals(a8));
    assertTrue(a9.equals(a9));
    assertFalse(a9.equals(a10));
    assertFalse(a9.equals(a11));

    assertFalse(a10.equals(a7));
    assertFalse(a10.equals(a8));
    assertFalse(a10.equals(a9));
    assertTrue(a10.equals(a10));
    assertTrue(a10.equals(a11));

    assertFalse(a11.equals(a7));
    assertFalse(a11.equals(a8));
    assertFalse(a11.equals(a9));
    assertTrue(a11.equals(a10));
    assertTrue(a11.equals(a11));
  }



  /**
   * Tests the {@code getValueAsBoolean} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsBoolean()
         throws Exception
  {
    // An attribute with no values should return null.
    Attribute a = new Attribute("a");
    assertNull(a.getValueAsBoolean());

    // Test values that should return TRUE.
    String[] trueStrs =
    {
      "TRUE",
      "true",
      "T",
      "t",
      "YES",
      "yes",
      "Y",
      "y",
      "ON",
      "on",
      "1",
    };
    for (String s : trueStrs)
    {
      a = new Attribute("a", s);
      assertNotNull(a.getValueAsBoolean());
      assertTrue(a.getValueAsBoolean());
    }

    // Test values that should return FALSE.
    String[] falseStrs =
    {
      "FALSE",
      "false",
      "F",
      "f",
      "NO",
      "no",
      "n",
      "n",
      "OFF",
      "off",
      "0",
    };
    for (String s : falseStrs)
    {
      a = new Attribute("a", s);
      assertNotNull(a.getValueAsBoolean());
      assertFalse(a.getValueAsBoolean());
    }

    // Test invalid values.
    String[] invalidStrs =
    {
      "",
      "invalid"
    };
    for (String s : invalidStrs)
    {
      a = new Attribute("a", s);
      assertNull(a.getValueAsBoolean());
    }
  }



  /**
   * Tests the {@code getValueAsDate} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsDate()
         throws Exception
  {
    // An attribute with no values should return null.
    Attribute a = new Attribute("a");
    assertNull(a.getValueAsDate());

    // Test values that should return a valid value.
    LinkedHashMap<String,Date> validValues =
         new LinkedHashMap<String,Date>();
    Date d = new Date();
    validValues.put(encodeGeneralizedTime(d), d);

    for (String s : validValues.keySet())
    {
      a = new Attribute("a", s);
      assertNotNull(a.getValueAsDate());
      assertEquals(a.getValueAsDate(), validValues.get(s));
    }

    // Test values that should not return a valid value.
    String[] invalidValues =
    {
      "",
      "invalid"
    };

    for (String s : invalidValues)
    {
      a = new Attribute("a", s);
      assertNull(a.getValueAsDate());
    }
  }



  /**
   * Tests the {@code getValueAsDN} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsDN()
         throws Exception
  {
    // An attribute with no values should return null.
    Attribute a = new Attribute("a");
    assertNull(a.getValueAsDN());

    // Test values that should return a valid value.
    a = new Attribute("a", "");
    assertEquals(a.getValueAsDN(), DN.NULL_DN);

    a = new Attribute("a", "dc=example,dc=com");
    assertEquals(a.getValueAsDN(), new DN("dc=example,dc=com"));

    // Test values that should not return a valid value.
    a = new Attribute("a", "invalid");
    assertNull(a.getValueAsDN());
  }



  /**
   * Tests the {@code getValueAsInteger} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsInteger()
         throws Exception
  {
    // An attribute with no values should return null.
    Attribute a = new Attribute("a");
    assertNull(a.getValueAsInteger());

    // Test values that should return a valid value.
    LinkedHashMap<String,Integer> validValues =
         new LinkedHashMap<String,Integer>();
    validValues.put("0", 0);
    validValues.put("1", 1);
    validValues.put("-1", -1);
    validValues.put("1234", 1234);
    validValues.put("-5678", -5678);
    validValues.put("-2147483648", Integer.MIN_VALUE);
    validValues.put("2147483647", Integer.MAX_VALUE);

    for (String s : validValues.keySet())
    {
      a = new Attribute("a", s);
      assertNotNull(a.getValueAsInteger());
      assertEquals(a.getValueAsInteger(), validValues.get(s));
    }

    // Test values that should not return a valid value.
    String[] invalidValues =
    {
      "",
      "invalid",
      String.valueOf(1L + Integer.MAX_VALUE),
      String.valueOf(-1L + Integer.MIN_VALUE),
      String.valueOf(Long.MAX_VALUE) + '0',
      String.valueOf(Long.MIN_VALUE) + '0'
    };

    for (String s : invalidValues)
    {
      a = new Attribute("a", s);
      assertNull(a.getValueAsInteger());
    }
  }



  /**
   * Tests the {@code getValueAsLong} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetValueAsLong()
         throws Exception
  {
    // An attribute with no values should return null.
    Attribute a = new Attribute("a");
    assertNull(a.getValueAsLong());

    // Test values that should return a valid value.
    LinkedHashMap<String,Long> validValues =
         new LinkedHashMap<String,Long>();
    validValues.put("0", 0L);
    validValues.put("1", 1L);
    validValues.put("-1", -1L);
    validValues.put("1234", 1234L);
    validValues.put("-5678", -5678L);
    validValues.put("-2147483648", Long.valueOf(Integer.MIN_VALUE));
    validValues.put("2147483647", Long.valueOf(Integer.MAX_VALUE));
    validValues.put("-2147483649", (Integer.MIN_VALUE - 1L));
    validValues.put("2147483648", (Integer.MAX_VALUE + 1L));
    validValues.put("-9223372036854775808", Long.MIN_VALUE);
    validValues.put("9223372036854775807", Long.MAX_VALUE);

    for (String s : validValues.keySet())
    {
      a = new Attribute("a", s);
      assertNotNull(a.getValueAsLong());
      assertEquals(a.getValueAsLong(), validValues.get(s));
    }

    // Test values that should not return a valid value.
    String[] invalidValues =
    {
      "",
      "invalid",
      String.valueOf(Long.MAX_VALUE) + '0',
      String.valueOf(Long.MIN_VALUE) + '0'
    };

    for (String s : invalidValues)
    {
      a = new Attribute("a", s);
      assertNull(a.getValueAsLong());
    }
  }



  /**
   * Tests the {@code hasValue} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testHasValue()
         throws Exception
  {
    Attribute a = new Attribute("foo", "bar");

    assertTrue(a.hasValue());

    assertTrue(a.hasValue("bar"));
    assertTrue(a.hasValue("Bar"));

    assertTrue(a.hasValue("bar", CaseExactStringMatchingRule.getInstance()));
    assertFalse(a.hasValue("Bar", CaseExactStringMatchingRule.getInstance()));

    assertTrue(a.hasValue("bar", IntegerMatchingRule.getInstance()));
    assertFalse(a.hasValue("Bar", IntegerMatchingRule.getInstance()));

    assertTrue(a.hasValue("bar".getBytes()));
    assertTrue(a.hasValue("Bar".getBytes()));

    assertTrue(a.hasValue("bar".getBytes(),
                          CaseExactStringMatchingRule.getInstance()));
    assertFalse(a.hasValue("Bar".getBytes(),
                           CaseExactStringMatchingRule.getInstance()));

    assertTrue(a.hasValue("bar".getBytes(),
                           IntegerMatchingRule.getInstance()));
    assertFalse(a.hasValue("Bar".getBytes(),
                           IntegerMatchingRule.getInstance()));
  }



  /**
   * Tests the {@code decode} method with a sequence whose length is not 2.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeInvalidSequenceLength()
         throws Exception
  {
    Attribute.decode(new ASN1Sequence(new ASN1OctetString("foo")));
  }



  /**
   * Tests the {@code decode} method with a sequence whose second element is not
   * a valid set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeSecondElementNotSet()
         throws Exception
  {
    Attribute.decode(new ASN1Sequence(new ASN1OctetString("foo"),
                                      new ASN1Integer(1)));
  }



  /**
   * Provides a number of tests involving values that may need to be
   * base64-encoded.
   *
   * @param  value   The value for which to make the determination.
   * @param  encode  Indicates whether the provided value needs to be
   *                 base64-encoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testBase64")
  public void testBase64(final String value, final boolean encode)
         throws Exception
  {
    assertEquals(Attribute.needsBase64Encoding(value), encode);

    assertEquals(Attribute.needsBase64Encoding(getBytes(value)), encode);

    final Attribute a = new Attribute("foo", value, "value2");
    assertEquals(a.needsBase64Encoding(), encode);
    assertNotNull(a.toString());
  }



  /**
   * Provides a set of test values for the {@code testBase64} method.
   *
   * @return  A set of test values for the {@code testBase64} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testBase64")
  public Object[][] getTestBase64Data()
         throws Exception
  {
    return new Object[][]
    {
      new Object[] { "", false },
      new Object[] { " ", true },
      new Object[] { "a", false },
      new Object[] { " a ", true },
      new Object[] { ":a ", true },
      new Object[] { "<a ", true },
      new Object[] { "  a ", true },
      new Object[] { "a ", true },
      new Object[] { "a  ", true },
      new Object[] { "ab ", true },
      new Object[] { " ab ", true },
      new Object[] { "ab  ", true },
      new Object[] { "a b", false },
      new Object[] { "\u00f1", true },
      new Object[] { "\u00f1a", true },
      new Object[] { "a\u00f1", true },
      new Object[] { "a\u00f1b", true },
      new Object[] { "jalape\u00f1o", true },
      new Object[] { "jalape\u00f1o", true },
      new Object[] { "a\nb", true },
      new Object[] { "a\r\nb", true },
    };
  }
}
