/*
 * Copyright 2007-2017 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2017 UnboundID Corp.
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

import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class provides a set of test for the RDN class.
 */
public class RDNTestCase
       extends LDAPSDKTestCase
{
  // The default standard schema for the LDAP SDK.
  private Schema schema = null;



  /**
   * Obtains the default standard schema for the LDAP SDK.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void getSchema()
         throws Exception
  {
    schema = Schema.getDefaultStandardSchema();
  }



  /**
   * Tests the first constructor, which takes a single name and string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    RDN rdn = new RDN("uid", "test.user");

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the first constructor, which takes a single name and string value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1WithSchema()
         throws Exception
  {
    RDN rdn = new RDN("uid", "test.user", schema);

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the first constructor with a null attribute and a non-null value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullAttr()
  {
    new RDN(null, "test.user");
  }



  /**
   * Tests the first constructor with a non-null attribute and a null value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor1NullValue()
  {
    new RDN("uid", (String) null);
  }



  /**
   * Tests the second constructor, which takes a single name and byte array
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2()
         throws Exception
  {
    RDN rdn = new RDN("uid", "test.user".getBytes("UTF-8"));

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the second constructor, which takes a single name and byte array
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2WithSchema()
         throws Exception
  {
    RDN rdn = new RDN("uid", "test.user".getBytes("UTF-8"), schema);

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the second constructor with a null attribute and a non-null value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullAttr()
         throws Exception
  {
    new RDN(null, "test.user".getBytes("UTF-8"));
  }



  /**
   * Tests the second constructor with a non-null attribute and a null value.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor2NullValue()
  {
    new RDN("uid", (byte[]) null);
  }



  /**
   * Tests the third constructor, which takes an array of names and an array of
   * string values, using a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleElement()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "uid" }, new String[] { "test.user" });

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the third constructor, which takes an array of names and an array of
   * string values, using a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3SingleElementWithSchema()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "uid" }, new String[] { "test.user" },
         schema);

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the third constructor, which takes an array of names and an array of
   * string values, using a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultiElement()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "givenName", "sn" },
                      new String[] { "Test", "User" });

    assertTrue(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 2);
    assertEquals(attrNames[0], "givenName");
    assertEquals(attrNames[1], "sn");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 2);
    assertEquals(attrValues[0], "Test");
    assertEquals(attrValues[1], "User");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 2);
    assertTrue(Arrays.equals(byteArrayValues[0],
         "Test".getBytes("UTF-8")));
    assertTrue(Arrays.equals(byteArrayValues[1],
         "User".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("givenName"));
    assertTrue(rdn.hasAttribute("sn"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test"));
    assertTrue(rdn.hasAttributeValue("sn", "User"));
    assertFalse(rdn.hasAttributeValue("givenName", "User"));
    assertFalse(rdn.hasAttributeValue("sn", "Test"));
    assertFalse(rdn.hasAttributeValue("cn", "Test"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test".getBytes("UTF-8")));
    assertTrue(rdn.hasAttributeValue("sn", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("givenName", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("sn", "Test".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "Test".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "givenname=test+sn=user");
    decodedRDN = new RDN(rdn.toNormalizedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the third constructor, which takes an array of names and an array of
   * string values, using a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor3MultiElementWithSchema()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "givenName", "sn" },
                      new String[] { "Test", "User" },
                      schema);

    assertTrue(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 2);
    assertEquals(attrNames[0], "givenName");
    assertEquals(attrNames[1], "sn");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 2);
    assertEquals(attrValues[0], "Test");
    assertEquals(attrValues[1], "User");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 2);
    assertTrue(Arrays.equals(byteArrayValues[0],
         "Test".getBytes("UTF-8")));
    assertTrue(Arrays.equals(byteArrayValues[1],
         "User".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("givenName"));
    assertTrue(rdn.hasAttribute("sn"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test"));
    assertTrue(rdn.hasAttributeValue("sn", "User"));
    assertFalse(rdn.hasAttributeValue("givenName", "User"));
    assertFalse(rdn.hasAttributeValue("sn", "Test"));
    assertFalse(rdn.hasAttributeValue("cn", "Test"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test".getBytes("UTF-8")));
    assertTrue(rdn.hasAttributeValue("sn", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("givenName", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("sn", "Test".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "Test".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "givenname=test+sn=user");
    decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the third constructor using a null set of attributes.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullAttrs()
  {
    new RDN(null, new String[] { "test.user" });
  }



  /**
   * Tests the third constructor using a null set of values.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NullValues()
  {
    new RDN(new String[] { "uid" }, (String[]) null);
  }



  /**
   * Tests the third constructor using arrays with zero elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3NoElements()
  {
    new RDN(new String[0], new String[0]);
  }



  /**
   * Tests the third constructor using arrays with mismatched numbers of
   * elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor3ElementCountMismatch()
  {
    new RDN(new String[0], new String[1]);
  }



  /**
   * Tests the fourth constructor, which takes an array of names and an array of
   * byte array values, using a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4SingleElement()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "uid" },
                      new byte[][] { "test.user".getBytes("UTF-8") });

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the fourth constructor, which takes an array of names and an array of
   * byte array values, using a single-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4SingleElementWithSchema()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "uid" },
                      new byte[][] { "test.user".getBytes("UTF-8") },
                      schema);

    assertFalse(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 1);
    assertEquals(attrNames[0], "uid");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 1);
    assertEquals(attrValues[0], "test.user");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 1);
    assertTrue(Arrays.equals(byteArrayValues[0],
               "test.user".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("uid"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user"));
    assertFalse(rdn.hasAttributeValue("uid", "not.test.user"));
    assertFalse(rdn.hasAttributeValue("cn", "test.user"));

    assertTrue(rdn.hasAttributeValue("uid", "test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("uid",
                                      "not.test.user".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "test.user".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "uid=test.user");
    decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the fourth constructor, which takes an array of names and an array of
   * byte array values, using a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultiElement()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "givenName", "sn" },
                      new byte[][] { "Test".getBytes("UTF-8"),
                                     "User".getBytes("UTF-8") });

    assertTrue(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 2);
    assertEquals(attrNames[0], "givenName");
    assertEquals(attrNames[1], "sn");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 2);
    assertEquals(attrValues[0], "Test");
    assertEquals(attrValues[1], "User");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 2);
    assertTrue(Arrays.equals(byteArrayValues[0],
         "Test".getBytes("UTF-8")));
    assertTrue(Arrays.equals(byteArrayValues[1],
         "User".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("givenName"));
    assertTrue(rdn.hasAttribute("sn"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test"));
    assertTrue(rdn.hasAttributeValue("sn", "User"));
    assertFalse(rdn.hasAttributeValue("givenName", "User"));
    assertFalse(rdn.hasAttributeValue("sn", "Test"));
    assertFalse(rdn.hasAttributeValue("cn", "Test"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test".getBytes("UTF-8")));
    assertTrue(rdn.hasAttributeValue("sn", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("givenName", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("sn", "Test".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "Test".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "givenname=test+sn=user");
    decodedRDN = new RDN(rdn.toNormalizedString());
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the fourth constructor, which takes an array of names and an array of
   * byte array values, using a multi-element array.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor4MultiElementWithSchema()
         throws Exception
  {
    RDN rdn = new RDN(new String[] { "givenName", "sn" },
                      new byte[][] { "Test".getBytes("UTF-8"),
                                     "User".getBytes("UTF-8") },
                      schema);

    assertTrue(rdn.isMultiValued());

    String[] attrNames = rdn.getAttributeNames();
    assertNotNull(attrNames);
    assertEquals(attrNames.length, 2);
    assertEquals(attrNames[0], "givenName");
    assertEquals(attrNames[1], "sn");

    String[] attrValues = rdn.getAttributeValues();
    assertNotNull(attrValues);
    assertEquals(attrValues.length, 2);
    assertEquals(attrValues[0], "Test");
    assertEquals(attrValues[1], "User");

    byte[][] byteArrayValues = rdn.getByteArrayAttributeValues();
    assertNotNull(byteArrayValues);
    assertEquals(byteArrayValues.length, 2);
    assertTrue(Arrays.equals(byteArrayValues[0],
         "Test".getBytes("UTF-8")));
    assertTrue(Arrays.equals(byteArrayValues[1],
         "User".getBytes("UTF-8")));

    assertTrue(rdn.hasAttribute("givenName"));
    assertTrue(rdn.hasAttribute("sn"));
    assertFalse(rdn.hasAttribute("cn"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test"));
    assertTrue(rdn.hasAttributeValue("sn", "User"));
    assertFalse(rdn.hasAttributeValue("givenName", "User"));
    assertFalse(rdn.hasAttributeValue("sn", "Test"));
    assertFalse(rdn.hasAttributeValue("cn", "Test"));

    assertTrue(rdn.hasAttributeValue("givenName", "Test".getBytes("UTF-8")));
    assertTrue(rdn.hasAttributeValue("sn", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("givenName", "User".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("sn", "Test".getBytes("UTF-8")));
    assertFalse(rdn.hasAttributeValue("cn", "Test".getBytes("UTF-8")));

    RDN decodedRDN = new RDN(rdn.toString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    decodedRDN = new RDN(rdn.toMinimallyEncodedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);

    assertEquals(rdn.toNormalizedString(), "givenname=test+sn=user");
    decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertNotNull(decodedRDN);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN, rdn);
  }



  /**
   * Tests the fourth constructor using a null set of attributes.
   *
   * @throws  Exception  If an unexpected error occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NullAttrs()
         throws Exception
  {
    new RDN(null, new byte[][] { "test.user".getBytes("UTF-8") });
  }



  /**
   * Tests the third constructor using a null set of values.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NullValues()
  {
    new RDN(new String[] { "uid" }, (byte[][]) null);
  }



  /**
   * Tests the fourth constructor using arrays with zero elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4NoElements()
  {
    new RDN(new String[0], new byte[0][]);
  }



  /**
   * Tests the fourth constructor using arrays with mismatched numbers of
   * elements.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testConstructor4ElementCountMismatch()
  {
    new RDN(new String[0], new byte[1][0]);
  }



  /**
   * Tests the fifth constructor, which decodes a string representation, using
   * a valid RDN string.
   *
   * @param  rdnString         The string representation of the RDN to decode.
   * @param  normalizedString  The normalized representation of the provided RDN
   *                           string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidRDNStrings")
  public void testConstructor5Valid(String rdnString, String normalizedString)
         throws Exception
  {
    RDN rdn = new RDN(rdnString);
    assertEquals(rdn.toString(), rdnString);
    assertEquals(rdn.toNormalizedString(), normalizedString);

    RDN decodedRDN = new RDN(rdn.toNormalizedString());
    assertEquals(decodedRDN, rdn);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN.toNormalizedString(), normalizedString);
  }



  /**
   * Tests the fifth constructor, which decodes a string representation, using
   * a valid RDN string.
   *
   * @param  rdnString         The string representation of the RDN to decode.
   * @param  normalizedString  The normalized representation of the provided RDN
   *                           string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidRDNStrings")
  public void testConstructor5ValidWithSchema(final String rdnString,
                                              final String normalizedString)
         throws Exception
  {
    RDN rdn = new RDN(rdnString, schema);
    assertEquals(rdn.toString(), rdnString);
    assertEquals(rdn.toNormalizedString(), normalizedString);

    RDN decodedRDN = new RDN(rdn.toNormalizedString(), schema);
    assertEquals(decodedRDN, rdn);
    assertEquals(decodedRDN.hashCode(), rdn.hashCode());
    assertEquals(decodedRDN.toNormalizedString(), normalizedString);
  }



  /**
   * Tests the fifth constructor, which decodes a string representation, using
   * an invalid RDN string.
   *
   * @param  rdnString  The invalid string representation to fail to decode.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidRDNStrings",
        expectedExceptions = { LDAPException.class })
  public void testConstructor5Invalid(String rdnString)
         throws Exception
  {
    new RDN(rdnString);
  }



  /**
   * Tests the {@code isValidRDN} method with a set of valid strings.
   *
   * @param  s  The string to examine.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidRDNStrings")
  public void testIsValidRDNTrue(String s, String n)
         throws Exception
  {
    assertTrue(RDN.isValidRDN(s));
  }



  /**
   * Tests the {@code isValidRDN} method with a set of invalid strings.
   *
   * @param  s  The string to examine.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testInvalidRDNStrings")
  public void testIsValidRDNFalse(String s)
         throws Exception
  {
    assertFalse(RDN.isValidRDN(s));
  }




  /**
   * Tests the {@code toString} method with various values.
   *
   * @param  names        The set of names to use for the RDN.
   * @param  values       The set of values to use for the RDN.
   * @param  rdnString    The expected string returned from the {@code toString}
   *                      method.
   * @param  meRDNString  The expected string returned from the
   *                      {@code toMinimallyEncodedString} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testToStringData")
  public void testToString(String[] names, String[] values, String rdnString,
                           String meRDNString)
         throws Exception
  {
    RDN rdn = new RDN(names, values);
    assertEquals(rdn.toString(), rdnString);
    assertEquals(rdn.toMinimallyEncodedString(), meRDNString);

    StringBuilder buffer = new StringBuilder();
    rdn.toString(buffer);
    assertEquals(buffer.toString(), rdnString);

    RDN decoded = new RDN(rdn.toString());
    assertEquals(decoded, rdn);

    decoded = new RDN(rdn.toMinimallyEncodedString());
    assertEquals(decoded, rdn);
  }



  /**
   * Tests the {@code normalize} method.
   *
   * @param  s  The string to examine.
   * @param  n  The normalized version of the string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testValidRDNStrings")
  public void testNormalize(String s, String n)
         throws Exception
  {
    assertEquals(RDN.normalize(s), n);
  }



  /**
   * Tests the {@code equals} method using a null element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNull()
         throws Exception
  {
    RDN rdn = new RDN("cn=foo");
    assertFalse(rdn.equals((Object) null));
    assertFalse(rdn.equals((String) null));
  }



  /**
   * Tests the {@code equals} method using an identity comparison.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdentity()
         throws Exception
  {
    RDN rdn = new RDN("cn=foo");
    assertTrue(rdn.equals(rdn));
  }



  /**
   * Tests the {@code equals} methods using a non-RDN element.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsNonRDN()
         throws Exception
  {
    RDN rdn = new RDN("cn=foo");
    assertFalse(rdn.equals(new Object()));
    assertTrue(rdn.equals("cn=foo"));
  }



  /**
   * Tests the {@code equals} method using an identical string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdenticalString()
         throws Exception
  {
    RDN rdn = new RDN("cn=foo");
    assertTrue(rdn.equals(new RDN("cn=foo")));
    assertTrue(RDN.equals("cn=foo", "cn=foo"));
  }



  /**
   * Tests the {@code equals} method using a string that is identical, ignoring
   * differences in capitalization.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdenticalIgnoringCase()
         throws Exception
  {
    RDN rdn = new RDN("cn=foo");
    assertTrue(rdn.equals(new RDN("CN=FOO")));
    assertTrue(RDN.equals("cn=foo", "CN=FOO"));
  }



  /**
   * Tests the {@code equals} method using a string that is identical, ignoring
   * extraneous spaces.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsIdenticalIgnoringSpaces()
         throws Exception
  {
    RDN rdn = new RDN("cn=foo");
    assertTrue(rdn.equals(new RDN("  cn  =  foo  ")));
  }



  /**
   * Tests the {@code compareTo} method.
   *
   * @param  rdn1Str        The string representation of first RDN to be
   *                        compared.
   * @param  rdn2Str        The string representation of the second RDN to be
   *                        compared.
   * @param  compareResult  An integer value that has the same sign as the
   *                        expected result.  Note that it may not be exactly
   *                        equal to the {@code compareTo} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testCompareToRDNs")
  public void testCompareTo(String rdn1Str, String rdn2Str, int compareResult)
         throws Exception
  {
    RDN rdn1 = new RDN(rdn1Str);
    RDN rdn2 = new RDN(rdn2Str);

    if (compareResult < 0)
    {
      assertTrue(rdn1.compareTo(rdn2) < 0);
    }
    else if (compareResult > 0)
    {
      assertTrue(rdn1.compareTo(rdn2) > 0);
    }
    else
    {
      assertEquals(rdn1.compareTo(rdn2), 0);
    }
  }



  /**
   * Tests the {@code compare} method that takes two RDNs.
   *
   * @param  rdn1Str        The string representation of first RDN to be
   *                        compared.
   * @param  rdn2Str        The string representation of the second RDN to be
   *                        compared.
   * @param  compareResult  An integer value that has the same sign as the
   *                        expected result.  Note that it may not be exactly
   *                        equal to the {@code compareTo} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testCompareToRDNs")
  public void testCompareDNs(String rdn1Str, String rdn2Str, int compareResult)
         throws Exception
  {
    RDN rdn1 = new RDN(rdn1Str);
    RDN rdn2 = new RDN(rdn2Str);

    if (compareResult < 0)
    {
      assertTrue(rdn1.compare(rdn1, rdn2) < 0);
    }
    else if (compareResult > 0)
    {
      assertTrue(rdn1.compare(rdn1, rdn2) > 0);
    }
    else
    {
      assertEquals(rdn1.compare(rdn1, rdn2), 0);
    }
  }



  /**
   * Tests the {@code compare} method that takes two strings.
   *
   * @param  rdn1Str        The string representation of first DN to be
   *                        compared.
   * @param  rdn2Str        The string representation of the second DN to be
   *                        compared.
   * @param  compareResult  An integer value that has the same sign as the
   *                        expected result.  Note that it may not be exactly
   *                        equal to the {@code compareTo} result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testCompareToRDNs")
  public void testCompareStrings(String rdn1Str, String rdn2Str,
                                 int compareResult)
         throws Exception
  {
    if (compareResult < 0)
    {
      assertTrue(RDN.compare(rdn1Str, rdn2Str) < 0);
    }
    else if (compareResult > 0)
    {
      assertTrue(RDN.compare(rdn1Str, rdn2Str) > 0);
    }
    else
    {
      assertEquals(RDN.compare(rdn1Str, rdn2Str), 0);
    }
  }



  /**
   * Retrieves a set of valid RDN string representations.
   *
   * @return  A set of valid RDN string representations.
   */
  @DataProvider(name = "testValidRDNStrings")
  public Object[][] getValidRDNStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        "uid=test.user",
        "uid=test.user"
      },

      new Object[]
      {
        "  uid  =  test.user  ",
        "uid=test.user"
      },

      new Object[]
      {
        "cn=Test     User",
        "cn=test user"
      },

      new Object[]
      {
        "givenName=Test+sn=User",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        " sn = User + givenName = Test ",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "givenName=Test+sn=User+cn=Test User+description=foo",
        "cn=test user+description=foo+givenname=test+sn=user"
      },

      new Object[]
      {
        " givenName = Test + sn = User + cn = Test User + description = foo ",
        "cn=test user+description=foo+givenname=test+sn=user"
      },

      new Object[]
      {
        "uid=#746573742e75736572", // Lowercase hex "e"
        "uid=test.user"
      },

      new Object[]
      {
        "uid=#746573742E75736572",  // Uppercase hex "e"
        "uid=test.user"
      },

      new Object[]
      {
        "UID=#544553542e55534552", // "UID=TEST.USER"
        "uid=test.user"
      },

      new Object[]
      {
        "givenName=#74657374+sn=#75736572",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "  givenName  =  #74657374  +  sn  =  #75736572  ",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "givenName=test+sn=#75736572",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "givenName=#74657374+sn=user",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "uid=\\74\\65\\73\\74\\2e\\75\\73\\65\\72",
        "uid=test.user"
      },

      new Object[]
      {
        "uid=\\54\\45\\53\\54\\2e\\55\\53\\45\\52",
        "uid=test.user"
      },

      new Object[]
      {
        "givenName=\\54\\45\\53\\54+sn=\\55\\53\\45\\52",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "uid=t\\45s\\54.\\55s\\45r",  // Mix of hex and non-hex
        "uid=test.user"
      },

      new Object[]
      {
        "uid=\\\\\\#\\=\\\"\\+\\,\\,\\;\\<\\>",
        "uid=\\\\\\#\\=\\\"\\+\\,\\,\\;\\<\\>",
      },

      new Object[]
      {
        "uid=\"test.user\"",
        "uid=test.user"
      },

      new Object[]
      {
        "givenName=\"Test\"+sn=\"User\"",
        "givenname=test+sn=user"
      },

      new Object[]
      {
        "cn=\"User, Test\"+givenName=Test+sn=User",
        "cn=user\\, test+givenname=test+sn=user",
      },

      new Object[]
      {
        "cn=\"1+1=2\"",
        "cn=1\\+1\\=2"
      },

      new Object[]
      {
        "givenName=\"1+1=2\"+sn=\"2+2=4\"",
        "givenname=1\\+1\\=2+sn=2\\+2\\=4"
      },

      new Object[]
      {
        "cn=Austin \\\"Danger\\\" Powers",
        "cn=austin \\\"danger\\\" powers"
      },

      new Object[]
      {
        "cn=#000102030405060708090a0b0c0d0e0f" +
            "101112131415161718191a1b1c1d1e1f" +
            "202122232425262728292a2b2c2d2e2f" +
            "303132333435363738393a3b3c3d3e3f" +
            "404142434445464748494a4b4c4d4e4f" +
            "505152535455565758595a5b5c5d5e5f" +
            "606162636465666768696a6b6c6d6e6f" +
            "707172737475767778797a7b7c7d7e7f",
        "cn=\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f" +
           "\\10\\11\\12\\13\\14\\15\\16\\17\\18\\19\\1a\\1b\\1c\\1d\\1e\\1f" +
           " !\\\"\\#$%&'()*\\+\\,-./" +
           "0123456789:\\;\\<\\=\\>?" +
           "@abcdefghijklmno" +
           "pqrstuvwxyz[\\\\]^_" +
           "`abcdefghijklmno" +
           "pqrstuvwxyz{|}~\\7f"
      },

      new Object[]
      {
        "cn=\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f" +
           "\\10\\11\\12\\13\\14\\15\\16\\17\\18\\19\\1a\\1b\\1c\\1d\\1e\\1f" +
           "\\20\\21\\22\\23\\24\\25\\26\\27\\28\\29\\2a\\2b\\2c\\2d\\2e\\2f" +
           "\\30\\31\\32\\33\\34\\35\\36\\37\\38\\39\\3a\\3b\\3c\\3d\\3e\\3f" +
           "\\40\\41\\42\\43\\44\\45\\46\\47\\48\\49\\4a\\4b\\4c\\4d\\4e\\4f" +
           "\\50\\51\\52\\53\\54\\55\\56\\57\\58\\59\\5a\\5b\\5c\\5d\\5e\\5f" +
           "\\60\\61\\62\\63\\64\\65\\66\\67\\68\\69\\6a\\6b\\6c\\6d\\6e\\6f" +
           "\\70\\71\\72\\73\\74\\75\\76\\77\\78\\79\\7a\\7b\\7c\\7d\\7e\\7f",
        "cn=\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09\\0a\\0b\\0c\\0d\\0e\\0f" +
           "\\10\\11\\12\\13\\14\\15\\16\\17\\18\\19\\1a\\1b\\1c\\1d\\1e\\1f" +
           " !\\\"\\#$%&'()*\\+\\,-./" +
           "0123456789:\\;\\<\\=\\>?" +
           "@abcdefghijklmno" +
           "pqrstuvwxyz[\\\\]^_" +
           "`abcdefghijklmno" +
           "pqrstuvwxyz{|}~\\7f"
      },

      new Object[]
      {
        "givenName=Jos\\c3\\a9+sn=Jalape\\c3\\b1o",
        "givenname=jos\\c3\\a9+sn=jalape\\c3\\b1o"
      },

      new Object[]
      {
        "givenName=JOS\\C3\\89+sn=JALAPE\\C3\\91O",
        "givenname=jos\\c3\\a9+sn=jalape\\c3\\b1o"
      },

      new Object[]
      {
        "uid=",
        "uid="
      },

      new Object[]
      {
        " uid = ",
        "uid="
      },

      new Object[]
      {
        "uid=foo+sn=",
        "sn=+uid=foo"
      },

      new Object[]
      {
        "uid=foo+sn=  ",
        "sn=+uid=foo"
      },

      new Object[]
      {
        "uid=+sn=",
        "sn=+uid="
      },

      new Object[]
      {
        "uid=+sn=test",
        "sn=test+uid="
      },

      new Object[]
      {
        "cn=foo+sn=bar+givenName=",
        "cn=foo+givenname=+sn=bar"
      },
    };
  }



  /**
   * Retrieves a set of invalid RDN string representations.
   *
   * @return  A set of invalid RDN string representations.
   */
  @DataProvider(name = "testInvalidRDNStrings")
  public Object[][] getInvalidRDNStrings()
  {
    return new Object[][]
    {
      new Object[] { "" },
      new Object[] { "uid" },
      new Object[] { "=test" },
      new Object[] { "uid=test+=user" },
      new Object[] { "uid=+sn" },
      new Object[] { "cn=foo+sn=bar+" },
      new Object[] { "cn=foo+sn=bar+ " },
      new Object[] { "cn=foo+sn=bar+givenName" },
      new Object[] { "cn=foo+sn=bar+givenName=+" },
      new Object[] { "cn=foo+sn=bar+givenName=," },
      new Object[] { "uid=test.user+" },
      new Object[] { "uid=test.user," },
      new Object[] { "uid=test.user;" },
      new Object[] { "uid=#746q" },
      new Object[] { "uid=\\74\\6" },
      new Object[] { "uid=\\74\\6q" },
      new Object[] { "cn=\"unclosed quote" },
      new Object[] { "cn=quote in \" the middle" },
      new Object[] { "cn=\"value outside the \" quotes" },
      new Object[] { "not a valid RDN" },
    };
  }



  /**
   * Retrieves a set of data to use when testing the {@code toString} method.
   *
   * @return  A set of data to use when testing the {@code toString} method.
   */
  @DataProvider(name = "testToStringData")
  public Object[][] getTestToStringData()
  {
    return new Object[][]
    {
      new Object[]
      {
        new String[] { "cn" },
        new String[] { "foo" },
        "cn=foo",
        "cn=foo"
      },

      new Object[]
      {
        new String[] { "cn", "sn" },
        new String[] { "foo", "bar" },
        "cn=foo+sn=bar",
        "cn=foo+sn=bar"
      },

      new Object[]
      {
        new String[] { "CN", "SN" },
        new String[] { "FOO", "BAR" },
        "CN=FOO+SN=BAR",
        "CN=FOO+SN=BAR"
      },

      new Object[]
      {
        new String[] { "cn" },
        new String[] { "\\#=+, ; <\u0000>\"" },
        "cn=\\\\\\#\\=\\+\\, \\; \\<\\00\\>\\\"",
        "cn=\\\\\\#\\=\\+\\, \\; \\<\\00\\>\\\""
      },

      new Object[]
      {
        new String[] { "givenName", "sn" },
        new String[] { "Jos\u00e9", "Jalape\u00f1o" },
        "givenName=Jos\\c3\\a9+sn=Jalape\\c3\\b1o",
        "givenName=Jos\u00e9+sn=Jalape\u00f1o"
      },

      new Object[]
      {
        new String[] { "givenName", "sn" },
        new String[] { "JOS\u00c9", "JALAPE\u00d1O" },
        "givenName=JOS\\c3\\89+sn=JALAPE\\c3\\91O",
        "givenName=JOS\u00c9+sn=JALAPE\u00d1O"
      },
    };
  }



  /**
   * Retrieves a set of data that may be used to test the {@code compareTo}
   * method.
   *
   * @return  A set of data that may be used to test the {@code compareTo}
   *          method.
   */
  @DataProvider(name = "testCompareToRDNs")
  public Object[][] getTestCompareToRDNs()
  {
    return new Object[][]
    {
      new Object[]
      {
        "dc=com",
        "dc=com",
        0
      },

      new Object[]
      {
        "o=example.com",
        "dc=com",
        1
      },

      new Object[]
      {
        "dc=com",
        "o=example.com",
        -1
      },

      new Object[]
      {
        "givenName=John+sn=Doe",
        "sn=Doe+givenName=John",
        0
      },

      new Object[]
      {
        "givenName=John+sn=Doe",
        "givenName=Joan+sn=Doe",
        1
      },

      new Object[]
      {
        "givenName=Joan+sn=Doe",
        "givenName=John+sn=Doe",
        -1
      },

      new Object[]
      {
        "givenName=John+sn=Doe",
        "givenName=John+sn=Dof",
        -1
      },

      new Object[]
      {
        "givenName=John+sn=Dof",
        "givenName=John+sn=Doe",
        1
      },
    };
  }



  /**
   * Tests the behavior when trying to normalize an RDN when a schema is
   * available.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNormalizeWithSchema()
         throws Exception
  {
    final Entry testSchemaEntry =
         Schema.getDefaultStandardSchema().getSchemaEntry().duplicate();
    testSchemaEntry.addAttribute("attributeTypes",
         "( 1.2.3.1 " +
              "NAME 'case-exact-attr' " +
              "EQUALITY caseExactMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
         "( 1.2.3.2 " +
              "NAME 'octet-string-attr' " +
              "EQUALITY octetStringMatch " +
              "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )");

    final Schema testSchema = new Schema(testSchemaEntry);

    RDN rdn = new RDN("case-exact-attr", "This Is A Test");
    assertEquals(rdn.toString(), "case-exact-attr=This Is A Test");
    assertEquals(rdn.toNormalizedString(),
         "case-exact-attr=this is a test");

    rdn = new RDN("case-exact-attr", "This Is A Test", testSchema);
    assertEquals(rdn.toString(), "case-exact-attr=This Is A Test");
    assertEquals(rdn.toNormalizedString(),
         "case-exact-attr=This Is A Test");

    rdn = new RDN("octet-string-attr", "This Is A Test");
    assertEquals(rdn.toString(), "octet-string-attr=This Is A Test");
    assertEquals(rdn.toNormalizedString(),
         "octet-string-attr=this is a test");

    rdn = new RDN("octet-string-attr", "This Is A Test", testSchema);
    assertEquals(rdn.toString(), "octet-string-attr=This Is A Test");
    assertEquals(rdn.toNormalizedString(),
         "octet-string-attr=This Is A Test");


    rdn = new RDN("case-exact-attr", " This  Is  A  Test ");
    assertEquals(rdn.toString(),
         "case-exact-attr=\\ This\\  Is\\  A\\  Test\\ ");
    assertEquals(rdn.toNormalizedString(),
         "case-exact-attr=this is a test");

    rdn = new RDN("case-exact-attr", " This  Is  A  Test ", testSchema);
    assertEquals(rdn.toString(),
         "case-exact-attr=\\ This\\  Is\\  A\\  Test\\ ");
    assertEquals(rdn.toNormalizedString(),
         "case-exact-attr=This Is A Test");

    rdn = new RDN("octet-string-attr", " This  Is  A  Test ");
    assertEquals(rdn.toString(),
         "octet-string-attr=\\ This\\  Is\\  A\\  Test\\ ");
    assertEquals(rdn.toNormalizedString(),
         "octet-string-attr=this is a test");

    rdn = new RDN("octet-string-attr", " This  Is  A  Test ", testSchema);
    assertEquals(rdn.toString(),
         "octet-string-attr=\\ This\\  Is\\  A\\  Test\\ ");
    assertEquals(rdn.toNormalizedString(),
         "octet-string-attr=\\ This\\  Is\\  A\\  Test\\ ");
  }
}
