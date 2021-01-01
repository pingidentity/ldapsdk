/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.util.LinkedHashMap;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.asn1.ASN1Sequence;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.LDAPSDKUsageException;



/**
 * This class defines a set of test cases for the override search limits request
 * control.
 */
public final class OverrideSearchLimitsRequestControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of a control created with the constructor that allows a
   * single property to be set.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSinglePropertyConstructor()
         throws Exception
  {
    OverrideSearchLimitsRequestControl c =
         new OverrideSearchLimitsRequestControl("propertyName",
              "propertyValue");

    c = new OverrideSearchLimitsRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.56");

    assertFalse(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getProperties());
    assertFalse(c.getProperties().isEmpty());
    assertEquals(c.getProperties().size(), 1);

    assertNotNull(c.getProperty("propertyName"));
    assertEquals(c.getProperty("propertyName"), "propertyValue");

    assertNull(c.getProperty("propertyName".toLowerCase()));
    assertNull(c.getProperty("propertyName".toUpperCase()));

    assertNull(c.getProperty("undefinedProperty"));

    assertNull(c.getPropertyAsBoolean("propertyName", null));

    assertNull(c.getPropertyAsBoolean("undefinedProperty", null));

    assertNull(c.getPropertyAsInteger("propertyName", null));

    assertNull(c.getPropertyAsInteger("undefinedProperty", null));

    assertNull(c.getPropertyAsLong("propertyName", null));

    assertNull(c.getPropertyAsLong("undefinedProperty", null));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of a control created with the constructor that takes a
   * map of properties.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPropertyMapConstructor()
         throws Exception
  {
    final LinkedHashMap<String,String> propertyMap = new LinkedHashMap<>(10);
    propertyMap.put("stringValue", "hello");
    propertyMap.put("trueValue", "true");
    propertyMap.put("falseValue", "false");
    propertyMap.put("zeroValue", "0");
    propertyMap.put("positiveOneValue", "1");
    propertyMap.put("negativeOneValue", "-1");
    propertyMap.put("integerMaxValue", String.valueOf(Integer.MAX_VALUE));
    propertyMap.put("integerMinValue", String.valueOf(Integer.MIN_VALUE));
    propertyMap.put("longMaxValue", String.valueOf(Long.MAX_VALUE));
    propertyMap.put("longMinValue", String.valueOf(Long.MIN_VALUE));

    OverrideSearchLimitsRequestControl c =
         new OverrideSearchLimitsRequestControl(propertyMap, true);

    c = new OverrideSearchLimitsRequestControl(c);

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.56");

    assertTrue(c.isCritical());

    assertTrue(c.hasValue());
    assertNotNull(c.getValue());

    assertNotNull(c.getProperties());
    assertFalse(c.getProperties().isEmpty());
    assertEquals(c.getProperties().size(), 10);

    assertNotNull(c.getProperty("stringValue"));
    assertEquals(c.getProperty("stringValue"), "hello");
    assertNull(c.getPropertyAsBoolean("stringValue", null));
    assertNull(c.getPropertyAsInteger("stringValue", null));
    assertNull(c.getPropertyAsLong("stringValue", null));

    assertNotNull(c.getPropertyAsBoolean("stringValue", Boolean.TRUE));
    assertEquals(c.getPropertyAsBoolean("stringValue", Boolean.TRUE),
         Boolean.TRUE);

    assertNotNull(c.getPropertyAsBoolean("stringValue", Boolean.FALSE));
    assertEquals(c.getPropertyAsBoolean("stringValue", Boolean.FALSE),
         Boolean.FALSE);

    assertNotNull(c.getPropertyAsInteger("stringValue", 1234));
    assertEquals(c.getPropertyAsInteger("stringValue", 1234),
         Integer.valueOf(1234));

    assertNotNull(c.getPropertyAsLong("stringValue", 1234L));
    assertEquals(c.getPropertyAsLong("stringValue", 1234L),
         Long.valueOf(1234L));

    assertNotNull(c.getProperty("trueValue"));
    assertEquals(c.getProperty("trueValue"), "true");
    assertNotNull(c.getPropertyAsBoolean("trueValue", null));
    assertEquals(c.getPropertyAsBoolean("trueValue", null), Boolean.TRUE);
    assertNull(c.getPropertyAsInteger("trueValue", null));
    assertNull(c.getPropertyAsLong("trueValue", null));

    assertNotNull(c.getProperty("falseValue"));
    assertEquals(c.getProperty("falseValue"), "false");
    assertNotNull(c.getPropertyAsBoolean("falseValue", null));
    assertEquals(c.getPropertyAsBoolean("falseValue", null), Boolean.FALSE);
    assertNull(c.getPropertyAsInteger("falseValue", null));
    assertNull(c.getPropertyAsLong("falseValue", null));

    assertNotNull(c.getProperty("zeroValue"));
    assertEquals(c.getProperty("zeroValue"), "0");
    assertNotNull(c.getPropertyAsBoolean("zeroValue", null));
    assertEquals(c.getPropertyAsBoolean("zeroValue", null), Boolean.FALSE);
    assertNotNull(c.getPropertyAsInteger("zeroValue", null));
    assertEquals(c.getPropertyAsInteger("zeroValue", null), Integer.valueOf(0));
    assertNotNull(c.getPropertyAsLong("zeroValue", null));
    assertEquals(c.getPropertyAsLong("zeroValue", null), Long.valueOf(0L));

    assertNotNull(c.getProperty("positiveOneValue"));
    assertEquals(c.getProperty("positiveOneValue"), "1");
    assertNotNull(c.getPropertyAsBoolean("positiveOneValue", null));
    assertEquals(c.getPropertyAsBoolean("positiveOneValue", null),
         Boolean.TRUE);
    assertNotNull(c.getPropertyAsInteger("positiveOneValue", null));
    assertEquals(c.getPropertyAsInteger("positiveOneValue", null),
         Integer.valueOf(1));
    assertNotNull(c.getPropertyAsLong("positiveOneValue", null));
    assertEquals(c.getPropertyAsLong("positiveOneValue", null),
         Long.valueOf(1L));

    assertNotNull(c.getProperty("negativeOneValue"));
    assertEquals(c.getProperty("negativeOneValue"), "-1");
    assertNull(c.getPropertyAsBoolean("negativeOneValue", null));
    assertNotNull(c.getPropertyAsInteger("negativeOneValue", null));
    assertEquals(c.getPropertyAsInteger("negativeOneValue", null),
         Integer.valueOf(-1));
    assertNotNull(c.getPropertyAsLong("negativeOneValue", null));
    assertEquals(c.getPropertyAsLong("negativeOneValue", null),
         Long.valueOf(-1L));

    assertNotNull(c.getProperty("integerMaxValue"));
    assertEquals(c.getProperty("integerMaxValue"),
         String.valueOf(Integer.MAX_VALUE));
    assertNull(c.getPropertyAsBoolean("integerMaxValue", null));
    assertNotNull(c.getPropertyAsInteger("integerMaxValue", null));
    assertEquals(c.getPropertyAsInteger("integerMaxValue", null),
         Integer.valueOf(Integer.MAX_VALUE));
    assertNotNull(c.getPropertyAsLong("integerMaxValue", null));
    assertEquals(c.getPropertyAsLong("integerMaxValue", null),
         Long.valueOf(Integer.MAX_VALUE));

    assertNotNull(c.getProperty("integerMinValue"));
    assertEquals(c.getProperty("integerMinValue"),
         String.valueOf(Integer.MIN_VALUE));
    assertNull(c.getPropertyAsBoolean("integerMinValue", null));
    assertNotNull(c.getPropertyAsInteger("integerMinValue", null));
    assertEquals(c.getPropertyAsInteger("integerMinValue", null),
         Integer.valueOf(Integer.MIN_VALUE));
    assertNotNull(c.getPropertyAsLong("integerMinValue", null));
    assertEquals(c.getPropertyAsLong("integerMinValue", null),
         Long.valueOf(Integer.MIN_VALUE));

    assertNotNull(c.getProperty("longMaxValue"));
    assertEquals(c.getProperty("longMaxValue"),
         String.valueOf(Long.MAX_VALUE));
    assertNull(c.getPropertyAsBoolean("longMaxValue", null));
    assertNull(c.getPropertyAsInteger("longMaxValue", null));
    assertNotNull(c.getPropertyAsLong("longMaxValue", null));
    assertEquals(c.getPropertyAsLong("longMaxValue", null),
         Long.valueOf(Long.MAX_VALUE));

    assertNotNull(c.getProperty("longMinValue"));
    assertEquals(c.getProperty("longMinValue"),
         String.valueOf(Long.MIN_VALUE));
    assertNull(c.getPropertyAsBoolean("longMinValue", null));
    assertNull(c.getPropertyAsInteger("longMinValue", null));
    assertNotNull(c.getPropertyAsLong("longMinValue", null));
    assertEquals(c.getPropertyAsLong("longMinValue", null),
         Long.valueOf(Long.MIN_VALUE));

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the {@code getPropertyAsBoolean} method with the
   * provided value.
   *
   * @param  stringValue   The string value to use when testing.
   * @param  booleanValue  The expected return value from the
   *                       {@code getPropertyAsBoolean} method.
   */
  @Test(dataProvider = "getPropertyAsBooleanTestData")
  public void testGetPropertyAsBoolean(final String stringValue,
                                       final Boolean booleanValue)
  {
    final OverrideSearchLimitsRequestControl c =
         new OverrideSearchLimitsRequestControl("name", stringValue);

    assertEquals(c.getPropertyAsBoolean("name", null), booleanValue);

    if (booleanValue == null)
    {
      assertNull(c.getPropertyAsBoolean("name", null));

      assertNotNull(c.getPropertyAsBoolean("name", Boolean.TRUE));
      assertEquals(c.getPropertyAsBoolean("name", Boolean.TRUE), Boolean.TRUE);

      assertNotNull(c.getPropertyAsBoolean("name", Boolean.FALSE));
      assertEquals(c.getPropertyAsBoolean("name", Boolean.FALSE),
           Boolean.FALSE);
    }
    else
    {
      assertNotNull(c.getPropertyAsBoolean("name", null));

      assertNotNull(c.getPropertyAsBoolean("name", Boolean.TRUE));
      assertEquals(c.getPropertyAsBoolean("name", Boolean.TRUE), booleanValue);

      assertNotNull(c.getPropertyAsBoolean("name", Boolean.FALSE));
      assertEquals(c.getPropertyAsBoolean("name", Boolean.FALSE), booleanValue);
    }
  }



  /**
   * Retrieves a set of data to use when testing the
   * {@code getPropertyAsBoolean} method.
   *
   * @return  A set of data to use when testing the {@code getPropertyAsBoolean}
   *          method.
   */
  @DataProvider(name="getPropertyAsBooleanTestData")
  public Object[][] getGetPropertyAsBooleanTestData()
  {
    return new Object[][]
    {
      new Object[]
      {
        "true",
        Boolean.TRUE
      },
      new Object[]
      {
        "TRUE",
        Boolean.TRUE
      },
      new Object[]
      {
        "True",
        Boolean.TRUE
      },
      new Object[]
      {
        "t",
        Boolean.TRUE
      },
      new Object[]
      {
        "T",
        Boolean.TRUE
      },
      new Object[]
      {
        "yes",
        Boolean.TRUE
      },
      new Object[]
      {
        "YES",
        Boolean.TRUE
      },
      new Object[]
      {
        "Yes",
        Boolean.TRUE
      },
      new Object[]
      {
        "y",
        Boolean.TRUE
      },
      new Object[]
      {
        "Y",
        Boolean.TRUE
      },
      new Object[]
      {
        "on",
        Boolean.TRUE
      },
      new Object[]
      {
        "ON",
        Boolean.TRUE
      },
      new Object[]
      {
        "On",
        Boolean.TRUE
      },
      new Object[]
      {
        "1",
        Boolean.TRUE
      },
      new Object[]
      {
        "false",
        Boolean.FALSE
      },
      new Object[]
      {
        "FALSE",
        Boolean.FALSE
      },
      new Object[]
      {
        "False",
        Boolean.FALSE
      },
      new Object[]
      {
        "f",
        Boolean.FALSE
      },
      new Object[]
      {
        "F",
        Boolean.FALSE
      },
      new Object[]
      {
        "no",
        Boolean.FALSE
      },
      new Object[]
      {
        "NO",
        Boolean.FALSE
      },
      new Object[]
      {
        "No",
        Boolean.FALSE
      },
      new Object[]
      {
        "n",
        Boolean.FALSE
      },
      new Object[]
      {
        "N",
        Boolean.FALSE
      },
      new Object[]
      {
        "off",
        Boolean.FALSE
      },
      new Object[]
      {
        "OFF",
        Boolean.FALSE
      },
      new Object[]
      {
        "Off",
        Boolean.FALSE
      },
      new Object[]
      {
        "0",
        Boolean.FALSE
      },
      new Object[]
      {
        "I guess",
        null
      },
      new Object[]
      {
        "2",
        null
      },
    };
  }



  /**
   * Tests the behavior when trying to retrieve a property with a {@code null}
   * property name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPropertyNullPropertyName()
         throws Exception
  {
    final OverrideSearchLimitsRequestControl c =
         new OverrideSearchLimitsRequestControl("name", "value");

    c.getProperty(null);
  }



  /**
   * Tests the behavior when trying to retrieve a property with an empty
   * property name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testGetPropertyEmptyPropertyName()
         throws Exception
  {
    final OverrideSearchLimitsRequestControl c =
         new OverrideSearchLimitsRequestControl("name", "value");

    c.getProperty("");
  }



  /**
   * Tests the behavior when trying to encode a control with a {@code null}
   * property map.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeNullPropertyMap()
         throws Exception
  {
    OverrideSearchLimitsRequestControl.encodeValue(null);
  }



  /**
   * Tests the behavior when trying to encode a control with an empty property
   * map.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodeEmptyPropertyMap()
         throws Exception
  {
    final LinkedHashMap<String,String> propertyMap = new LinkedHashMap<>(0);
    OverrideSearchLimitsRequestControl.encodeValue(propertyMap);
  }



  /**
   * Tests the behavior when trying to encode a control with a property map that
   * contains an empty key.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodePropertyMapWithEmptyKey()
         throws Exception
  {
    final LinkedHashMap<String,String> propertyMap = new LinkedHashMap<>(1);
    propertyMap.put("", "value");

    OverrideSearchLimitsRequestControl.encodeValue(propertyMap);
  }



  /**
   * Tests the behavior when trying to encode a control with a property map that
   * contains an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testEncodePropertyMapWithEmptyValue()
         throws Exception
  {
    final LinkedHashMap<String,String> propertyMap = new LinkedHashMap<>(1);
    propertyMap.put("key", "");

    OverrideSearchLimitsRequestControl.encodeValue(propertyMap);
  }



  /**
   * Tests the behavior when trying to decode a control that does not have a
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithoutValue()
         throws Exception
  {
    final Control c = new Control("1.3.6.1.4.1.30221.2.5.56", false);
    new OverrideSearchLimitsRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value is not an
   * ASN.1 sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlValueNotSequence()
         throws Exception
  {
    final Control c = new Control("1.3.6.1.4.1.30221.2.5.56", false,
         new ASN1OctetString("this is not a sequence"));
    new OverrideSearchLimitsRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence is
   * empty.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlEmptyValueSequence()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence();

    final Control c = new Control("1.3.6.1.4.1.30221.2.5.56", false,
         new ASN1OctetString(valueSequence.encode()));
    new OverrideSearchLimitsRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a property with an empty name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlEmptyPropertyName()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1OctetString(""),
              new ASN1OctetString("value")));

    final Control c = new Control("1.3.6.1.4.1.30221.2.5.56", false,
         new ASN1OctetString(valueSequence.encode()));
    new OverrideSearchLimitsRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains a property with an empty value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlEmptyPropertyValue()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1OctetString("name"),
              new ASN1OctetString("")));

    final Control c = new Control("1.3.6.1.4.1.30221.2.5.56", false,
         new ASN1OctetString(valueSequence.encode()));
    new OverrideSearchLimitsRequestControl(c);
  }



  /**
   * Tests the behavior when trying to decode a control whose value sequence
   * contains multiple properties with the same name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlDuplicatePropertyName()
         throws Exception
  {
    final ASN1Sequence valueSequence = new ASN1Sequence(
         new ASN1Sequence(
              new ASN1OctetString("name1"),
              new ASN1OctetString("value1")),
         new ASN1Sequence(
              new ASN1OctetString("name2"),
              new ASN1OctetString("value2")),
         new ASN1Sequence(
              new ASN1OctetString("name1"),
              new ASN1OctetString("value3")));

    final Control c = new Control("1.3.6.1.4.1.30221.2.5.56", false,
         new ASN1OctetString(valueSequence.encode()));
    new OverrideSearchLimitsRequestControl(c);
  }
}
