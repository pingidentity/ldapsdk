/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.util.json;



import java.math.BigDecimal;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code JSONNumber} class.
 */
public final class JSONNumberTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for an integer value of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testZeroInteger()
         throws Exception
  {
    final JSONNumber n = new JSONNumber(0);

    assertEquals(n.getValue().compareTo(new BigDecimal(0)), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), "0");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "0");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "0");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "0");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "0");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "0");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(true, true, true), "0");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(false, false, false), "0");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "0");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "0");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "0");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":0");
  }



  /**
   * Tests the behavior for a positive integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPositiveInteger()
         throws Exception
  {
    final JSONNumber n = new JSONNumber(12345);

    assertEquals(n.getValue().compareTo(new BigDecimal(12345)), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), "12345");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "12345");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "12345");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "12345");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "12345");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "12345");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(true, true, true), "12345");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(false, false, false), "12345");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "12345");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "12345");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "12345");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":12345");
  }



  /**
   * Tests the behavior for a negative integer.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNegativeInteger()
         throws Exception
  {
    final JSONNumber n = new JSONNumber(-54321);

    assertEquals(n.getValue().compareTo(new BigDecimal(-54321)), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), "-54321");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "-54321");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "-54321");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "-54321");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "-54321");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "-54321");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(true, true, true), "-54321");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(false, false, false), "-54321");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "-54321");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "-54321");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "-54321");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":-54321");
  }



  /**
   * Tests the behavior for a floating-point value of zero.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testZeroFloatingPoint()
         throws Exception
  {
    final JSONNumber n = new JSONNumber(0.0);

    assertEquals(n.getValue().compareTo(new BigDecimal(0)), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), "0.0");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "0.0");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "0.0");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "0.0");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "0");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "0");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(true, true, true), "0");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(false, false, false), "0");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "0");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "0");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "0.0");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":0.0");
  }



  /**
   * Tests the behavior for a positive floating-point value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPositiveFloatingPoint()
         throws Exception
  {
    final JSONNumber n = new JSONNumber(1234.5);

    assertEquals(n.getValue().compareTo(new BigDecimal(1234.5)), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), "1234.5");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "1234.5");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "1234.5");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "1234.5");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "1234.5");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "1234.5");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(true, true, true), "1234.5");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(false, false, false), "1234.5");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "1234.5");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "1234.5");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "1234.5");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":1234.5");
  }



  /**
   * Tests the behavior for a negative floating-point value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNegativeFloatingPoint()
         throws Exception
  {
    final JSONNumber n = new JSONNumber(-9876.5);

    assertEquals(n.getValue().compareTo(new BigDecimal(-9876.5)), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), "-9876.5");

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), "-9876.5");

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), "-9876.5");

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), "-9876.5");

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), "-9876.5");

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), "-9876.5");

    assertNotNull(n.toNormalizedString(true, true, true));
    assertEquals(n.toNormalizedString(), "-9876.5");

    assertNotNull(n.toNormalizedString(false, false, false));
    assertEquals(n.toNormalizedString(), "-9876.5");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, true, true, true);
    assertEquals(toNormalizedStringBuffer.toString(), "-9876.5");

    toNormalizedStringBuffer.setLength(0);
    n.toNormalizedString(toNormalizedStringBuffer, false, false, false);
    assertEquals(toNormalizedStringBuffer.toString(), "-9876.5");

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), "-9876.5");

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(), "\"fieldName\":-9876.5");
  }



  /**
   * Tests the behavior for JSON numbers created from a {@code BigDecimal}
   * object.
   *
   * @param  stringRepresentation  The string representation of the value.
   * @param  bdValue               The {@code BigDecimal} equivalent of the
   *                               value.
   * @param  normalizedString      The normalized string representation for the
   *                               value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validNumberStrings")
  public void testNumberFromBigDecimal(final String stringRepresentation,
                                       final BigDecimal bdValue,
                                       final String normalizedString)
         throws Exception
  {
    final JSONNumber n = new JSONNumber(bdValue);

    assertEquals(n.getValue().compareTo(bdValue), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), normalizedString);

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), normalizedString);

    final StringBuilder toStringBuffer = new StringBuilder();
    n.toString(toStringBuffer);
    assertEquals(toStringBuffer.toString(), normalizedString);

    final StringBuilder toSingleLineStringBuffer = new StringBuilder();
    n.toSingleLineString(toSingleLineStringBuffer);
    assertEquals(toSingleLineStringBuffer.toString(), normalizedString);

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), normalizedString);

    final StringBuilder toNormalizedStringBuffer = new StringBuilder();
    n.toNormalizedString(toNormalizedStringBuffer);
    assertEquals(toNormalizedStringBuffer.toString(), normalizedString);

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), normalizedString);

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"fieldName\":" + normalizedString);
  }



  /**
   * Tests the behavior for JSON numbers created from a string representation.
   *
   * @param  stringRepresentation  The string representation of the value.
   * @param  bdValue               The {@code BigDecimal} equivalent of the
   *                               value.
   * @param  normalizedString      The normalized string representation for the
   *                               value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validNumberStrings")
  public void testNumberFromString(final String stringRepresentation,
                                   final BigDecimal bdValue,
                                   final String normalizedString)
         throws Exception
  {
    final JSONNumber n = new JSONNumber(stringRepresentation);

    assertEquals(n.getValue().compareTo(bdValue), 0);

    assertNotNull(n.toString());
    assertEquals(n.toString(), stringRepresentation);

    assertNotNull(n.toSingleLineString());
    assertEquals(n.toSingleLineString(), stringRepresentation);

    StringBuilder buffer = new StringBuilder();
    n.toString(buffer);
    assertEquals(buffer.toString(), stringRepresentation);

    buffer = new StringBuilder();
    n.toSingleLineString(buffer);
    assertEquals(buffer.toString(), stringRepresentation);

    assertNotNull(n.toNormalizedString());
    assertEquals(n.toNormalizedString(), normalizedString);

    buffer = new StringBuilder();
    n.toNormalizedString(buffer);
    assertEquals(buffer.toString(), normalizedString);

    final JSONBuffer jsonBuffer = new JSONBuffer();
    n.appendToJSONBuffer(jsonBuffer);
    assertEquals(jsonBuffer.toString(), stringRepresentation);

    jsonBuffer.clear();
    n.appendToJSONBuffer("fieldName", jsonBuffer);
    assertEquals(jsonBuffer.toString(),
         "\"fieldName\":" + stringRepresentation);
  }



  /**
   * Tests the behavior of the equals method.
   *
   * Tests the behavior for JSON numbers created from a string representation.
   *
   * @param  stringRepresentation  The string representation of the value.
   * @param  bdValue               The {@code BigDecimal} equivalent of the
   *                               value.
   * @param  normalizedString      The normalized string representation for the
   *                               value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validNumberStrings")
  public void testEquals(final String stringRepresentation,
                         final BigDecimal bdValue,
                         final String normalizedString)
         throws Exception
  {
    final JSONNumber n1 = new JSONNumber(stringRepresentation);
    assertTrue(n1.equals(n1));
    assertEquals(n1.hashCode(), n1.hashCode());


    final JSONNumber n2 = new JSONNumber(bdValue);
    assertTrue(n2.equals(n2));
    assertEquals(n2.hashCode(), n2.hashCode());

    assertTrue(n1.equals(n2));
    assertTrue(n2.equals(n1));
    assertEquals(n1.hashCode(), n2.hashCode());


    final JSONNumber n3 = new JSONNumber(normalizedString);
    assertTrue(n3.equals(n3));
    assertEquals(n3.hashCode(), n3.hashCode());

    assertTrue(n1.equals(n3));
    assertTrue(n3.equals(n1));
    assertEquals(n1.hashCode(), n3.hashCode());

    assertTrue(n2.equals(n3));
    assertTrue(n3.equals(n2));
    assertEquals(n2.hashCode(), n3.hashCode());
  }



  /**
   * Tests the additional behavior for the equals method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMoreEquals()
         throws Exception
  {
    final JSONNumber n1 = new JSONNumber(1234);
    final JSONNumber n2 = new JSONNumber(5678);
    assertFalse(n1.equals(n2));
    assertFalse(n2.equals(n1));

    assertFalse(n1.equals(null));

    assertFalse(n1.equals("1234"));
  }



  /**
   * Tests a number of strings that should not be parsable as JSON numbers.
   *
   * @param  invalidString  The string that should not be parsable as a JSON
   *                        number.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidNumberStrings",
        expectedExceptions = { JSONException.class})
  public void testNumberParseFailure(final String invalidString)
         throws Exception
  {
    new JSONNumber(invalidString);
  }



  /**
   * Retrieves a set of valid strings that can be parsed as JSON numbers.
   * Each element of the array should itself be an array consisting of the
   * following elements:
   * <OL>
   *   <LI>The JSON string to process as a number</LI>
   *   <LI>The BigDecimal value that corresponds to the number contained in the
   *       string</LI>
   *   <LI>The normalized string representation for the number</LI>
   * </OL>
   *
   * @return  A set of valid strings that can be parsed as JSON numbers.
   */
  @DataProvider(name="validNumberStrings")
  public Object[][] getValidNumberStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        "0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0.0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0e0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0e+0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0e-0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0E0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0.0e0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "0.0E0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0.0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0e0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0e+0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0e-0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0E0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0.0e0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "-0.0E0",
        new BigDecimal(0),
        "0"
      },

      new Object[]
      {
        "1234",
        new BigDecimal(1234),
        "1234"
      },

      new Object[]
      {
        "1.234e3",
        new BigDecimal(1234),
        "1234"
      },

      new Object[]
      {
        "12.34e+2",
        new BigDecimal(1234),
        "1234"
      },

      new Object[]
      {
        "-123.4e1",
        new BigDecimal(-1234),
        "-1234"
      },

      new Object[]
      {
        "1234e0",
        new BigDecimal(1234),
        "1234"
      },

      new Object[]
      {
        "12340e-1",
        new BigDecimal(1234),
        "1234"
      },

      new Object[]
      {
        "1234.5",
        new BigDecimal(1234.5),
        "1234.5"
      },

      new Object[]
      {
        "1234.500",
        new BigDecimal(1234.5),
        "1234.5"
      },

      new Object[]
      {
        "1234.5E0",
        new BigDecimal(1234.5),
        "1234.5"
      },

      new Object[]
      {
        "123.45E+1",
        new BigDecimal(1234.5),
        "1234.5"
      }
    };
  }



  /**
   * Retrieves a set of strings that cannot be parsed as JSON numbers.  Each
   * element of the array will be a single-element array with the invalid string
   * representation.
   *
   * @return  A set of strings that cannot be parsed as JSON numbers.
   */
  @DataProvider(name="invalidNumberStrings")
  public Object[][] getInvalidNumberStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "invalid"
      },

      new Object[]
      {
        "01"
      },

      new Object[]
      {
        "-01"
      },

      new Object[]
      {
        "-a1"
      },

      new Object[]
      {
        "1x2"
      },

      new Object[]
      {
        "1."
      },

      new Object[]
      {
        "1.a234"
      },

      new Object[]
      {
        "1.2.3.4"
      },

      new Object[]
      {
        "e0"
      },

      new Object[]
      {
        "1e"
      },

      new Object[]
      {
        "1e2e3"
      },

      new Object[]
      {
        "1e2.3"
      },

      new Object[]
      {
        "1ea23"
      },

      new Object[]
      {
        "1e+a23"
      },

      new Object[]
      {
        "1e-a23"
      }
    };
  }



  /**
   * Tests the {@code equals} method that takes an extended set of arguments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEqualsExtended()
         throws Exception
  {
    final JSONNumber n1 = new JSONNumber(0);
    final JSONNumber n2 = new JSONNumber(0);
    final JSONNumber n3 = new JSONNumber(1);

    assertTrue(n1.equals(n1, true, true, true));
    assertTrue(n1.equals(n1, false, false, false));

    assertTrue(n1.equals(n2, true, true, true));
    assertTrue(n1.equals(n2, false, false, false));

    assertFalse(n1.equals(n3, true, true, true));
    assertFalse(n1.equals(n3, false, false, false));
  }
}
