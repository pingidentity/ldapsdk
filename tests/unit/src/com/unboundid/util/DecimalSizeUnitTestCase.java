/*
 * Copyright 2023 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2023 Ping Identity Corporation
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
 * Copyright (C) 2023 Ping Identity Corporation
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
package com.unboundid.util;



import java.math.BigDecimal;
import java.math.BigInteger;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code DecimalSizeUnit} enum.
 */
public final class DecimalSizeUnitTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides basic test coverage for the various enum methods.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicEnumMethods()
         throws Exception
  {
    for (final DecimalSizeUnit unit : DecimalSizeUnit.values())
    {
      assertNotNull(unit.getSingularName());
      assertNotNull(unit.getPluralName());
      assertNotNull(unit.getAbbreviation());
      assertNotNull(unit.getNumBytesPerUnit());

      assertEquals(DecimalSizeUnit.forName(unit.name()), unit);
      assertEquals(DecimalSizeUnit.forName(unit.getSingularName()), unit);
      assertEquals(DecimalSizeUnit.forName(unit.getPluralName()), unit);
      assertEquals(DecimalSizeUnit.forName(unit.getAbbreviation()), unit);

      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toLowerCase(unit.name())), unit);
      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toLowerCase(unit.getSingularName())), unit);
      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toLowerCase(unit.getPluralName())), unit);
      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toLowerCase(unit.getAbbreviation())), unit);

      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toUpperCase(unit.name())), unit);
      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toUpperCase(unit.getSingularName())), unit);
      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toUpperCase(unit.getPluralName())), unit);
      assertEquals(DecimalSizeUnit.forName(
           StaticUtils.toUpperCase(unit.getAbbreviation())), unit);

      for (int i=1; i <= 999; i++)
      {
        final BigInteger numBytes = unit.getNumBytesPerUnit().multiply(
             BigInteger.valueOf(i));

        assertEquals(DecimalSizeUnit.bytesToHumanReadableSize(numBytes),
             i + unit.getAbbreviation());

        assertEquals(unit.toBytes(i), numBytes);
        assertEquals(unit.toBytes(i * 1.0d), numBytes);

        assertEquals(unit.fromBytes(numBytes), BigDecimal.valueOf(i));
        if (canRepresentAsLong(numBytes))
        {
          assertEquals(unit.fromBytes(numBytes.longValue()),
               BigDecimal.valueOf(i));
        }
      }
    }
  }



  /**
   * Ensures that the {@code forName} method returns {@code null} for an
   * invalid or unrecognized name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testForNameInvalid()
         throws Exception
  {
    assertNull(DecimalSizeUnit.forName("invalid"));
  }



  /**
   * Ensures that the {@code bytesToHumanReadableSize} method yields the
   * expected output for the given value.
   *
   * @param  numBytes
   *              The number of bytes to provide as an argument to the
   *              {@code bytesToHumanReadableSize} method.
   * @param  expectedStringRepresentation
   *              The expected string representation for the provided value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "BytesToHumanReadableSizeTestData")
  public void testBytesToHumanReadableSize(final BigInteger numBytes,
                   final String expectedStringRepresentation)
         throws Exception
  {
    assertEquals(DecimalSizeUnit.bytesToHumanReadableSize(numBytes),
         expectedStringRepresentation);

    if (canRepresentAsLong(numBytes))
    {
      assertEquals(
           DecimalSizeUnit.bytesToHumanReadableSize(numBytes.longValue()),
           expectedStringRepresentation);
    }
  }



  /**
   * Retrieves data that may be used for testing the
   * {@code bytesToHumanReadableDuration} method.
   *
   * @return  Data that may be used for testing the
   *          {@code bytesToHumanReadableDuration} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name = "BytesToHumanReadableSizeTestData")
  public Object[][] getBytesToHumanReadableSizeTestData()
         throws Exception
  {
    return new Object[][]
    {
      new Object[]
      {
        BigInteger.valueOf(0L),
        "0B"
      },
      new Object[]
      {
        BigInteger.valueOf(1L),
        "1B"
      },
      new Object[]
      {
        BigInteger.valueOf(12L),
        "12B"
      },
      new Object[]
      {
        BigInteger.valueOf(123L),
        "123B"
      },
      new Object[]
      {
        BigInteger.valueOf(1000L),
        "1KB"
      },
      new Object[]
      {
        BigInteger.valueOf(1234L),
        "1.23KB"
      },
      new Object[]
      {
        BigInteger.valueOf(2000L),
        "2KB"
      },
      new Object[]
      {
        BigInteger.valueOf(12345L),
        "12.35KB"
      },
      new Object[]
      {
        BigInteger.valueOf(123456L),
        "123.46KB"
      },
      new Object[]
      {
        BigInteger.valueOf(1000000L),
        "1MB"
      },
      new Object[]
      {
        BigInteger.valueOf(1234567L),
        "1.23MB"
      },
      new Object[]
      {
        BigInteger.valueOf(6000000L),
        "6MB"
      },
      new Object[]
      {
        BigInteger.valueOf(12345678L),
        "12.35MB"
      },
      new Object[]
      {
        BigInteger.valueOf(123456789L),
        "123.46MB"
      },
      new Object[]
      {
        BigInteger.valueOf(1000000000L),
        "1GB"
      },
      new Object[]
      {
        BigInteger.valueOf(1234567890L),
        "1.23GB"
      },
      new Object[]
      {
        BigInteger.valueOf(10000000000L),
        "10GB"
      },
      new Object[]
      {
        BigInteger.valueOf(53000000000L),
        "53GB"
      },
      new Object[]
      {
        BigInteger.valueOf(123456789012L),
        "123.46GB"
      },
      new Object[]
      {
        BigInteger.valueOf(1000000000000L),
        "1TB"
      },
      new Object[]
      {
        BigInteger.valueOf(1234567890123L),
        "1.23TB"
      },
      new Object[]
      {
        BigInteger.valueOf(12345678901234L),
        "12.35TB"
      },
    };
  }



  /**
   * Indicates whether the provided {@code BigInteger} value can be represented
   * as a {@code long}.
   *
   * @param  value  The value for which to make the determination.
   *
   * @return  {@code true} if the provided value can be represented as a
   *          {@code long}, or {@code false} if not.
   */
  private static boolean canRepresentAsLong(final BigInteger value)
  {
    return value.equals(BigInteger.valueOf(value.longValue()));
  }
}
