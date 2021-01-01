/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.util.args;



import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the timestamp argument.
 */
public final class TimestampArgumentTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the minimal constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructor()
         throws Exception
  {
    TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");

    a = a.getCleanCopy();

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('t'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "longID");

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());
    assertNull(a.getStringValue());

    assertNotNull(a.getValueStringRepresentations(true));
    assertTrue(a.getValueStringRepresentations(true).isEmpty());

    a.addValue("20160101123456.789Z");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         StaticUtils.decodeGeneralizedTime("20160101123456.789Z"));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertNotNull(a.getStringValue());
    assertEquals(a.getStringValue(), "20160101123456.789Z");

    assertNotNull(a.getValueStringRepresentations(true));
    assertEquals(a.getValueStringRepresentations(true).size(), 1);

    assertFalse(a.hasDefaultValue());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the non-minimal constructor that doesn't allow choosing a default.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonMinimalConstructorNoDefault()
         throws Exception
  {
    TimestampArgument a = new TimestampArgument('t', "longID", false, 1,
         "{placeholder}", "the description");

    a = a.getCleanCopy();

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('t'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "longID");

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());
    assertNull(a.getStringValue());

    assertNotNull(a.getValueStringRepresentations(true));
    assertTrue(a.getValueStringRepresentations(true).isEmpty());

    a.addValue("20160101123456.789Z");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         StaticUtils.decodeGeneralizedTime("20160101123456.789Z"));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertNotNull(a.getStringValue());
    assertEquals(a.getStringValue(), "20160101123456.789Z");

    assertNotNull(a.getValueStringRepresentations(true));
    assertEquals(a.getValueStringRepresentations(true).size(), 1);

    assertFalse(a.hasDefaultValue());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the non-minimal constructor that allows a single default value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonMinimalConstructorSingleDefault()
         throws Exception
  {
    TimestampArgument a = new TimestampArgument('t', "longID", false, 1,
         "{placeholder}", "the description", new Date());

    a = a.getCleanCopy();

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('t'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "longID");

    assertNotNull(a.getDefaultValues());

    assertNotNull(a.getValue());
    assertNotNull(a.getStringValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertNotNull(a.getValueStringRepresentations(true));
    assertEquals(a.getValueStringRepresentations(true).size(), 1);

    a.addValue("20160101123456.789Z");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         StaticUtils.decodeGeneralizedTime("20160101123456.789Z"));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertNotNull(a.getStringValue());
    assertEquals(a.getStringValue(), "20160101123456.789Z");

    assertNotNull(a.getValueStringRepresentations(true));
    assertEquals(a.getValueStringRepresentations(true).size(), 1);

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Tests the non-minimal constructor that allows multiple default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNonMinimalConstructorMultipleDefaults()
         throws Exception
  {
    TimestampArgument a = new TimestampArgument('t', "longID", false, 0,
         "{placeholder}", "the description",
         Arrays.asList(
              StaticUtils.decodeGeneralizedTime("20160101123456.789Z"),
              StaticUtils.decodeGeneralizedTime("20160101123456.790Z")));

    a = a.getCleanCopy();

    assertNotNull(a.getShortIdentifier());
    assertEquals(a.getShortIdentifier(), Character.valueOf('t'));

    assertNotNull(a.getLongIdentifier());
    assertEquals(a.getLongIdentifier(), "longID");

    assertNotNull(a.getDefaultValues());

    assertNotNull(a.getValue());
    assertNotNull(a.getStringValue());

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 2);

    assertNotNull(a.getValueStringRepresentations(true));
    assertEquals(a.getValueStringRepresentations(true).size(), 2);

    a.addValue("20160101123456.789Z");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(),
         StaticUtils.decodeGeneralizedTime("20160101123456.789Z"));

    assertNotNull(a.getValues());
    assertEquals(a.getValues().size(), 1);

    assertNotNull(a.getStringValue());
    assertEquals(a.getStringValue(), "20160101123456.789Z");

    assertNotNull(a.getValueStringRepresentations(true));
    assertEquals(a.getValueStringRepresentations(true).size(), 1);

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDataTypeName());

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());
  }



  /**
   * Provides coverage for the {@code parseTimestamp} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseTimestamp()
         throws Exception
  {
    assertNotNull(TimestampArgument.parseTimestamp("20160101123456.789Z"));
    assertNotNull(TimestampArgument.parseTimestamp("20160101123456Z"));
    assertNotNull(TimestampArgument.parseTimestamp("201601011234Z"));
    assertNotNull(TimestampArgument.parseTimestamp("2016010112Z"));

    assertNotNull(TimestampArgument.parseTimestamp("20160101123456.789"));
    assertNotNull(TimestampArgument.parseTimestamp("20160101123456"));
    assertNotNull(TimestampArgument.parseTimestamp("201601011234"));

    for (final String s :
         Arrays.asList("invalid1123456.789", "invalid1123456", "invalid11234",
              "invalid"))
    {
      try
      {
        TimestampArgument.parseTimestamp(s);
        fail("No exception when trying to parse invalid timestamp "+ s);
      }
      catch (final ParseException pe)
      {
        // This was expected
      }
    }
  }



  /**
   * Tests the behavior when trying to add a value that is malformed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueMalformed()
         throws Exception
  {
    final TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");

    a.addValue("invalid");
  }



  /**
   * Tests the behavior when trying to add a value when the argument already has
   * the maximum number of allowed values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testAddValueTooManyValues()
         throws Exception
  {
    final TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");

    a.addValue("20160101123456.789Z");
    a.addValue("20160101123456.790Z");
  }



  /**
   * Tests the behavior when the argument is configured with a timestamp range
   * validator and the provided value is acceptable.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidatorValueAcceptable()
         throws Exception
  {
    final TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");

    final TimestampRangeArgumentValueValidator v =
         new TimestampRangeArgumentValueValidator(
              StaticUtils.decodeGeneralizedTime("20150101123456.789Z"),
              StaticUtils.decodeGeneralizedTime("20170101123456.789Z"));
    a.addValueValidator(v);

    assertNotNull(v.getOldestAllowedDate());
    assertEquals(v.getOldestAllowedDate(),
         StaticUtils.decodeGeneralizedTime("20150101123456.789Z"));

    assertNotNull(v.getMostRecentAllowedDate());
    assertEquals(v.getMostRecentAllowedDate(),
         StaticUtils.decodeGeneralizedTime("20170101123456.789Z"));

    assertNotNull(v.toString());

    a.addValue("20160101123456.789Z");
  }



  /**
   * Tests the behavior when the argument is configured with a timestamp range
   * validator and the provided value is too old.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testValidatorValueTooOld()
         throws Exception
  {
    final TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");

    final TimestampRangeArgumentValueValidator v =
         new TimestampRangeArgumentValueValidator(
              StaticUtils.decodeGeneralizedTime("20150101123456.789Z"),
              null);
    a.addValueValidator(v);

    assertNotNull(v.getOldestAllowedDate());
    assertEquals(v.getOldestAllowedDate(),
         StaticUtils.decodeGeneralizedTime("20150101123456.789Z"));

    assertNull(v.getMostRecentAllowedDate());

    assertNotNull(v.toString());

    a.addValue("20140101123456.789Z");
  }



  /**
   * Tests the behavior when the argument is configured with a timestamp range
   * validator and the provided value is too new.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { ArgumentException.class })
  public void testValidatorValueTooNew()
         throws Exception
  {
    final TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");

    final TimestampRangeArgumentValueValidator v =
         new TimestampRangeArgumentValueValidator(null,
              StaticUtils.decodeGeneralizedTime("20150101123456.789Z"));
    a.addValueValidator(v);

    assertNull(v.getOldestAllowedDate());

    assertNotNull(v.getMostRecentAllowedDate());
    assertEquals(v.getMostRecentAllowedDate(),
         StaticUtils.decodeGeneralizedTime("20150101123456.789Z"));

    assertNotNull(v.toString());

    a.addValue("20160101123456.789Z");
  }



  /**
   * Tests the behavior of the {@code addToCommandLine} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddToCommandLine()
         throws Exception
  {
    final TimestampArgument a = new TimestampArgument('t', "longID",
         "the description");
    a.addValue("20160101123456.789Z");

    final ArrayList<String> argStrings = new ArrayList<String>(2);

    a.addToCommandLine(argStrings);
    assertEquals(argStrings,
         Arrays.asList("--longID", "20160101123456.789Z"));

    argStrings.clear();
    a.setSensitive(true);

    a.addToCommandLine(argStrings);
    assertEquals(argStrings,
         Arrays.asList("--longID", "***REDACTED***"));
  }
}
