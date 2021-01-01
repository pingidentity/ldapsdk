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
package com.unboundid.util.args;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.controls.AuthorizationIdentityRequestControl;
import com.unboundid.util.Base64;



/**
 * This class provides a set of test cases for the control argument.
 */
public final class ControlArgumentTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the minimal constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMinimalConstructor()
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control",
         "The description for the control");
    a = a.getCleanCopy();

    assertNotNull(a.getValuePlaceholder());

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertTrue(a.getValues().isEmpty());

    assertNotNull(a.getDataTypeName());
    assertEquals(a.getDataTypeName(), "Control");

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    a.addValue("1.2.3.4");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("1.2.3.4", false, null));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(),
         Collections.singletonList(new Control("1.2.3.4", false, null)));

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNotNull(a.toString());

    final ArgumentParser newParser = new ArgumentParser("test", "test");
    newParser.addArgument(a);
    assertNotNull(newParser.getControlArgument(a.getIdentifierString()));

    assertNull(newParser.getControlArgument("--noSuchArgument"));
  }



  /**
   * Tests the behavior of the argument with a single value and no default.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleValueWithoutDefault()
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control", false, 1, null,
         "The description for the control");
    a = a.getCleanCopy();

    assertNotNull(a.getValuePlaceholder());

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNull(a.getValue());

    assertNotNull(a.getValues());
    assertTrue(a.getValues().isEmpty());

    assertNotNull(a.getDataTypeName());
    assertEquals(a.getDataTypeName(), "Control");

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    a.addValue("1.2.3.4");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("1.2.3.4", false, null));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(),
         Collections.singletonList(new Control("1.2.3.4", false, null)));

    assertFalse(a.hasDefaultValue());

    assertNull(a.getDefaultValues());

    assertNotNull(a.toString());

    try
    {
      a.addValue("1.2.3.5");
      fail("Expected an exception when adding a second value");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the argument with a single value and a single default
   * value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSingleValueWithSingleDefault()
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control", false, 1, null,
         "The description for the control", new Control("1.2.3.4"));
    a = a.getCleanCopy();

    assertNotNull(a.getValuePlaceholder());

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues(),
         Collections.singletonList(new Control("1.2.3.4")));

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("1.2.3.4"));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(),
         Collections.singletonList(new Control("1.2.3.4")));

    assertNotNull(a.getDataTypeName());
    assertEquals(a.getDataTypeName(), "Control");

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    a.addValue("1.2.3.5");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("1.2.3.5", false, null));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(),
         Collections.singletonList(new Control("1.2.3.5", false, null)));

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues(),
         Collections.singletonList(new Control("1.2.3.4")));

    assertNotNull(a.toString());

    try
    {
      a.addValue("1.2.3.6");
      fail("Expected an exception when adding a second value");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }
  }



  /**
   * Tests the behavior of the argument with multiple values and a set of
   * default values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMultipleValuesWithMultipleDefaults()
         throws Exception
  {
    final List<Control> defaultValues = Arrays.asList(
         new Control("1.2.3.4"),
         new Control("1.2.3.5", true, new ASN1OctetString("foo")));

    ControlArgument a = new ControlArgument('J', "control", false, 0, null,
         "The description for the control", defaultValues);
    a = a.getCleanCopy();

    assertNotNull(a.getValuePlaceholder());

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues(), defaultValues);

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("1.2.3.4"));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(), defaultValues);

    assertNotNull(a.getDataTypeName());
    assertEquals(a.getDataTypeName(), "Control");

    assertNotNull(a.getValueConstraints());

    assertNotNull(a.toString());

    a.addValue("5.6.7.8");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("5.6.7.8", false, null));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(),
         Collections.singletonList(new Control("5.6.7.8", false, null)));

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues(), defaultValues);

    assertNotNull(a.toString());

    a.addValue("5.6.7.9:true:bar");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("5.6.7.8", false, null));

    assertNotNull(a.getValues());
    assertEquals(a.getValues(),
         Arrays.asList(
              new Control("5.6.7.8", false, null),
              new Control("5.6.7.9", true, new ASN1OctetString("bar"))));

    assertTrue(a.hasDefaultValue());

    assertNotNull(a.getDefaultValues());
    assertEquals(a.getDefaultValues(), defaultValues);

    assertNotNull(a.toString());
  }



  /**
   * Tests the behavior when creating an argument with an explicit placeholder.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateWithPlaceholder()
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control", false, 1,
         "this is the placeholder", "The description for the control");

    assertNotNull(a.getValuePlaceholder());
    assertEquals(a.getValuePlaceholder(), "this is the placeholder");
  }



  /**
   * Tests the argument's behavior with an argument value validator.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testWithArgumentValueValidator()
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control", false, 1,
         "{oid}[:{criticality}[:{stringValue}|::{base64Value}]]",
         "The description for the control");
    a.addValueValidator(new TestArgumentValueValidator("1.2.3.4:false:"));

    assertNull(a.getValue());

    try
    {
      a.addValue("1.2.3.4");
      fail("Expected an exception from an argument value validator.");
    }
    catch (final ArgumentException ae)
    {
      // This was expected
    }

    assertNull(a.getValue());

    a.addValue("1.2.3.4:false:");

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), new Control("1.2.3.4", false,
         new ASN1OctetString()));
  }



  /**
   * Tests to ensure that the provided string can be decoded as the expected
   * control.
   *
   * @param  s  The string to be decoded.
   * @param  c  The control expected to match the provided value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="validControlStrings")
  public void testValidValues(final String s, final Control c)
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control", false, 1,
         "{oid}[:{criticality}[:{stringValue}|::{base64Value}]]",
         "The description for the control");
    a = a.getCleanCopy();

    a.addValue(s);

    assertNotNull(a.getValue());
    assertEquals(a.getValue(), c);
  }



  /**
   * Tests to ensure that a number of invalid strings are properly rejected.
   *
   * @param  s  The string to be examined.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="invalidControlStrings")
  public void testInvalidValues(final String s)
         throws Exception
  {
    ControlArgument a = new ControlArgument('J', "control", false, 1,
         "{oid}[:{criticality}[:{stringValue}|::{base64Value}]]",
         "The description for the control");
    a = a.getCleanCopy();

    try
    {
      a.addValue(s);
      fail("Expected an exception when trying to parse an invalid value");
    }
    catch (final ArgumentException ae)
    {
      // This was expected.
    }
  }



  /**
   * Retrieves a set of valid strings that can be used to create controls.
   *
   * @return  A set of valid strings that can be used to create controls.
   */
  @DataProvider(name="validControlStrings")
  public Object[][] getValidControlStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        "1.2.3.4",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "authzid",
        new Control(
             AuthorizationIdentityRequestControl.
                  AUTHORIZATION_IDENTITY_REQUEST_OID,
             false, null)
      },

      new Object[]
      {
        "1.2.3.4:true",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "authzid:true",
        new Control(
             AuthorizationIdentityRequestControl.
                  AUTHORIZATION_IDENTITY_REQUEST_OID,
             true, null)
      },

      new Object[]
      {
        "1.2.3.4:TRUE",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:t",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:T",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:yes",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:YES",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:y",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:Y",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:on",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:ON",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:1",
        new Control("1.2.3.4", true, null)
      },

      new Object[]
      {
        "1.2.3.4:false",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:FALSE",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:f",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:F",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:no",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:NO",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:n",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:N",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:off",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:OFF",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:0",
        new Control("1.2.3.4", false, null)
      },

      new Object[]
      {
        "1.2.3.4:true:",
        new Control("1.2.3.4", true, new ASN1OctetString())
      },

      new Object[]
      {
        "1.2.3.4:true::",
        new Control("1.2.3.4", true, new ASN1OctetString())
      },

      new Object[]
      {
        "1.2.3.4:t:",
        new Control("1.2.3.4", true, new ASN1OctetString())
      },

      new Object[]
      {
        "1.2.3.4:t::",
        new Control("1.2.3.4", true, new ASN1OctetString())
      },

      new Object[]
      {
        "1.2.3.4:true:a",
        new Control("1.2.3.4", true, new ASN1OctetString("a"))
      },

      new Object[]
      {
        "1.2.3.4:true::" + Base64.encode("a"),
        new Control("1.2.3.4", true, new ASN1OctetString("a"))
      },

      new Object[]
      {
        "1.2.3.4:t:a",
        new Control("1.2.3.4", true, new ASN1OctetString("a"))
      },

      new Object[]
      {
        "1.2.3.4:t::" + Base64.encode("a"),
        new Control("1.2.3.4", true, new ASN1OctetString("a"))
      }
    };
  }



  /**
   * Retrieves a set of invalid strings that cannot be used to create controls.
   *
   * @return  A set of invalid strings that cannot be used to create controls.
   */
  @DataProvider(name="invalidControlStrings")
  public Object[][] getInvalidControlStrings()
  {
    return new Object[][]
    {
      new Object[]
      {
        ""
      },

      new Object[]
      {
        "not-a-valid-oid"
      },

      new Object[]
      {
        ":true",
      },

      new Object[]
      {
        "1.2.3.4:not-a-valid-criticality",
      },

      new Object[]
      {
        "1.2.3.4::empty-criticality",
      },

      new Object[]
      {
        "1.2.3.4:false::not-a-valid-base64-string",
      }
    };
  }
}
