/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the PasswordPolicyStateOperation
 * class.
 */
public class PasswordPolicyStateOperationTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         new PasswordPolicyStateOperation(0);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 0);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the second constructor with a null set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Null()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         new PasswordPolicyStateOperation(0, null);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 0);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the second constructor with an empty set of values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Empty()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         new PasswordPolicyStateOperation(0, new ASN1OctetString[0]);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 0);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the second constructor with a single value that can be parsed as an
   * integer but not a boolean or generalized timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2SingleValue()
         throws Exception
  {
    ASN1OctetString[] values =
    {
      new ASN1OctetString("12345")
    };

    PasswordPolicyStateOperation op =
         new PasswordPolicyStateOperation(0, values);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 0);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "12345");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    assertEquals(op.getIntValue(), 12345);

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the second constructor with a multiple values that cannot be parsed
   * as booleans, integers, or generalized timestamps.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2MultipleValues()
         throws Exception
  {
    ASN1OctetString[] values =
    {
      new ASN1OctetString("the first string"),
      new ASN1OctetString("the second string")
    };

    PasswordPolicyStateOperation op =
         new PasswordPolicyStateOperation(0, values);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 0);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 2);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "the first string");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 2);
    assertEquals(op.getStringValues()[1], "the second string");

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordPolicyDNOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordPolicyDNOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordPolicyDNOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 0);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountDisabledStateOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountDisabledStateOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetAccountDisabledStateOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 1);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAccountDisabledStateOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetAccountDisabledStateOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetAccountDisabledStateOperation(true);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 2);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertEquals(op.getStringValue(), "true");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    assertTrue(op.getBooleanValue());

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearAccountDisabledStateOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearAccountDisabledStateOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearAccountDisabledStateOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 3);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountActivationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountActivationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetAccountActivationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 45);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAccountActivationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetAccountActivationTimeOperation()
         throws Exception
  {
    Date d = new Date();

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetAccountActivationTimeOperation(d);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 46);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());
    assertEquals(op.getGeneralizedTimeValue(), d);

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearAccountActivationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearAccountActivationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearAccountActivationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 47);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilAccountActivationOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilAccountActivationOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilAccountActivationOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 48);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountExpirationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountExpirationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetAccountExpirationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 4);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAccountExpirationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetAccountExpirationTimeOperation()
         throws Exception
  {
    Date d = new Date();

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetAccountExpirationTimeOperation(d);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 5);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());
    assertEquals(op.getGeneralizedTimeValue(), d);

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearAccountExpirationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearAccountExpirationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearAccountExpirationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 6);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilAccountExpirationOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilAccountExpirationOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilAccountExpirationOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 7);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordChangedTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordChangedTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordChangedTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 8);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetPasswordChangedTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetPasswordChangedTimeOperation()
         throws Exception
  {
    Date d = new Date();

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createSetPasswordChangedTimeOperation(d);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 9);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());
    assertEquals(op.getGeneralizedTimeValue(), d);

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordChangedTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearPasswordChangedTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearPasswordChangedTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 10);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordExpirationWarnedTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordExpirationWarnedTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetPasswordExpirationWarnedTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 11);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetPasswordExpirationWarnedTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetPasswordExpirationWarnedTimeOperation()
         throws Exception
  {
    Date d = new Date();

    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createSetPasswordExpirationWarnedTimeOperation(d);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 12);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());
    assertEquals(op.getGeneralizedTimeValue(), d);

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordExpirationWarnedTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearPasswordExpirationWarnedTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearPasswordExpirationWarnedTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 13);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilPasswordExpirationOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilPasswordExpirationOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilPasswordExpirationOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 14);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilPasswordExpirationWarningOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilPasswordExpirationWarningOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilPasswordExpirationWarningOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 15);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAuthenticationFailureTimesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAuthenticationFailureTimesOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetAuthenticationFailureTimesOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 16);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddAuthenticationFailureTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddAuthenticationFailureTimeOperationNoValues()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createAddAuthenticationFailureTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 17);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddAuthenticationFailureTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddAuthenticationFailureTimeOperationOneValue()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createAddAuthenticationFailureTimeOperation(
                   new Date[] { new Date() });

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 17);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddAuthenticationFailureTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddAuthenticationFailureTimeOperationMultipleValues()
         throws Exception
  {
    final Date[] dates =
    {
      new Date(System.currentTimeMillis() - 1234L),
      new Date()
    };

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createAddAuthenticationFailureTimeOperation(dates);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 17);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 2);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 2);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 2);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAuthenticationFailureTimesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetAuthenticationFailureTimesOperation()
         throws Exception
  {
    Date d = new Date();
    Date[] failureTimes =
    {
      new Date(d.getTime() - 1000),
      d
    };

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetAuthenticationFailureTimesOperation(failureTimes);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 18);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 2);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 2);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 2);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAuthenticationFailureTimesOperation method using a
   * {@code null} argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetAuthenticationFailureTimesOperationNull()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetAuthenticationFailureTimesOperation(null);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 18);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAuthenticationFailureTimesOperation method using an
   * empty array argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetAuthenticationFailureTimesOperationEmpty()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetAuthenticationFailureTimesOperation(new Date[0]);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 18);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearAuthenticationFailureTimesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearAuthenticationFailureTimesOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearAuthenticationFailureTimesOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 19);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSecondsUntilAuthenticationFailureUnlockOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilAuthenticationFailureUnlockOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilAuthenticationFailureUnlockOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 20);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetRemainingAuthenticationFailureCountOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetRemainingAuthenticationFailureCountOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetRemainingAuthenticationFailureCountOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 21);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetLastLoginTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetLastLoginTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetLastLoginTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 22);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetLastLoginTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetLastLoginTimeOperation()
         throws Exception
  {
    Date d = new Date();

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createSetLastLoginTimeOperation(d);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 23);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());
    assertEquals(op.getGeneralizedTimeValue(), d);

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearLastLoginTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClearLastLoginTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearLastLoginTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 24);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilIdleLockoutOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilIdleLockoutOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilIdleLockoutOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 25);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetLastLoginIPAddressOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetLastLoginIPAddressOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetLastLoginIPAddressOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 49);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetLastLoginIPAddressOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetLastLoginIPAddressOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createSetLastLoginIPAddressOperation(
              "1.2.3.4");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 50);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "1.2.3.4");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearLastLoginIPAddressOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testClearLastLoginIPAddressOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearLastLoginIPAddressOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 51);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordResetStateOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordResetStateOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordResetStateOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 26);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetPasswordResetStateOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetPasswordResetStateOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetPasswordResetStateOperation(false);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 27);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "false");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    assertFalse(op.getBooleanValue());

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordResetStateOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearPasswordResetStateOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearPasswordResetStateOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 28);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilPasswordResetLockoutOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilPasswordResetLockoutOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilPasswordResetLockoutOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 29);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetGraceLoginUseTimesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetGraceLoginUseTimesOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetGraceLoginUseTimesOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 30);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddGraceLoginUseTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddGraceLoginUseTimeOperationNoValues()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createAddGraceLoginUseTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 31);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddGraceLoginUseTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddGraceLoginUseTimeOperationOneValue()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createAddGraceLoginUseTimeOperation(
              new Date[] { new Date() });

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 31);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddGraceLoginUseTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddGraceLoginUseTimeOperationMultipleValues()
         throws Exception
  {
    final Date[] dates =
    {
      new Date(System.currentTimeMillis() - 1234L),
      new Date()
    };

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createAddGraceLoginUseTimeOperation(
              dates);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 31);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 2);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 2);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 2);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetGraceLoginUseTimesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetGraceLoginUseTimesOperation()
         throws Exception
  {
    Date d = new Date();
    Date[] useTimes =
    {
      new Date(d.getTime() - 1000),
      d
    };

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetGraceLoginUseTimesOperation(useTimes);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 32);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 2);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 2);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 2);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetGraceLoginUseTimesOperation method using a {@code null}
   * argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetGraceLoginUseTimesOperationNull()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetGraceLoginUseTimesOperation(null);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 32);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetGraceLoginUseTimesOperation method using an empty array
   * argument.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testSetGraceLoginUseTimesOperationEmpty()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetGraceLoginUseTimesOperation(new Date[0]);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 32);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearGraceLoginUseTimesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearGraceLoginUseTimesOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearGraceLoginUseTimesOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 33);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetRemainingGraceLoginCountOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetRemainingGraceLoginCountOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetRemainingGraceLoginCountOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 34);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordChangedByRequiredTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordChangedByRequiredTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetPasswordChangedByRequiredTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 35);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetPasswordChangedByRequiredTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetPasswordChangedByRequiredTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetPasswordChangedByRequiredTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 36);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordChangedByRequiredTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearPasswordChangedByRequiredTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearPasswordChangedByRequiredTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 37);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsUntilRequiredChangeTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsUntilRequiredChangeTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsUntilRequiredChangeTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 38);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testCreateGetPasswordHistoryOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordHistoryOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 39);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearPasswordHistoryOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearPasswordHistoryOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 40);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateHasRetiredPasswordOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createHasRetiredPasswordOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 41);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordRetiredTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordRetiredTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 42);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetRetiredPasswordExpirationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetRetiredPasswordExpirationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 43);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearPasswordHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreatePurgeRetiredPasswordOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createPurgeRetiredPasswordOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 44);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountUsabilityNoticesOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountUsabilityNoticesOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetAccountUsabilityNoticesOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 52);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountUsabilityWarningsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountUsabilityWarningsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetAccountUsabilityWarningsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 53);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountUsabilityErrorsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountUsabilityErrorsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetAccountUsabilityErrorsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 54);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsUsableOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsUsableOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetAccountIsUsableOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 55);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsNotYetActiveOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsNotYetActiveOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetAccountIsNotYetActiveOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 56);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsExpiredOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsExpiredOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetAccountIsExpiredOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 57);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordExpirationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordExpirationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetPasswordExpirationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 58);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsFailureLockedOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsFailureLockedOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetAccountIsFailureLockedOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 59);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAccountIsFailureLockedOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetAccountIsFailureLockedOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createSetAccountIsFailureLockedOperation(false);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 60);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "false");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    assertFalse(op.getBooleanValue());

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetFailureLockoutTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetFailureLockoutTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetFailureLockoutTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 61);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsIdleLockedOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsIdleLockedOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetAccountIsIdleLockedOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 62);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetIdleLockoutTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetIdleLockoutTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetIdleLockoutTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 63);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsResetLockedOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsResetLockedOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetAccountIsResetLockedOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 64);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetResetLockoutTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetResetLockoutTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetResetLockoutTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 65);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordHistoryCountOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordHistoryCountOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordHistoryCountOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 66);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetPasswordIsExpiredOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetPasswordIsExpiredOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetPasswordIsExpiredOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 67);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAvailableSASLMechanismsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAvailableSASLMechanismsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetAvailableSASLMechanismsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 68);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAvailableOTPDeliveryMechanismsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAvailableOTPDeliveryMechanismsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetAvailableOTPDeliveryMechanismsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 69);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createHasTOTPSharedSecret method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  @SuppressWarnings("deprecation")
  public void testCreateHasTOTPSharedSecret()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createHasTOTPSharedSecret();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 70);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createHasTOTPSharedSecretOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateHasTOTPSharedSecretOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createHasTOTPSharedSecretOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 70);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetRegisteredYubiKeyPublicIDsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetRegisteredYubiKeyPublicIDsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetRegisteredYubiKeyPublicIDsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 71);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddRegisteredYubiKeyPublicIDOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddRegisteredYubiKeyPublicIDOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createAddRegisteredYubiKeyPublicIDOperation("abcdefg");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 72);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "abcdefg");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createRemoveRegisteredYubiKeyPublicIDOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateRemoveRegisteredYubiKeyPublicIDOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createRemoveRegisteredYubiKeyPublicIDOperation("abcdefg");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 73);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "abcdefg");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetRegisteredYubiKeyPublicIDsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetRegisteredYubiKeyPublicIDOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createSetRegisteredYubiKeyPublicIDsOperation("abcdefg");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 74);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "abcdefg");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearRegisteredYubiKeyPublicIDsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearRegisteredYubiKeyPublicIDsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createClearRegisteredYubiKeyPublicIDsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 75);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createAddTOTPSharedSecretOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateAddTOTPSharedSecretOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createAddTOTPSharedSecretOperation("abcdefghijklmnop");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 76);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "abcdefghijklmnop");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createRemoveTOTPSharedSecretOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateRemoveTOTPSharedSecretOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createRemoveTOTPSharedSecretOperation("abcdefghijklmnop");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 77);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "abcdefghijklmnop");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetTOTPSharedSecretsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetTOTPSharedSecretsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createSetTOTPSharedSecretsOperation("abcdefghijklmnop");

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 78);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "abcdefghijklmnop");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearTOTPSharedSecretsOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearTOTPSharedSecretsOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createClearTOTPSharedSecretsOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 79);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createHasYubiKeyPublicIDOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateHasYubiKeyPublicIDOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createHasYubiKeyPublicIDOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 80);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createHasStaticPasswordOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateHasStaticPasswordOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createHasStaticPasswordOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 81);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetLastBindPasswordValidationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetLastBindPasswordValidationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetLastBindPasswordValidationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 82);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetSecondsSinceLastBindPasswordValidationOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetSecondsSinceLastBindPasswordValidationOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createGetSecondsSinceLastBindPasswordValidationOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 83);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetLastBindPasswordValidationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetLastBindPasswordValidationTimeOperation()
         throws Exception
  {
    Date d = new Date();

    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createSetLastBindPasswordValidationTimeOperation(d);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 84);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNotNull(op.getGeneralizedTimeValue());
    assertEquals(op.getGeneralizedTimeValue(), d);

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 1);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearLastBindPasswordValidationTimeOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearLastBindPasswordValidationTimeOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.
              createClearLastBindPasswordValidationTimeOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 85);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetAccountIsValidationLockedOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetAccountIsValidationLockedOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createGetAccountIsValidationLockedOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 86);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createSetAccountIsValidationLockedOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateSetAccountIsValidationLockedOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op = PasswordPolicyStateOperation.
         createSetAccountIsValidationLockedOperation(false);

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 87);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 1);

    assertNotNull(op.getStringValue());
    assertEquals(op.getStringValue(), "false");

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 1);

    assertFalse(op.getBooleanValue());

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValue();
      fail("Expected an exception when calling getGeneralizedTimeValue()");
    } catch (Exception e) {}

    try
    {
      op.getGeneralizedTimeValues();
      fail("Expected an exception when calling getGeneralizedTimeValues()");
    } catch (Exception e) {}

    assertNotNull(op.toString());
  }



  /**
   * Tests the createGetRecentLoginHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateGetRecentLoginHistoryOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createGetRecentLoginHistoryOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 88);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }



  /**
   * Tests the createClearRecentLoginHistoryOperation method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCreateClearRecentLoginHistoryOperation()
         throws Exception
  {
    PasswordPolicyStateOperation op =
         PasswordPolicyStateOperation.createClearRecentLoginHistoryOperation();

    op = PasswordPolicyStateOperation.decode(op.encode());

    assertEquals(op.getOperationType(), 89);

    assertNotNull(op.getRawValues());
    assertEquals(op.getRawValues().length, 0);

    assertNull(op.getStringValue());

    assertNotNull(op.getStringValues());
    assertEquals(op.getStringValues().length, 0);

    try
    {
      op.getBooleanValue();
      fail("Expected an exception when calling getBooleanValue()");
    } catch (Exception e) {}

    try
    {
      op.getIntValue();
      fail("Expected an exception when calling getIntValue()");
    } catch (Exception e) {}

    assertNull(op.getGeneralizedTimeValue());

    assertNotNull(op.getGeneralizedTimeValues());
    assertEquals(op.getGeneralizedTimeValues().length, 0);

    assertNotNull(op.toString());
  }
}
