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



import java.lang.reflect.Field;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;



/**
 * This class provides a set of test cases for the ResultCode class.
 */
public class ResultCodeTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests to ensure that all predefined result code values are included in the
   * array returned by the values method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValuesIncludesAllPredefinedValues()
         throws Exception
  {
    for (Field f : ResultCode.class.getFields())
    {
      if (f.getDeclaringClass().equals(ResultCode.class) &&
          f.getType().equals(ResultCode.class))
      {
        ResultCode predefined = (ResultCode) f.get(null);

        boolean found = false;
        for (ResultCode rc : ResultCode.values())
        {
          if (rc == predefined)
          {
            found = true;
            break;
          }
        }

        assertTrue(found,
             "Result code " + predefined.getName() + " not in values()");
      }
    }
  }



  /**
   * Tests to ensure that all predefined result code values are handled by
   * valueOf.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfIncludesAllPredefinedValues()
         throws Exception
  {
    for (Field f : ResultCode.class.getFields())
    {
      if (f.getDeclaringClass().equals(ResultCode.class) &&
          f.getType().equals(ResultCode.class))
      {
        ResultCode predefined = (ResultCode) f.get(null);
        ResultCode valueOf = ResultCode.valueOf(predefined.intValue());

        assertEquals(predefined, valueOf);
        assertEquals(predefined.intValue(), valueOf.intValue());
        assertEquals(predefined.hashCode(), valueOf.hashCode());
        assertEquals(predefined.getName(), valueOf.getName());
        assertSame(predefined, valueOf);
      }
    }
  }



  /**
   * Tests to ensure that multiple calls to valueOf with undefined values will
   * behave correctly and will return the same object.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValueOfUndefined()
         throws Exception
  {
    ResultCode rc1 = ResultCode.valueOf(12345);
    assertEquals(rc1.intValue(), 12345);
    assertEquals(rc1.getName(), String.valueOf("12345"));
    assertEquals(rc1.toString(), String.valueOf("12345"));

    ResultCode rc2 = ResultCode.valueOf(12345);
    assertEquals(rc2.intValue(), 12345);
    assertEquals(rc2.getName(), String.valueOf("12345"));
    assertEquals(rc2.toString(), String.valueOf("12345"));

    assertEquals(rc1, rc2);
    assertSame(rc1, rc2);

    ResultCode rc3 = ResultCode.valueOf(12346, "one two three four six");
    assertEquals(rc3.intValue(), 12346);
    assertEquals(rc3.getName(), "one two three four six");
    assertEquals(rc3.toString(), "12346 (one two three four six)");

    ResultCode rc4 = ResultCode.valueOf(12346);
    assertEquals(rc4.intValue(), 12346);
    assertEquals(rc3.getName(), "one two three four six");
    assertEquals(rc3.toString(), "12346 (one two three four six)");

    assertEquals(rc3, rc4);
    assertSame(rc3, rc4);

    ResultCode rc5 = ResultCode.valueOf(12347, null, false);
    assertNull(rc5);
  }




  /**
   * Tests the {@code equals} method.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEquals()
         throws Exception
  {
    assertFalse(ResultCode.SUCCESS.equals(null));
    assertTrue(ResultCode.SUCCESS.equals(ResultCode.SUCCESS));
    assertFalse(ResultCode.SUCCESS.equals(ResultCode.OTHER));
    assertTrue(ResultCode.SUCCESS.equals(ResultCode.valueOf(0)));
    assertFalse(ResultCode.SUCCESS.equals("foo"));
  }



  /**
   * Provides test coverage for ResultCode methods.
   *
   * @param  resultCode        The result code to use for the test exception.
   * @param  clientSide        Indicates whether it is a client-side result
   *                           code.
   * @param  connectionUsable  Indicates whether to consider the connection
   *                           usable after a response with the result code.
   */
  @Test(dataProvider = "testResultCodes")
  public void testResultCodeMethods(ResultCode resultCode, boolean clientSide,
                                    boolean connectionUsable)
  {
    assertNotNull(resultCode.getName());
    assertNotNull(resultCode.toString());

    assertEquals(ResultCode.valueOf(resultCode.intValue()), resultCode);
    assertFalse(ResultCode.valueOf(resultCode.intValue()+1).equals(resultCode));

    assertEquals(resultCode.isClientSideResultCode(), clientSide);
    assertEquals(ResultCode.isClientSideResultCode(resultCode), clientSide);

    assertEquals(resultCode.isConnectionUsable(), connectionUsable);
    assertEquals(ResultCode.isConnectionUsable(resultCode), connectionUsable);
  }



  /**
   * Retrieves a set of result code values that may be used for testing
   * purposes.
   *
   * @return  A set of result code values that may be used for testing purposes.
   */
  @DataProvider(name = "testResultCodes")
  public Object[][] getTestResultCodes()
  {
    return new Object[][]
    {
      new Object[] { ResultCode.SUCCESS, false, true },
      new Object[] { ResultCode.OPERATIONS_ERROR, false, false },
      new Object[] { ResultCode.PROTOCOL_ERROR, false, false },
      new Object[] { ResultCode.TIME_LIMIT_EXCEEDED, false, true },
      new Object[] { ResultCode.SIZE_LIMIT_EXCEEDED, false, true },
      new Object[] { ResultCode.COMPARE_FALSE, false, true },
      new Object[] { ResultCode.COMPARE_TRUE, false, true },
      new Object[] { ResultCode.AUTH_METHOD_NOT_SUPPORTED, false, true },
      new Object[] { ResultCode.STRONG_AUTH_REQUIRED, false, true },
      new Object[] { ResultCode.REFERRAL, false, true },
      new Object[] { ResultCode.ADMIN_LIMIT_EXCEEDED, false, true },
      new Object[] { ResultCode.UNAVAILABLE_CRITICAL_EXTENSION, false, true },
      new Object[] { ResultCode.CONFIDENTIALITY_REQUIRED, false, true },
      new Object[] { ResultCode.SASL_BIND_IN_PROGRESS, false, true },
      new Object[] { ResultCode.NO_SUCH_ATTRIBUTE, false, true },
      new Object[] { ResultCode.UNDEFINED_ATTRIBUTE_TYPE, false, true },
      new Object[] { ResultCode.INAPPROPRIATE_MATCHING, false, true },
      new Object[] { ResultCode.CONSTRAINT_VIOLATION, false, true },
      new Object[] { ResultCode.ATTRIBUTE_OR_VALUE_EXISTS, false, true },
      new Object[] { ResultCode.INVALID_ATTRIBUTE_SYNTAX, false, true },
      new Object[] { ResultCode.NO_SUCH_OBJECT, false, true },
      new Object[] { ResultCode.ALIAS_PROBLEM, false, true },
      new Object[] { ResultCode.INVALID_DN_SYNTAX, false, true },
      new Object[] { ResultCode.ALIAS_DEREFERENCING_PROBLEM, false, true },
      new Object[] { ResultCode.INAPPROPRIATE_AUTHENTICATION, false, true },
      new Object[] { ResultCode.INVALID_CREDENTIALS, false, true },
      new Object[] { ResultCode.INSUFFICIENT_ACCESS_RIGHTS, false, true },
      new Object[] { ResultCode.BUSY, false, false },
      new Object[] { ResultCode.UNAVAILABLE, false, false },
      new Object[] { ResultCode.UNWILLING_TO_PERFORM, false, true },
      new Object[] { ResultCode.LOOP_DETECT, false, true },
      new Object[] { ResultCode.SORT_CONTROL_MISSING, false, true },
      new Object[] { ResultCode.OFFSET_RANGE_ERROR, false, true },
      new Object[] { ResultCode.NAMING_VIOLATION, false, true },
      new Object[] { ResultCode.OBJECT_CLASS_VIOLATION, false, true },
      new Object[] { ResultCode.NOT_ALLOWED_ON_NONLEAF, false, true },
      new Object[] { ResultCode.NOT_ALLOWED_ON_RDN, false, true },
      new Object[] { ResultCode.ENTRY_ALREADY_EXISTS, false, true },
      new Object[] { ResultCode.OBJECT_CLASS_MODS_PROHIBITED, false, true },
      new Object[] { ResultCode.AFFECTS_MULTIPLE_DSAS, false, true },
      new Object[] { ResultCode.VIRTUAL_LIST_VIEW_ERROR, false, true },
      new Object[] { ResultCode.OTHER, false, false },
      new Object[] { ResultCode.SERVER_DOWN, true, false },
      new Object[] { ResultCode.LOCAL_ERROR, true, false },
      new Object[] { ResultCode.ENCODING_ERROR, true, false },
      new Object[] { ResultCode.DECODING_ERROR, true, false },
      new Object[] { ResultCode.TIMEOUT, true, false },
      new Object[] { ResultCode.AUTH_UNKNOWN, true, true },
      new Object[] { ResultCode.FILTER_ERROR, true, true },
      new Object[] { ResultCode.USER_CANCELED, true, true },
      new Object[] { ResultCode.PARAM_ERROR, true, true },
      new Object[] { ResultCode.NO_MEMORY, true, false },
      new Object[] { ResultCode.CONNECT_ERROR, true, false },
      new Object[] { ResultCode.NOT_SUPPORTED, true, true },
      new Object[] { ResultCode.CONTROL_NOT_FOUND, true, true },
      new Object[] { ResultCode.NO_RESULTS_RETURNED, true, true },
      new Object[] { ResultCode.MORE_RESULTS_TO_RETURN, true, true },
      new Object[] { ResultCode.CLIENT_LOOP, true, true },
      new Object[] { ResultCode.REFERRAL_LIMIT_EXCEEDED, true, true },
      new Object[] { ResultCode.CANCELED, false, true },
      new Object[] { ResultCode.NO_SUCH_OPERATION, false, true },
      new Object[] { ResultCode.TOO_LATE, false, true },
      new Object[] { ResultCode.CANNOT_CANCEL, false, true },
      new Object[] { ResultCode.ASSERTION_FAILED, false, true },
      new Object[] { ResultCode.AUTHORIZATION_DENIED, false, true },
      new Object[] { ResultCode.E_SYNC_REFRESH_REQUIRED, false, true },
      new Object[] { ResultCode.NO_OPERATION, false, true },
      new Object[] { ResultCode.INTERACTIVE_TRANSACTION_ABORTED, false, true },
      new Object[] { ResultCode.DATABASE_LOCK_CONFLICT, false, true },
      new Object[] { ResultCode.MIRRORED_SUBTREE_DIGEST_MISMATCH, false, true },
      new Object[] { ResultCode.TOKEN_DELIVERY_MECHANISM_UNAVAILABLE, false,
                     true },
      new Object[] { ResultCode.TOKEN_DELIVERY_ATTEMPT_FAILED, false, true },
      new Object[] { ResultCode.TOKEN_DELIVERY_INVALID_RECIPIENT_ID, false,
                     true },
      new Object[] { ResultCode.TOKEN_DELIVERY_INVALID_ACCOUNT_STATE, false,
                     true }
    };
  }
}
