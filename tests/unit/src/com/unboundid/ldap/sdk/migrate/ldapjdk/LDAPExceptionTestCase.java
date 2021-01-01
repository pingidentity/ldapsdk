/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.migrate.ldapjdk;



import java.util.Locale;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides test coverage for the {@code LDAPException} class.
 */
public class LDAPExceptionTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the default constructor.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDefaultConstructor()
         throws Exception
  {
    LDAPException e = new LDAPException();

    assertNotNull(e);

    assertNotNull(e.getMessage());

    assertEquals(e.getLDAPResultCode(), ResultCode.OTHER_INT_VALUE);

    assertNull(e.getLDAPErrorMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.toLDAPException());
    assertEquals(e.toLDAPException().getResultCode(), ResultCode.OTHER);
    assertNotNull(e.toLDAPException().getMessage());

    assertNotNull(e.errorCodeToString());

    assertNotNull(e.errorCodeToString(Locale.getDefault()));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE,
                                                  Locale.getDefault()));

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessage()
         throws Exception
  {
    LDAPException e = new LDAPException("oops");

    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "oops");

    assertEquals(e.getLDAPResultCode(), ResultCode.OTHER_INT_VALUE);

    assertNull(e.getLDAPErrorMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.toLDAPException());
    assertEquals(e.toLDAPException().getResultCode(), ResultCode.OTHER);
    assertNotNull(e.toLDAPException().getMessage());

    assertNotNull(e.errorCodeToString());

    assertNotNull(e.errorCodeToString(Locale.getDefault()));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE,
                                                  Locale.getDefault()));

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a message and a
   * result code.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessageAndResultCode()
         throws Exception
  {
    LDAPException e =
         new LDAPException("oops", ResultCode.NO_SUCH_OBJECT_INT_VALUE);

    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "oops");

    assertEquals(e.getLDAPResultCode(), ResultCode.NO_SUCH_OBJECT_INT_VALUE);

    assertNull(e.getLDAPErrorMessage());

    assertNull(e.getMatchedDN());

    assertNotNull(e.toLDAPException());
    assertEquals(e.toLDAPException().getResultCode(),
                 ResultCode.NO_SUCH_OBJECT);
    assertNotNull(e.toLDAPException().getMessage());

    assertNotNull(e.errorCodeToString());

    assertNotNull(e.errorCodeToString(Locale.getDefault()));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE,
                                                  Locale.getDefault()));

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a message, a result
   * code, and a server error message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessageResultCodeAndServerMessage()
         throws Exception
  {
    LDAPException e =
         new LDAPException("oops", ResultCode.NO_SUCH_OBJECT_INT_VALUE,
                           "server oops");

    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "oops");

    assertEquals(e.getLDAPResultCode(), ResultCode.NO_SUCH_OBJECT_INT_VALUE);

    assertNotNull(e.getLDAPErrorMessage());
    assertEquals(e.getLDAPErrorMessage(), "server oops");

    assertNull(e.getMatchedDN());

    assertNotNull(e.toLDAPException());
    assertEquals(e.toLDAPException().getResultCode(),
                 ResultCode.NO_SUCH_OBJECT);
    assertNotNull(e.toLDAPException().getMessage());

    assertNotNull(e.errorCodeToString());

    assertNotNull(e.errorCodeToString(Locale.getDefault()));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE,
                                                  Locale.getDefault()));

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes a message, a result
   * code, a server error message, and a matched DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithMessageResultCodeServerMessageAndMatchedDN()
         throws Exception
  {
    LDAPException e =
         new LDAPException(null, ResultCode.NO_SUCH_OBJECT_INT_VALUE,
                           "server oops", "dc=example,dc=com");

    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "server oops");

    assertEquals(e.getLDAPResultCode(), ResultCode.NO_SUCH_OBJECT_INT_VALUE);

    assertNotNull(e.getLDAPErrorMessage());
    assertEquals(e.getLDAPErrorMessage(), "server oops");

    assertNotNull(e.getMatchedDN());
    assertEquals(e.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(e.toLDAPException());
    assertEquals(e.toLDAPException().getResultCode(),
                 ResultCode.NO_SUCH_OBJECT);
    assertNotNull(e.toLDAPException().getMessage());

    assertNotNull(e.errorCodeToString());

    assertNotNull(e.errorCodeToString(Locale.getDefault()));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE,
                                                  Locale.getDefault()));

    assertNotNull(e.toString());
  }



  /**
   * Provides test coverage for the constructor which takes an SDK exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorWithSDKException()
         throws Exception
  {
    LDAPException e = new LDAPException(
         new com.unboundid.ldap.sdk.LDAPException(ResultCode.NO_SUCH_OBJECT,
              "Entry doesn't exist", "dc=example,dc=com", null, null,  null));

    assertNotNull(e);

    assertNotNull(e.getMessage());
    assertEquals(e.getMessage(), "Entry doesn't exist");

    assertEquals(e.getLDAPResultCode(), ResultCode.NO_SUCH_OBJECT_INT_VALUE);

    assertNotNull(e.getLDAPErrorMessage());
    assertEquals(e.getLDAPErrorMessage(), "Entry doesn't exist");

    assertNotNull(e.getMatchedDN());
    assertEquals(e.getMatchedDN(), "dc=example,dc=com");

    assertNotNull(e.toLDAPException());
    assertEquals(e.toLDAPException().getResultCode(),
                 ResultCode.NO_SUCH_OBJECT);
    assertNotNull(e.toLDAPException().getMessage());

    assertNotNull(e.errorCodeToString());

    assertNotNull(e.errorCodeToString(Locale.getDefault()));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE));

    assertNotNull(LDAPException.errorCodeToString(ResultCode.OTHER_INT_VALUE,
                                                  Locale.getDefault()));

    assertNotNull(e.toString());
  }
}
