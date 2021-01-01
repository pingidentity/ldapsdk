/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Base64;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the base64 password encoder.
 */
public final class Base64PasswordEncoderOutputFormatterTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior with an empty password, which should never happen but
   * we'll handle anyway.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testEmptyPassword()
         throws Exception
  {
    final Base64PasswordEncoderOutputFormatter formatter =
         Base64PasswordEncoderOutputFormatter.getInstance();
    assertNotNull(formatter);

    final byte[] formattedBytes = formatter.format(StaticUtils.NO_BYTES);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes.length, 0);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes.length, 0);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior with a password that is a multiple of three bytes and
   * therefore will not require any base64 padding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordMultipleOfThreeBytes()
         throws Exception
  {
    final byte[] sourceBytes = StaticUtils.getBytes("123456");

    final byte[] targetBytes = StaticUtils.getBytes(Base64.encode(sourceBytes));
    assertNotNull(targetBytes);
    assertEquals(targetBytes.length, ((sourceBytes.length / 3) * 4));
    assertFalse(targetBytes[targetBytes.length - 1] == '=');

    final Base64PasswordEncoderOutputFormatter formatter =
         Base64PasswordEncoderOutputFormatter.getInstance();
    assertNotNull(formatter);

    final byte[] formattedBytes = formatter.format(sourceBytes);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes, targetBytes);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes, sourceBytes);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior with a password that is not a multiple of three bytes
   * and therefore will require base64 padding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordNotMultipleOfThreeBytes()
         throws Exception
  {
    final byte[] sourceBytes = StaticUtils.getBytes("1234567");

    final byte[] targetBytes = StaticUtils.getBytes(Base64.encode(sourceBytes));
    assertNotNull(targetBytes);
    assertTrue(targetBytes[targetBytes.length - 1] == '=');

    final Base64PasswordEncoderOutputFormatter formatter =
         Base64PasswordEncoderOutputFormatter.getInstance();
    assertNotNull(formatter);

    final byte[] formattedBytes = formatter.format(sourceBytes);
    assertNotNull(formattedBytes);
    assertEquals(formattedBytes, targetBytes);

    final byte[] unFormattedBytes = formatter.unFormat(formattedBytes);
    assertNotNull(unFormattedBytes);
    assertEquals(unFormattedBytes, sourceBytes);

    assertNotNull(formatter.toString());
  }



  /**
   * Tests the behavior when trying to un-format a value that isn't valid
   * base64.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testUnFormatMalformedValue()
         throws Exception
  {
    final Base64PasswordEncoderOutputFormatter formatter =
         Base64PasswordEncoderOutputFormatter.getInstance();
    assertNotNull(formatter);

    // This array is malformed both because it has an invalid length that can't
    // possibly be the result of base64 encoding, and because it's got a
    // character (the null character) that isn't used in base64 encoding).
    final byte[] malformedBytes = new byte[1];
    formatter.unFormat(malformedBytes);
  }
}
