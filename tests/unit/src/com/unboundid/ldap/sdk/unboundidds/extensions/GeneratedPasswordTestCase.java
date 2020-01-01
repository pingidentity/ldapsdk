/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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



import java.util.Arrays;

import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the {@code GeneratedPassword}
 * class.
 */
public final class GeneratedPasswordTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior for a password created from a string.  It will indicate
   * that no validation has been attempted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordCreatedFromString()
         throws Exception
  {
    GeneratedPassword p =
         new GeneratedPassword("createdFromString", false, null);

    p = GeneratedPassword.decode(p.encode());

    assertNotNull(p.getPasswordString());
    assertEquals(p.getPasswordString(), "createdFromString");

    assertNotNull(p.getPasswordBytes());
    assertEquals(p.getPasswordBytes(),
         "createdFromString".getBytes("UTF-8"));

    assertFalse(p.validationAttempted());

    assertNotNull(p.getValidationErrors());
    assertTrue(p.getValidationErrors().isEmpty());

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior for a password created from a byte array.  It will
   * indicate that validation has been attempted and that there were
   * validation errors.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPasswordCreatedFromBytes()
         throws Exception
  {
    GeneratedPassword p = new GeneratedPassword(
         StaticUtils.getBytes("createdFromBytes"), true,
         Arrays.asList(
              "I don't like the password.",
              "You shouldn't use it."));

    p = GeneratedPassword.decode(p.encode());

    assertNotNull(p.getPasswordString());
    assertEquals(p.getPasswordString(), "createdFromBytes");

    assertNotNull(p.getPasswordBytes());
    assertEquals(p.getPasswordBytes(),
         "createdFromBytes".getBytes("UTF-8"));

    assertTrue(p.validationAttempted());

    assertNotNull(p.getValidationErrors());
    assertFalse(p.getValidationErrors().isEmpty());
    assertEquals(p.getValidationErrors().size(), 2);
    assertEquals(p.getValidationErrors(),
         Arrays.asList(
              "I don't like the password.",
              "You shouldn't use it."));

    assertNotNull(p.toString());
  }



  /**
   * Tests the behavior when trying to decode an ASN.1 element that does not
   * contain a valid encoding.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDecodeMalformed()
         throws Exception
  {
    try
    {
      GeneratedPassword.decode(new ASN1OctetString("malformed"));
      fail("Expected an exception when trying to decode a malformed element " +
           "as a generated password.");
    }
    catch (final LDAPException e)
    {
      assertResultCodeEquals(e, ResultCode.DECODING_ERROR);
    }
  }
}
