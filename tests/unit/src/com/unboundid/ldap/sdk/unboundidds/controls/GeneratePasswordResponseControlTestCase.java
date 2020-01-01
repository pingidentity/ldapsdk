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
package com.unboundid.ldap.sdk.unboundidds.controls;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the generate password response
 * control.
 */
public final class GeneratePasswordResponseControlTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for a response control that does not contain the
   * optional {@code secondsUntilExpiration} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithoutSecondsUntilExpiration()
         throws Exception
  {
    GeneratePasswordResponseControl c = new GeneratePasswordResponseControl(
         "the-generated-password", false, (Long) null);

    c = new GeneratePasswordResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.59");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getGeneratedPassword());
    assertEquals(c.getGeneratedPassword().stringValue(),
         "the-generated-password");

    assertNotNull(c.getGeneratedPasswordString());
    assertEquals(c.getGeneratedPasswordString(),
         "the-generated-password");

    assertNotNull(c.getGeneratedPasswordBytes());
    assertEquals(c.getGeneratedPasswordBytes(),
         StaticUtils.getBytes("the-generated-password"));

    assertFalse(c.mustChangePassword());

    assertNull(c.getSecondsUntilExpiration());

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Provides test coverage for a response control that includes the optional
   * optional {@code secondsUntilExpiration} value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testControlWithSecondsUntilExpiration()
         throws Exception
  {
    GeneratePasswordResponseControl c = new GeneratePasswordResponseControl(
         StaticUtils.getBytes("another-generated-password"), true, 12345678L);

    c = new GeneratePasswordResponseControl().decodeControl(c.getOID(),
         c.isCritical(), c.getValue());

    assertNotNull(c.getOID());
    assertEquals(c.getOID(), "1.3.6.1.4.1.30221.2.5.59");

    assertFalse(c.isCritical());

    assertNotNull(c.getValue());

    assertNotNull(c.getGeneratedPassword());
    assertEquals(c.getGeneratedPassword().stringValue(),
         "another-generated-password");

    assertNotNull(c.getGeneratedPasswordString());
    assertEquals(c.getGeneratedPasswordString(),
         "another-generated-password");

    assertNotNull(c.getGeneratedPasswordBytes());
    assertEquals(c.getGeneratedPasswordBytes(),
         StaticUtils.getBytes("another-generated-password"));

    assertTrue(c.mustChangePassword());

    assertNotNull(c.getSecondsUntilExpiration());
    assertEquals(c.getSecondsUntilExpiration().longValue(),
         12345678L);

    assertNotNull(c.getControlName());

    assertNotNull(c.toString());
  }



  /**
   * Tests the behavior of the {@code decodeControl} method for a control that
   * does not have a value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlMissingValue()
         throws Exception
  {
    new GeneratePasswordResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.59", false, null);
  }



  /**
   * Tests the behavior of the {@code decodeControl} method for a control that
   * has a value that cannot be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testDecodeControlWithMalformedValue()
         throws Exception
  {
    new GeneratePasswordResponseControl().decodeControl(
         "1.3.6.1.4.1.30221.2.5.59", false, new ASN1OctetString("foo"));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that does not include any controls.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithoutAnyControls()
         throws Exception
  {
    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS);
    assertNull(GeneratePasswordResponseControl.get(result));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that does includes controls but no generate password response
   * control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithNonGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.2.3.4", false, new ASN1OctetString("foo"))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNull(GeneratePasswordResponseControl.get(result));
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that includes a valid generate password response control that is
   * already an instance of that type of control.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidDecodedGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new GeneratePasswordResponseControl("generated-password", true, 12345L)
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNotNull(GeneratePasswordResponseControl.get(result));
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getGeneratedPasswordString(),
         "generated-password");
    assertTrue(
         GeneratePasswordResponseControl.get(result).mustChangePassword());
    assertNotNull(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration());
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration().longValue(),
         12345L);
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that includes a valid generate password response control that is
   * provided as a generic control that needs to be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetWithValidNonDecodedGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.59", false,
           new GeneratePasswordResponseControl("generated-password", true,
                12345L).getValue())
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    assertNotNull(GeneratePasswordResponseControl.get(result));
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getGeneratedPasswordString(),
         "generated-password");
    assertTrue(
         GeneratePasswordResponseControl.get(result).mustChangePassword());
    assertNotNull(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration());
    assertEquals(
         GeneratePasswordResponseControl.get(result).
              getSecondsUntilExpiration().longValue(),
         12345L);
  }



  /**
   * Provides test coverage for the {@code get} method when provided with a
   * result that has a control with the same OID as the generate password
   * response control, but that cannot be decoded.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testGetWithInvalidGeneratePasswordResponseControl()
         throws Exception
  {
    final Control[] responseControls =
    {
      new Control("1.3.6.1.4.1.30221.2.5.59", false,
           new ASN1OctetString("foo"))
    };

    final LDAPResult result = new LDAPResult(2, ResultCode.SUCCESS, null, null,
         null, responseControls);

    GeneratePasswordResponseControl.get(result);
  }
}
