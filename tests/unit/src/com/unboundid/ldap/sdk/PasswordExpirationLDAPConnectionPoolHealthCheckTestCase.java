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
package com.unboundid.ldap.sdk;



import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.controls.PasswordExpiredControl;
import com.unboundid.ldap.sdk.controls.PasswordExpiringControl;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10ResponseControl;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10ErrorType;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10WarningType;



/**
 * This class provides a set of test cases for the password expiration health
 * check.
 */
public final class PasswordExpirationLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the health check when it is configured to throw an
   * exception for any kind of warning.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testThrowOnWarning(final BindResult bindResult,
                                 final boolean expectWarning,
                                 final boolean expectError,
                                 final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck();

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  Both warnings and
    // errors should result in exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning || expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectWarning || expectError);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  Subsequent warnings should be suppressed, but errors will
    // result in exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
    }

    conn.close();
  }



  /**
   * Tests the behavior of the health check when it is configured to write
   * warnings to an output stream.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testWarningToOutputStream(final BindResult bindResult,
                                        final boolean expectWarning,
                                        final boolean expectError,
                                        final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck(outputStream);

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  All warnings
    // should be appended to the output stream, and errors should result in
    // exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  All warnings should be suppressed, and errors should result in
    // exceptions.
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length == 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }

    conn.close();
  }



  /**
   * Tests the behavior of the health check when it is configured to write
   * warnings to a writer.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testWarningToWriter(final BindResult bindResult,
                                  final boolean expectWarning,
                                  final boolean expectError,
                                  final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck(
              new OutputStreamWriter(outputStream));

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  All warnings
    // should be appended to the output stream, and errors should result in
    // exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  All warnings should be suppressed, and errors should result in
    // exceptions.
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length == 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }

    conn.close();
  }



  /**
   * Tests the behavior of the health check when it is configured to write
   * warnings to an output stream in a manner that will not suppress repeat
   * warnings.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testWarningToOutputStreamNeverSuppress(
                   final BindResult bindResult, final boolean expectWarning,
                   final boolean expectError, final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck(outputStream, 0L);

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  All warnings
    // should be appended to the output stream, and errors should result in
    // exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  This should behave exactly the same as the first occurrence.
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }

    conn.close();
  }



  /**
   * Tests the behavior of the health check when it is configured to write
   * warnings to a writer in a manner that will not suppress repeat warnings.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testWarningToWriterNeverSuppress(
                   final BindResult bindResult, final boolean expectWarning,
                   final boolean expectError, final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck(
              new OutputStreamWriter(outputStream), 0L);

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  All warnings
    // should be appended to the output stream, and errors should result in
    // exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  This should behave exactly the same as the first occurrence.
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }

    conn.close();
  }



  /**
   * Tests the behavior of the health check when it is configured to write
   * warnings to an output stream in a manner that will temporarily suppress
   * repeat warnings.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testWarningToOutputStreamTemporarilySuppress(
                   final BindResult bindResult, final boolean expectWarning,
                   final boolean expectError, final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck(outputStream,
              1000L);

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  All warnings
    // should be appended to the output stream, and errors should result in
    // exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  All warnings should be suppressed, and errors should result in
    // exceptions.
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length == 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Sleep for 1.5 seconds and check again.  This should behave exactly the
    // same as the first occurrence.
    Thread.sleep(1500L);
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }

    conn.close();
  }



  /**
   * Tests the behavior of the health check when it is configured to write
   * warnings to a writer in a manner that will temporarily suppress repeat
   * warnings.
   *
   * @param  bindResult     The bind result to be tested.
   * @param  expectWarning  Indicates whether the provided bind result is
   *                        expected to generate a warning.
   * @param  expectError    Indicates whether the provided bind result is
   *                        expected to generate an error.
   * @param  description    A description of the bind result.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider = "testBindResults")
  public void testWarningToWriterTemporarilySuppress(
                   final BindResult bindResult, final boolean expectWarning,
                   final boolean expectError, final String description)
         throws Exception
  {
    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

    final PasswordExpirationLDAPConnectionPoolHealthCheck hc =
         new PasswordExpirationLDAPConnectionPoolHealthCheck(
              new OutputStreamWriter(outputStream), 1000L);

    assertNotNull(hc.toString());


    // Ensure that the first occurrence is handled properly.  All warnings
    // should be appended to the output stream, and errors should result in
    // exceptions.
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Ensure that a second occurrence immediately after the first is handled
    // properly.  All warnings should be suppressed, and errors should result in
    // exceptions.
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length == 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }


    // Sleep for 1.5 seconds and check again.  This should behave exactly the
    // same as the first occurrence.
    Thread.sleep(1500L);
    outputStream.reset();
    try
    {
      hc.ensureConnectionValidAfterAuthentication(conn, bindResult);
      if (expectWarning)
      {
        assertTrue(outputStream.toByteArray().length > 0);
      }
      else if (expectError)
      {
        fail("Expected an exception for bind result " + bindResult);
      }
    }
    catch (final LDAPException le)
    {
      assertTrue(expectError);
      assertTrue(outputStream.toByteArray().length == 0);
    }

    conn.close();
  }



  /**
   * Retrieves a set of test data for this class.
   *
   * @return  A set of test data for this class.
   */
  @DataProvider(name="testBindResults")
  public Object[][] getTestBindResults()
  {
    return new Object[][]
    {
      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null, null),
        false,
        false,
        "Successful bind with no controls"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS, null, null, null,
             null),
        false,
        false,
        "Failed bind with no controls"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null,
             new Control[] { new PasswordExpiringControl(1234) }),
        true,
        false,
        "Successful bind with password expiring control and no diagnostic " +
             "message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, "Your password is expiring", null,
             null, new Control[] { new PasswordExpiringControl(1234) }),
        true,
        false,
        "Successful bind with password expiring control and a diagnostic " +
             "message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null,
             new Control[] { new PasswordExpiredControl() }),
        false,
        true,
        "Successful bind with password expired control and no diagnostic " +
             "message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, "Change your password", null,
             null, new Control[] { new PasswordExpiredControl() }),
        false,
        true,
        "Successful bind with password expired control and a diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS, null, null, null,
             new Control[] { new PasswordExpiredControl() }),
        false,
        true,
        "Failed bind with password expired control and no diagnostic " +
             "message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS,
             "Your password is expired", null, null,
             new Control[] { new PasswordExpiredControl() }),
        false,
        true,
        "Failed bind with password expired control and a diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    DraftBeheraLDAPPasswordPolicy10WarningType.
                         TIME_BEFORE_EXPIRATION,
                    1234, null)
             }),
        true,
        false,
        "Successful bind with password expiring PW policy warning and no " +
             "diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, "Your password is expiring", null,
             null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    DraftBeheraLDAPPasswordPolicy10WarningType.
                         TIME_BEFORE_EXPIRATION,
                    1234, null)
             }),
        true,
        false,
        "Successful bind with password expiring PW policy warning and a " +
             "diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    DraftBeheraLDAPPasswordPolicy10WarningType.
                         GRACE_LOGINS_REMAINING,
                    3, null)
             }),
        true,
        false,
        "Successful bind with grace login and no diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS,
             "You have three grace logins remaining", null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    DraftBeheraLDAPPasswordPolicy10WarningType.
                         GRACE_LOGINS_REMAINING,
                    3, null)
             }),
        true,
        false,
        "Successful bind with grace login and a diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS, null, null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    null, 0,
                    DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED)
             }),
        false,
        true,
        "Failed bind with pw policy expired password and no diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS,
             "Your password is expired", null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    null, 0,
                    DraftBeheraLDAPPasswordPolicy10ErrorType.PASSWORD_EXPIRED)
             }),
        false,
        true,
        "Failed bind with pw policy expired password and a diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    null, 0,
                    DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET)
             }),
        false,
        true,
        "Successful bind with must change password and no diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS,
             "Change your password", null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    null, 0,
                    DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET)
             }),
        false,
        true,
        "Successful bind with must change password and a diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS, null, null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    null, 0,
                    DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET)
             }),
        false,
        true,
        "Failed bind with must change password and no diagnostic message"
      },

      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS,
             "Change your password", null, null,
             new Control[]
             {
               new DraftBeheraLDAPPasswordPolicy10ResponseControl(
                    null, 0,
                    DraftBeheraLDAPPasswordPolicy10ErrorType.CHANGE_AFTER_RESET)
             }),
        false,
        true,
        "Failed bind with must change password and a diagnostic message"
      },
    };
  }
}
