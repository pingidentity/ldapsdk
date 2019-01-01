/*
 * Copyright 2016-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.io.ByteArrayOutputStream;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.sdk.BindResult;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the report bind result LDAP
 * connection pool health check class.
 */
public final class ReportBindResultLDAPConnectionPoolHealthCheckTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior of the health check when configured to only report the
   * results of failed bind attempts.
   *
   * @param  bindResult  The bind result to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testBindResults")
  public void testOnlyReportBindFailures(final BindResult bindResult)
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final LDAPModify tool = new LDAPModify(null, out, out);

    final ReportBindResultLDAPConnectionPoolHealthCheck hc =
         new ReportBindResultLDAPConnectionPoolHealthCheck(tool, false, false);
    assertNotNull(hc.toString());

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    hc.ensureConnectionValidAfterAuthentication(conn, bindResult);

    conn.close();

    if (bindResult.getResultCode() == ResultCode.SUCCESS)
    {
      assertEquals(out.toByteArray().length, 0);
    }
    else
    {
      assertTrue(out.toByteArray().length > 0);
    }
  }



  /**
   * Tests the behavior of the health check when configured to report successful
   * authentications when they have controls.
   *
   * @param  bindResult  The bind result to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testBindResults")
  public void testReportSuccessWithControls(final BindResult bindResult)
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final LDAPModify tool = new LDAPModify(null, out, out);

    final ReportBindResultLDAPConnectionPoolHealthCheck hc =
         new ReportBindResultLDAPConnectionPoolHealthCheck(tool, true, false);
    assertNotNull(hc.toString());

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    hc.ensureConnectionValidAfterAuthentication(conn, bindResult);

    conn.close();

    if (bindResult.getResultCode() == ResultCode.SUCCESS)
    {
      if (bindResult.hasResponseControl())
      {
        assertTrue(out.toByteArray().length > 0);
      }
      else
      {
        assertEquals(out.toByteArray().length, 0);
      }
    }
    else
    {
      assertTrue(out.toByteArray().length > 0);
    }
  }



  /**
   * Tests the behavior of the health check when configured to report successful
   * authentications regardless of whether they have controls.
   *
   * @param  bindResult  The bind result to test.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testBindResults")
  public void testReportSuccessWithoutControls(final BindResult bindResult)
         throws Exception
  {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final LDAPModify tool = new LDAPModify(null, out, out);

    final ReportBindResultLDAPConnectionPoolHealthCheck hc =
         new ReportBindResultLDAPConnectionPoolHealthCheck(tool, true, true);
    assertNotNull(hc.toString());

    final InMemoryDirectoryServer ds = getTestDS();
    final LDAPConnection conn = ds.getConnection();

    hc.ensureConnectionValidAfterAuthentication(conn, bindResult);

    conn.close();

    assertTrue(out.toByteArray().length > 0);
  }



  /**
   * Retrieves a set of bind results to use for testing.
   *
   * @return  A set of bind results to use for testing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @DataProvider(name="testBindResults")
  public Object[][] getTestBindResults()
         throws Exception
  {
    final Control[] controls =
    {
      new Control("1.2.3.4", true, null),
      new Control("5.6.7.8", false, new ASN1OctetString("value"))
    };

    final String[] referralURLs =
    {
      "ldap://ds1.example.com:389/dc=example,dc=com",
      "ldap://ds2.example.com:389/dc=example,dc=com"
    };

    return new Object[][]
    {
      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null, null)
      },
      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null, controls)
      },
      new Object[]
      {
        new BindResult(1, ResultCode.SUCCESS, null, null, null, null)
      },
      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS, "No such user",
             "ou=People,dc=example,dc=com", referralURLs, null, null)
      },
      new Object[]
      {
        new BindResult(1, ResultCode.INVALID_CREDENTIALS, "No such user",
             "ou=People,dc=example,dc=com", referralURLs, controls,
             new ASN1OctetString("server SASL credentials"))
      },
    };
  }
}
