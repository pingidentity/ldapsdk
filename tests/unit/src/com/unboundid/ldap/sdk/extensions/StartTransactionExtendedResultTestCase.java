/*
 * Copyright 2007-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2007-2019 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.extensions;



import org.testng.annotations.Test;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Control;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the
 * StartTransactionExtendedResult class.
 */
public class StartTransactionExtendedResultTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the first constructor with a success response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Success()
         throws Exception
  {
    ExtendedResult er = new ExtendedResult(1, ResultCode.SUCCESS, null, null,
                                           new String[0], null,
                                           new ASN1OctetString("1234"),
                                           new Control[0]);

    StartTransactionExtendedResult r = new StartTransactionExtendedResult(er);

    assertEquals(r.getMessageID(), 1);

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the first constructor with a failure response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor1Failure()
         throws Exception
  {
    ExtendedResult er =
         new ExtendedResult(1, ResultCode.UNWILLING_TO_PERFORM,
                            "Transactions are not supported in this server",
                            "dc=example,dc=com",
                            new String[] { "ldap://server1.example.com/",
                                           "ldap://server2.example.com/" },
                            null, null,
                            new Control[] { new Control("1.2.3.4"),
                                            new Control("1.2.3.5") });

    StartTransactionExtendedResult r = new StartTransactionExtendedResult(er);

    assertEquals(r.getMessageID(), 1);

    assertNull(r.getValue());

    assertNull(r.getTransactionID());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a success response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Success()
         throws Exception
  {
    StartTransactionExtendedResult r = new StartTransactionExtendedResult(1,
         ResultCode.SUCCESS, null, null, null, new ASN1OctetString("1234"),
         null);
    r = new StartTransactionExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertNotNull(r.getValue());

    assertNotNull(r.getTransactionID());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 0);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }



  /**
   * Tests the second constructor with a failure response.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructor2Failure()
         throws Exception
  {
    String[] referralURLs =
    {
      "ldap://server1.example.com/dc=example,dc=com",
      "ldap://server2.example.com/dc=example,dc=com",
    };

    Control[] controls =
    {
      new Control("1.2.3.4"),
      new Control("1.2.3.5", true, new ASN1OctetString(new byte[1]))
    };

    StartTransactionExtendedResult r = new StartTransactionExtendedResult(1,
         ResultCode.UNWILLING_TO_PERFORM,
         "Transactions are not supported in this server", "dc=example,dc=com",
         referralURLs, null, controls);
    r = new StartTransactionExtendedResult(r);

    assertEquals(r.getMessageID(), 1);

    assertNull(r.getValue());

    assertNull(r.getTransactionID());

    assertNotNull(r.getResponseControls());
    assertEquals(r.getResponseControls().length, 2);

    assertNotNull(r.getExtendedResultName());
    assertNotNull(r.toString());
  }
}
