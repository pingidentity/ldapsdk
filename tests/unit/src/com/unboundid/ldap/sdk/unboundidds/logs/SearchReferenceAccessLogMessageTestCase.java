/*
 * Copyright 2009-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2025 Ping Identity Corporation
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
 * Copyright (C) 2009-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * {@code SearchReferenceAccessLogMessage} class.
 */
public class SearchReferenceAccessLogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create a log message from a string containing only a
   * timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyTimestamp()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d);

    SearchReferenceAccessLogMessage m = new SearchReferenceAccessLogMessage(s);
    m = new SearchReferenceAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REFERENCE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNull(m.getOperationID());

    assertNull(m.getMessageID());

    assertNull(m.getOrigin());

    assertNotNull(m.getReferralURLs());
    assertTrue(m.getReferralURLs().isEmpty());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing only a
   * basic set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBasicContents()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH REFERENCE conn=1 op=2 msgID=3 " +
               "referralURLs=\"ldap://server.example.com:389/\"";

    SearchReferenceAccessLogMessage m = new SearchReferenceAccessLogMessage(s);
    m = new SearchReferenceAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REFERENCE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNull(m.getOrigin());

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 1);
    assertTrue(m.getReferralURLs().contains("ldap://server.example.com:389/"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing a
   * complete set of information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteContents()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH REFERENCE " +
               "product=\"Directory Server\" " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" " +
               "referralURLs=\"ldap://server1.example.com:389/," +
               "ldap://server2.example.com:389/\" responseControls=\"8.7.6.5\"";

    SearchReferenceAccessLogMessage m = new SearchReferenceAccessLogMessage(s);
    m = new SearchReferenceAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REFERENCE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getConnectionID());
    assertEquals(m.getConnectionID(), Long.valueOf(1));

    assertNotNull(m.getOperationID());
    assertEquals(m.getOperationID(), Long.valueOf(2));

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Integer.valueOf(3));

    assertNotNull(m.getOrigin());
    assertEquals(m.getOrigin(), "internal");

    assertNotNull(m.getReferralURLs());
    assertEquals(m.getReferralURLs().size(), 2);
    assertTrue(m.getReferralURLs().contains("ldap://server1.example.com:389/"));
    assertTrue(m.getReferralURLs().contains("ldap://server2.example.com:389/"));

    assertNotNull(m.getResponseControlOIDs());
    assertEquals(m.getResponseControlOIDs().size(), 1);
    assertTrue(m.getResponseControlOIDs().contains("8.7.6.5"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }
}
