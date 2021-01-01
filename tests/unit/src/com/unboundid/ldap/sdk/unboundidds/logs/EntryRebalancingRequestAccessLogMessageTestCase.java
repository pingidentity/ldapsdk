/*
 * Copyright 2012-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2012-2021 Ping Identity Corporation
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
 * Copyright (C) 2012-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * {@code EntryRebalancingRequestAccessLogMessage} class.
 */
public class EntryRebalancingRequestAccessLogMessageTestCase
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

    EntryRebalancingRequestAccessLogMessage m =
         new EntryRebalancingRequestAccessLogMessage(s);
    m = new EntryRebalancingRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.ENTRY_REBALANCING_REQUEST);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNull(m.getRebalancingOperationID());

    assertNull(m.getTriggeringConnectionID());

    assertNull(m.getTriggeringOperationID());

    assertNull(m.getSubtreeBaseDN());

    assertNull(m.getSizeLimit());

    assertNull(m.getSourceBackendSetName());

    assertNull(m.getSourceBackendServer());

    assertNull(m.getTargetBackendSetName());

    assertNull(m.getTargetBackendServer());

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
    String s = f.format(d) + " ENTRY-REBALANCING-REQUEST rebalancingOp=1 " +
         "triggeredByConn=2 triggeredByOp=3 " +
         "base=\"ou=subtree,dc=example,dc=com\" sizeLimit=4 " +
         "sourceBackendSet=\"source set\" " +
         "sourceServer=\"source.example.com:1389\" " +
         "targetBackendSet=\"target set\" " +
         "targetServer=\"target.example.com:2389\"";

    EntryRebalancingRequestAccessLogMessage m =
         new EntryRebalancingRequestAccessLogMessage(s);
    m = new EntryRebalancingRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.ENTRY_REBALANCING_REQUEST);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNotNull(m.getRebalancingOperationID());
    assertEquals(m.getRebalancingOperationID(), Long.valueOf(1L));

    assertNotNull(m.getTriggeringConnectionID());
    assertEquals(m.getTriggeringConnectionID(), Long.valueOf(2L));

    assertNotNull(m.getTriggeringOperationID());
    assertEquals(m.getTriggeringOperationID(), Long.valueOf(3L));

    assertNotNull(m.getSubtreeBaseDN());
    assertEquals(new DN(m.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(m.getSizeLimit());
    assertEquals(m.getSizeLimit(), Integer.valueOf(4));

    assertNotNull(m.getSourceBackendSetName());
    assertEquals(m.getSourceBackendSetName(), "source set");

    assertNotNull(m.getSourceBackendServer());
    assertEquals(m.getSourceBackendServer(), "source.example.com:1389");

    assertNotNull(m.getTargetBackendSetName());
    assertEquals(m.getTargetBackendSetName(), "target set");

    assertNotNull(m.getTargetBackendServer());
    assertEquals(m.getTargetBackendServer(), "target.example.com:2389");

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
    String s = f.format(d) + " ENTRY-REBALANCING-REQUEST " +
         "product=\"Directory Server\" " +
         "instanceName=\"server.example.com:389\" startupID=\"ABCDEFG\" " +
         "rebalancingOp=1 triggeredByConn=2 triggeredByOp=3 " +
         "base=\"ou=subtree,dc=example,dc=com\" sizeLimit=4 " +
         "sourceBackendSet=\"source set\" " +
         "sourceServer=\"source.example.com:1389\" " +
         "targetBackendSet=\"target set\" " +
         "targetServer=\"target.example.com:2389\"";

    EntryRebalancingRequestAccessLogMessage m =
         new EntryRebalancingRequestAccessLogMessage(s);
    m = new EntryRebalancingRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.ENTRY_REBALANCING_REQUEST);

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNull(m.getConnectionID());

    assertNotNull(m.getRebalancingOperationID());
    assertEquals(m.getRebalancingOperationID(), Long.valueOf(1L));

    assertNotNull(m.getTriggeringConnectionID());
    assertEquals(m.getTriggeringConnectionID(), Long.valueOf(2L));

    assertNotNull(m.getTriggeringOperationID());
    assertEquals(m.getTriggeringOperationID(), Long.valueOf(3L));

    assertNotNull(m.getSubtreeBaseDN());
    assertEquals(new DN(m.getSubtreeBaseDN()),
         new DN("ou=subtree,dc=example,dc=com"));

    assertNotNull(m.getSizeLimit());
    assertEquals(m.getSizeLimit(), Integer.valueOf(4));

    assertNotNull(m.getSourceBackendSetName());
    assertEquals(m.getSourceBackendSetName(), "source set");

    assertNotNull(m.getSourceBackendServer());
    assertEquals(m.getSourceBackendServer(), "source.example.com:1389");

    assertNotNull(m.getTargetBackendSetName());
    assertEquals(m.getTargetBackendSetName(), "target set");

    assertNotNull(m.getTargetBackendServer());
    assertEquals(m.getTargetBackendServer(), "target.example.com:2389");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }
}
