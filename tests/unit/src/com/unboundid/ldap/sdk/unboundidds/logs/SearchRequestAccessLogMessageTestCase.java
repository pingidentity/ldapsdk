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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DereferencePolicy;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.SearchScope;



/**
 * This class provides test coverage for the
 * {@code SearchRequestAccessLogMessage} class.
 */
public class SearchRequestAccessLogMessageTestCase
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

    SearchRequestAccessLogMessage m = new SearchRequestAccessLogMessage(s);
    m = new SearchRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.SEARCH);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNull(m.getOperationID());

    assertNull(m.getMessageID());

    assertNull(m.getOrigin());

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNull(m.getIntermediateClientRequest());

    assertNull(m.getOperationPurpose());

    assertNull(m.getBaseDN());

    assertNull(m.getScope());

    assertNull(m.getFilter());

    assertNull(m.getParsedFilter());

    assertNull(m.getDereferencePolicy());

    assertNull(m.getSizeLimit());

    assertNull(m.getTimeLimit());

    assertNull(m.typesOnly());

    assertNull(m.getRequestedAttributes());

    assertNull(m.usingAdminSessionWorkerThread());

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

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
    String s = f.format(d) + " SEARCH REQUEST conn=1 op=2 msgID=3 " +
               "base=\"dc=example,dc=com\" scope=0 " +
               "filter=\"(objectClass=*)\" attrs=\"ALL\"";

    SearchRequestAccessLogMessage m = new SearchRequestAccessLogMessage(s);
    m = new SearchRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

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

    assertNull(m.getRequesterDN());

    assertNull(m.getRequesterIPAddress());

    assertNull(m.getIntermediateClientRequest());

    assertNull(m.getOperationPurpose());

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.BASE);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(objectClass=*)");

    assertNotNull(m.getParsedFilter());
    assertEquals(m.getParsedFilter(),
                 Filter.createPresenceFilter("objectClass"));

    assertNull(m.getDereferencePolicy());

    assertNull(m.getSizeLimit());

    assertNull(m.getTimeLimit());

    assertNull(m.typesOnly());

    assertNotNull(m.getRequestedAttributes());
    assertTrue(m.getRequestedAttributes().isEmpty());

    assertNull(m.usingAdminSessionWorkerThread());

    assertNull(m.getTriggeredByConnectionID());

    assertNull(m.getTriggeredByOperationID());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing a
   * complete set of information with a single requested attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteContentsSingleAttr()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH REQUEST " +
               "product=\"Directory Server\" " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "usingAdminSessionWorkerThread=true " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(uid=test.user)\" sizeLimit=123 timeLimit=456 " +
               "deref=\"NEVER\" typesOnly=false attrs=\"cn\" " +
               "triggeredByConn=987 triggeredByOp=654";

    SearchRequestAccessLogMessage m = new SearchRequestAccessLogMessage(s);
    m = new SearchRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

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

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.SUB);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(uid=test.user)");

    assertNotNull(m.getParsedFilter());
    assertEquals(m.getParsedFilter(),
                 Filter.createEqualityFilter("uid", "test.user"));

    assertNotNull(m.getDereferencePolicy());
    assertEquals(m.getDereferencePolicy(), DereferencePolicy.NEVER);

    assertNotNull(m.getSizeLimit());
    assertEquals(m.getSizeLimit(), Integer.valueOf(123));

    assertNotNull(m.getTimeLimit());
    assertEquals(m.getTimeLimit(), Integer.valueOf(456));

    assertNotNull(m.typesOnly());
    assertEquals(m.typesOnly(), Boolean.FALSE);

    assertNotNull(m.getRequestedAttributes());
    assertEquals(m.getRequestedAttributes().size(), 1);
    assertEquals(m.getRequestedAttributes().iterator().next(), "cn");

    assertNotNull(m.usingAdminSessionWorkerThread());
    assertEquals(m.usingAdminSessionWorkerThread(), Boolean.TRUE);

    assertNotNull(m.getTriggeredByConnectionID());
    assertEquals(m.getTriggeredByConnectionID().longValue(), 987L);

    assertNotNull(m.getTriggeredByOperationID());
    assertEquals(m.getTriggeredByOperationID().longValue(), 654L);

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing a
   * complete set of information with multiple requested attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testCompleteContentsMultipleAttrs()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH REQUEST " +
               "product=\"Directory Server\" " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
               "origin=\"internal\" requesterIP=\"1.2.3.4\" " +
               "requesterDN=\"uid=test.user,ou=People,dc=example,dc=com\" " +
               "usingAdminSessionWorkerThread=true " +
               "via=\"app='UnboundID Directory Proxy Server'\" " +
               "opPurpose=\"app='Some Client' purpose='foo'\" " +
               "base=\"dc=example,dc=com\" scope=2 " +
               "filter=\"(invalid)\" sizeLimit=123 timeLimit=456 " +
               "deref=\"ALWAYS\" typesOnly=false attrs=\"givenName,sn\" " +
               "triggeredByConn=987 triggeredByOp=654";

    SearchRequestAccessLogMessage m = new SearchRequestAccessLogMessage(s);
    m = new SearchRequestAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(), AccessLogMessageType.REQUEST);

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

    assertNotNull(m.getRequesterDN());
    assertEquals(m.getRequesterDN(),
                 "uid=test.user,ou=People,dc=example,dc=com");

    assertNotNull(m.getRequesterIPAddress());
    assertEquals(m.getRequesterIPAddress(), "1.2.3.4");

    assertNotNull(m.getIntermediateClientRequest());
    assertEquals(m.getIntermediateClientRequest(),
                 "app='UnboundID Directory Proxy Server'");

    assertNotNull(m.getOperationPurpose());
    assertEquals(m.getOperationPurpose(),
                 "app='Some Client' purpose='foo'");

    assertNotNull(m.getBaseDN());
    assertEquals(m.getBaseDN(), "dc=example,dc=com");

    assertNotNull(m.getScope());
    assertEquals(m.getScope(), SearchScope.SUB);

    assertNotNull(m.getFilter());
    assertEquals(m.getFilter(), "(invalid)");

    assertNull(m.getParsedFilter());

    assertNotNull(m.getDereferencePolicy());
    assertEquals(m.getDereferencePolicy(), DereferencePolicy.ALWAYS);

    assertNotNull(m.getSizeLimit());
    assertEquals(m.getSizeLimit(), Integer.valueOf(123));

    assertNotNull(m.getTimeLimit());
    assertEquals(m.getTimeLimit(), Integer.valueOf(456));

    assertNotNull(m.typesOnly());
    assertEquals(m.typesOnly(), Boolean.FALSE);

    assertNotNull(m.getRequestedAttributes());
    assertEquals(m.getRequestedAttributes().size(), 2);

    Iterator<String> iterator = m.getRequestedAttributes().iterator();
    assertEquals(iterator.next(), "givenName");
    assertEquals(iterator.next(), "sn");

    assertNotNull(m.usingAdminSessionWorkerThread());
    assertEquals(m.usingAdminSessionWorkerThread(), Boolean.TRUE);

    assertNotNull(m.getTriggeredByConnectionID());
    assertEquals(m.getTriggeredByConnectionID().longValue(), 987L);

    assertNotNull(m.getTriggeredByOperationID());
    assertEquals(m.getTriggeredByOperationID().longValue(), 654L);

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }
}
