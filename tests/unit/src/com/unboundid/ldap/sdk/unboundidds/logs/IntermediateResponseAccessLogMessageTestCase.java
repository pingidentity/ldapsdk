/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the
 * {@code IntermediateResponseAccessLogMessage} class.
 */
public class IntermediateResponseAccessLogMessageTestCase
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

    IntermediateResponseAccessLogMessage m =
         new IntermediateResponseAccessLogMessage(s);
    m = new IntermediateResponseAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.INTERMEDIATE_RESPONSE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNull(m.getOperationID());

    assertNull(m.getMessageID());

    assertNull(m.getOrigin());

    assertNull(m.getOID());

    assertNull(m.getIntermediateResponseName());

    assertNull(m.getValueString());

    assertNotNull(m.getResponseControlOIDs());
    assertTrue(m.getResponseControlOIDs().isEmpty());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string containing only a
   * timestamp.
   *
   * @param  opTypeString   The operation type string to use for the message.
   * @param  expectedMatch  The operation type expected to match the given name.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(dataProvider="testOperationTypes")
  public void testOperationTypes(final String opTypeString,
       final AccessLogOperationType expectedMatch)
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + ' ' + opTypeString + " INTERMEDIATE-RESPONSE";

    IntermediateResponseAccessLogMessage m =
         new IntermediateResponseAccessLogMessage(s);
    m = new IntermediateResponseAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.INTERMEDIATE_RESPONSE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), expectedMatch);

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getConnectionID());

    assertNull(m.getOperationID());

    assertNull(m.getMessageID());

    assertNull(m.getOrigin());

    assertNull(m.getOID());

    assertNull(m.getIntermediateResponseName());

    assertNull(m.getValueString());

    assertNotNull(m.getResponseControlOIDs());
    assertTrue(m.getResponseControlOIDs().isEmpty());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Retrieves a set of operation type data that can be used for testing.
   *
   * @return  A set of operation type data that can be used for testing.
   */
  @DataProvider(name="testOperationTypes")
  public Object[][] getTestOperationTypes()
  {
    return new Object[][]
    {
      new Object[] { "ABANDON",   AccessLogOperationType.EXTENDED },
      new Object[] { "ADD",       AccessLogOperationType.ADD },
      new Object[] { "BIND",      AccessLogOperationType.BIND },
      new Object[] { "COMPARE",   AccessLogOperationType.COMPARE },
      new Object[] { "DELETE",    AccessLogOperationType.DELETE },
      new Object[] { "EXTENDED",  AccessLogOperationType.EXTENDED },
      new Object[] { "MODIFY",    AccessLogOperationType.MODIFY },
      new Object[] { "MODDN",     AccessLogOperationType.MODDN },
      new Object[] { "SEARCH",    AccessLogOperationType.SEARCH },
      new Object[] { "UNBIND",    AccessLogOperationType.EXTENDED },
      new Object[] { "FOO",       AccessLogOperationType.EXTENDED },
    };
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
    String s = f.format(d) + " EXTENDED INTERMEDIATE-RESPONSE conn=1 op=2 " +
         "msgID=3 oid=\"1.3.6.1.4.1.30221.2.6.7\" " +
         "name=\"Stream Directory Values Intermediate Response\" " +
         "value=\"result='more values to return' valueCount='1000'\"";

    IntermediateResponseAccessLogMessage m =
         new IntermediateResponseAccessLogMessage(s);
    m = new IntermediateResponseAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.INTERMEDIATE_RESPONSE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

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

    assertNotNull(m.getOID());
    assertEquals(m.getOID(), "1.3.6.1.4.1.30221.2.6.7");

    assertNotNull(m.getIntermediateResponseName());
    assertEquals(m.getIntermediateResponseName(),
         "Stream Directory Values Intermediate Response");

    assertNotNull(m.getValueString());
    assertEquals(m.getValueString(),
         "result='more values to return' valueCount='1000'");

    assertNotNull(m.getResponseControlOIDs());
    assertTrue(m.getResponseControlOIDs().isEmpty());

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
    String s = f.format(d) + " EXTENDED INTERMEDIATE-RESPONSE " +
         "product=\"Directory Server\" " +
         "instanceName=\"server.example.com:389\" " +
         "startupID=\"ABCDEFG\" conn=1 op=2 msgID=3 " +
         "origin=\"internal\" " +
         "oid=\"1.3.6.1.4.1.30221.2.6.7\" " +
         "name=\"Stream Directory Values Intermediate Response\" " +
         "value=\"result='more values to return' valueCount='1000'\" " +
         "responseControls=\"8.7.6.5\"";

    IntermediateResponseAccessLogMessage m =
         new IntermediateResponseAccessLogMessage(s);
    m = new IntermediateResponseAccessLogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getMessageType());
    assertEquals(m.getMessageType(),
         AccessLogMessageType.INTERMEDIATE_RESPONSE);

    assertNotNull(m.getOperationType());
    assertEquals(m.getOperationType(), AccessLogOperationType.EXTENDED);

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

    assertNotNull(m.getOID());
    assertEquals(m.getOID(), "1.3.6.1.4.1.30221.2.6.7");

    assertNotNull(m.getIntermediateResponseName());
    assertEquals(m.getIntermediateResponseName(),
         "Stream Directory Values Intermediate Response");

    assertNotNull(m.getValueString());
    assertEquals(m.getValueString(),
         "result='more values to return' valueCount='1000'");

    assertNotNull(m.getResponseControlOIDs());
    assertEquals(m.getResponseControlOIDs().size(), 1);
    assertTrue(m.getResponseControlOIDs().contains("8.7.6.5"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }
}
