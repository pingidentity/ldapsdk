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



import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code ErrorLogReader} class.
 */
public class ErrorLogReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to read a valid error log message from a file containing
   * only the message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testOnlyValidMessage()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " category=CORE severity=NOTICE msgID=458887 " +
               "msg=\"The Directory Server has started successfully\"";

    File file = createTempFile(s);

    ErrorLogReader reader = new ErrorLogReader(file);

    ErrorLogMessage m = reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNotNull(m.getCategory());
    assertEquals(m.getCategory(), ErrorLogCategory.CORE);

    assertNotNull(m.getSeverity());
    assertEquals(m.getSeverity(), ErrorLogSeverity.NOTICE);

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Long.valueOf(458887));

    assertNotNull(m.getMessage());
    assertEquals(m.getMessage(),
                 "The Directory Server has started successfully");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the ability to read a valid error log message from a file containing
   * a log message and a comment.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidMessageWithComment()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " product=\"Directory Server\" " +
               "instanceName=\"server.example.com:389\" " +
               "startupID=ABCDEFG category=INVALID severity=INVALID " +
               "msgID=12345 msg=\"foo\"";

    File file = createTempFile(
         "# This is a comment and the next line is blank.",
         "",
         s);

    ErrorLogReader reader = new ErrorLogReader(file.getAbsolutePath());

    ErrorLogMessage m = reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.getProductName());
    assertEquals(m.getProductName(), "Directory Server");

    assertNotNull(m.getInstanceName());
    assertEquals(m.getInstanceName(), "server.example.com:389");

    assertNotNull(m.getStartupID());
    assertEquals(m.getStartupID(), "ABCDEFG");

    assertNotNull(m.getNamedValue("category"));
    assertNull(m.getCategory());

    assertNotNull(m.getNamedValue("severity"));
    assertNull(m.getSeverity());

    assertNotNull(m.getMessageID());
    assertEquals(m.getMessageID(), Long.valueOf(12345));

    assertNotNull(m.getMessage());
    assertEquals(m.getMessage(), "foo");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the ability to read a message containing only a timestamp.
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

    File file = createTempFile(s);

    ErrorLogReader reader = new ErrorLogReader(new FileReader(file));

    ErrorLogMessage m = reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getCategory());

    assertNull(m.getSeverity());

    assertNull(m.getMessageID());

    assertNull(m.getMessage());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    assertNull(reader.read());
    reader.close();
  }



  /**
   * Tests the ability to handle a valid message after an invalid message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidAfterInvalid()
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

    File file = createTempFile(
         "invalid",
         s);

    ErrorLogReader reader =
         new ErrorLogReader(new BufferedReader(new FileReader(file)));

    try
    {
      reader.read();
      fail("Expected an exception when trying to read an invalid message");
    }
    catch (LogException le)
    {
      // This was expected.
      assertEquals(le.getLogMessage(), "invalid");
    }

    ErrorLogMessage m = reader.read();

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNull(m.getProductName());

    assertNull(m.getInstanceName());

    assertNull(m.getStartupID());

    assertNull(m.getCategory());

    assertNull(m.getSeverity());

    assertNull(m.getMessageID());

    assertNull(m.getMessage());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);

    assertNull(reader.read());
    reader.close();
  }
}
