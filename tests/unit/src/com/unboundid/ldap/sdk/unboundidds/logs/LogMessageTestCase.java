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
import java.util.GregorianCalendar;
import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the {@code LogMessage} class.
 */
public class LogMessageTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to create a log message from a string containing only a
   * timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMessageStringOnlyTimestamp()
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

    LogMessage m = new LogMessage(s);
    m = new LogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertTrue(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string formatted in the
   * manner of an error log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMessageStringErrorLogFormat()
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

    LogMessage m = new LogMessage(s);
    m = new LogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertTrue(m.getUnnamedValues().isEmpty());

    assertEquals(m.getNamedValue("category"), "CORE");
    assertEquals(m.getNamedValue("severity"), "NOTICE");
    assertEquals(m.getNamedValueAsLong("msgID"), Long.valueOf(458887));
    assertEquals(m.getNamedValue("msg"),
                 "The Directory Server has started successfully");

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from a string formatted in the
   * manner of an access log message.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testMessageStringAccessLogFormat()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " SEARCH RESULT conn=1 op=2 msgID=3 " +
               "resultCode=0 etime=0.123 qtime=5 entriesReturned=4 " +
               "unindexed=true";

    LogMessage m = new LogMessage(s);
    m = new LogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValues());
    assertFalse(m.getNamedValues().isEmpty());

    assertNotNull(m.getUnnamedValues());
    assertFalse(m.getUnnamedValues().isEmpty());

    assertEquals(m.getNamedValueAsLong("conn"), Long.valueOf(1));
    assertEquals(m.getNamedValueAsLong("op"), Long.valueOf(2));
    assertEquals(m.getNamedValueAsInteger("msgID"), Integer.valueOf(3));
    assertEquals(m.getNamedValueAsInteger("resultCode"), Integer.valueOf(0));
    assertEquals(m.getNamedValueAsDouble("etime"), Double.valueOf("0.123"));
    assertEquals(m.getNamedValueAsDouble("qtime"), Double.valueOf("5"));
    assertEquals(m.getNamedValueAsLong("entriesReturned"),
                 Long.valueOf(4));
    assertEquals(m.getNamedValueAsBoolean("unindexed"), Boolean.TRUE);

    assertTrue(m.hasUnnamedValue("SEARCH"));
    assertTrue(m.hasUnnamedValue("RESULT"));

    assertNotNull(m.toString());
    assertEquals(m.toString(), s);
  }



  /**
   * Tests the ability to create a log message from an empty string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LogException.class })
  public void testMessageStringEmpty()
         throws Exception
  {
    new LogMessage("");
  }



  /**
   * Tests the ability to create a log message from a string that does not
   * contain a timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LogException.class })
  public void testMessageStringNoTimestamp()
         throws Exception
  {
    new LogMessage("this is not a valid log message");
  }



  /**
   * Tests the ability to create a log message from a string that does not
   * contains a malformed timestamp.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LogException.class })
  public void testMessageStringMalformedTimestamp()
         throws Exception
  {
    new LogMessage("[malformed] this is not a valid log message");
  }



  /**
   * Tests the ability to create a log message from a string containing a valid
   * set of escaped characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEscapedCharacters()
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
               "msg=\"0123456789:;<=>?#30#31#32#33#34#35#36#37#38#39" +
               "#3A#3B#3C#3D#3E#3F#30#31#32#33#34#35#36#37#38#39" +
               "#3a#3b#3c#3d#3e#3f\"";

    LogMessage m = new LogMessage(s);
    m = new LogMessage(m);

    assertNotNull(m);

    assertNotNull(m.getTimestamp());
    assertEquals(m.getTimestamp(), d);

    assertNotNull(m.getNamedValue("msg"));
    assertEquals(m.getNamedValue("msg"),
                 "0123456789:;<=>?0123456789:;<=>?0123456789:;<=>?");
  }



  /**
   * Tests the ability to create a log message from a string containing invalid
   * escaped characters.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LogException.class })
  public void testInvalidEscapedCharacters()
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
               "msg=\"#gg\"";

    new LogMessage(s);
  }



  /**
   * Tests the ability to create a log message from a string containing a short
   * escaped character sequence.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LogException.class })
  public void testShortEscapedCharacters()
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
               "msg=\"#30#3\"";

    new LogMessage(s);
  }



  /**
   * Tests the ability to parse valid and invalid Boolean values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseBooleanValues()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " a=true b=TRUE c=\"true\" d=\"TRUE\" e=t f=yes " +
               "g=y h=on i=1 j=false k=FALSE l=\"false\" m=\"FALSE\" n=f " +
               "o=no p=n q=off r=0 s=invalid";

    LogMessage m = new LogMessage(s);

    assertEquals(m.getNamedValueAsBoolean("a"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("b"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("c"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("d"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("e"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("f"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("g"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("h"), Boolean.TRUE);
    assertEquals(m.getNamedValueAsBoolean("i"), Boolean.TRUE);

    assertEquals(m.getNamedValueAsBoolean("j"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("k"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("l"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("m"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("n"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("o"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("p"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("q"), Boolean.FALSE);
    assertEquals(m.getNamedValueAsBoolean("r"), Boolean.FALSE);

    assertNotNull(m.getNamedValue("s"));
    assertNull(m.getNamedValueAsBoolean("s"));

    assertNull(m.getNamedValue("t"));
    assertNull(m.getNamedValueAsBoolean("t"));
  }



  /**
   * Tests the ability to parse valid and invalid Double values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseDoubleValues()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " a=0 b=1 c=-1 d=0.0 e=1.0 f=-1.0 g=0.1 h=1.2 " +
               "i=-3.4 j=invalid";

    LogMessage m = new LogMessage(s);

    assertEquals(m.getNamedValueAsDouble("a"), Double.valueOf("0"));
    assertEquals(m.getNamedValueAsDouble("b"), Double.valueOf("1"));
    assertEquals(m.getNamedValueAsDouble("c"), Double.valueOf("-1"));
    assertEquals(m.getNamedValueAsDouble("d"), Double.valueOf("0.0"));
    assertEquals(m.getNamedValueAsDouble("e"), Double.valueOf("1.0"));
    assertEquals(m.getNamedValueAsDouble("f"), Double.valueOf("-1.0"));
    assertEquals(m.getNamedValueAsDouble("g"), Double.valueOf("0.1"));
    assertEquals(m.getNamedValueAsDouble("h"), Double.valueOf("1.2"));
    assertEquals(m.getNamedValueAsDouble("i"), Double.valueOf("-3.4"));

    assertNotNull(m.getNamedValue("j"));
    assertNull(m.getNamedValueAsDouble("j"));

    assertNull(m.getNamedValue("k"));
    assertNull(m.getNamedValueAsDouble("k"));
  }



  /**
   * Tests the ability to parse valid and invalid Integer values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseIntegerValues()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " a=0 b=1 c=-1 d=12345 e=-54321 f=invalid";

    LogMessage m = new LogMessage(s);

    assertEquals(m.getNamedValueAsInteger("a"), Integer.valueOf(0));
    assertEquals(m.getNamedValueAsInteger("b"), Integer.valueOf(1));
    assertEquals(m.getNamedValueAsInteger("c"), Integer.valueOf(-1));
    assertEquals(m.getNamedValueAsInteger("d"), Integer.valueOf(12345));
    assertEquals(m.getNamedValueAsInteger("e"), Integer.valueOf(-54321));

    assertNotNull(m.getNamedValue("f"));
    assertNull(m.getNamedValueAsInteger("f"));

    assertNull(m.getNamedValue("g"));
    assertNull(m.getNamedValueAsInteger("g"));
  }



  /**
   * Tests the ability to parse valid and invalid Long values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseLongValues()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 0);
    d = c.getTime();

    SimpleDateFormat f = new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss Z']'");
    String s = f.format(d) + " a=0 b=1 c=-1 d=12345 e=-54321 f=invalid";

    LogMessage m = new LogMessage(s);

    assertEquals(m.getNamedValueAsLong("a"), Long.valueOf(0));
    assertEquals(m.getNamedValueAsLong("b"), Long.valueOf(1));
    assertEquals(m.getNamedValueAsLong("c"), Long.valueOf(-1));
    assertEquals(m.getNamedValueAsLong("d"), Long.valueOf(12345));
    assertEquals(m.getNamedValueAsLong("e"), Long.valueOf(-54321));

    assertNotNull(m.getNamedValue("f"));
    assertNull(m.getNamedValueAsLong("f"));

    assertNull(m.getNamedValue("g"));
    assertNull(m.getNamedValueAsLong("g"));
  }


  /**
   * Tests the ability to parse valid and invalid Integer values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testParseTimestampWithMs()
         throws Exception
  {
    // Get a timestamp that doesn't include milliseconds.
    Date d = new Date();
    GregorianCalendar c = new GregorianCalendar();
    c.setTime(d);
    c.set(GregorianCalendar.MILLISECOND, 123);
    d = c.getTime();

    SimpleDateFormat f =
            new SimpleDateFormat("'['dd/MMM/yyyy:HH:mm:ss.SSS Z']'");
    String s = f.format(d) + " a=0 b=1 c=-1 d=12345 e=-54321 f=invalid";

    LogMessage m = new LogMessage(s);
    Date d2 = m.getTimestamp();
    assertEquals(d, d2, "Timestamps are unexpectedly not equal");
  }

}
