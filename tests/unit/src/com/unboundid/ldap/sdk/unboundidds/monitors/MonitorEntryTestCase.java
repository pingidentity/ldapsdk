/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.AfterClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.Debug;



/**
 * This class provides test coverage for the MonitorEntry class.
 */
public class MonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Enable debugging before running tests in this class to get better
   * coverage.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void setUp()
         throws Exception
  {
    Debug.setEnabled(true);
  }



  /**
   * Disable debugging after testing has completed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void cleanUp()
         throws Exception
  {
    Debug.setEnabled(false);
  }



  /**
   * Provides test coverage for the constructor with a valid generic entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorGeneric()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: bar");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDN());
    assertEquals(new DN(me.getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertNotNull(me.getEntry());
    assertEquals(new DN(me.getEntry().getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertEquals(me.getMonitorClass(), "ds-foo-monitor-entry");

    assertEquals(me.getMonitorName(), "foo");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 MonitorEntry.class.getName());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());
    assertEquals(me.getMonitorAttributes().get("foo").getStringValue(), "bar");
  }



  /**
   * Provides test coverage for the constructor with an entry that isn't really
   * a monitor entry.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNotMonitor()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: extensibleObject",
                        "cn: foo");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDN());
    assertEquals(new DN(me.getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertNotNull(me.getEntry());
    assertEquals(new DN(me.getEntry().getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertEquals(me.getMonitorClass(), "ds-monitor-entry");

    assertEquals(me.getMonitorName(), "foo");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 MonitorEntry.class.getName());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    assertNotNull(me.getMonitorAttributes());
    assertTrue(me.getMonitorAttributes().isEmpty());
  }



  /**
   * Provides test coverage for the constructor with an entry that doesn't
   * contain a specific monitor subclass.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNoSubclass()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: bar");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDN());
    assertEquals(new DN(me.getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertNotNull(me.getEntry());
    assertEquals(new DN(me.getEntry().getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertEquals(me.getMonitorClass(), "ds-monitor-entry");

    assertEquals(me.getMonitorName(), "foo");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 MonitorEntry.class.getName());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());
    assertEquals(me.getMonitorAttributes().get("foo").getStringValue(), "bar");
  }



  /**
   * Provides test coverage for the constructor with an entry that contains
   * multiple monitor subclasses.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorMultipleSubclasses()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: ds-bar-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: bar");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDN());
    assertEquals(new DN(me.getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertNotNull(me.getEntry());
    assertEquals(new DN(me.getEntry().getDN()),
                 new DN("cn=foo,cn=monitor"));

    assertEquals(me.getMonitorClass(), "ds-bar-monitor-entry");

    assertEquals(me.getMonitorName(), "foo");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 MonitorEntry.class.getName());

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());
    assertEquals(me.getMonitorAttributes().get("foo").getStringValue(), "bar");
  }



  /**
   * Tests the {@code getBoolean} method with a value of "true".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBooleanTrue()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: true");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getBoolean("foo"));
    assertEquals(me.getBoolean("foo"), Boolean.TRUE);
  }



  /**
   * Tests the {@code getBoolean} method with a value of "false".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBooleanFalse()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: false");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getBoolean("foo"));
    assertEquals(me.getBoolean("foo"), Boolean.FALSE);
  }



  /**
   * Tests the {@code getBoolean} method with a missing attribute.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBooleanMissing()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: true");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getBoolean("bar"));
  }



  /**
   * Tests the {@code getBoolean} method with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetBooleanInvalid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: not boolean");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getBoolean("foo"));
  }



  /**
   * Tests the {@code getDate} method with a valid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDateValid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: 20080101010101Z");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDate("foo"));
  }



  /**
   * Tests the {@code getDate} method with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDateInvalid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: invalid");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getDate("foo"));
  }



  /**
   * Tests the {@code getDate} method with a missing value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDateMissing()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: 20080101010101Z");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getDate("bar"));
  }



  /**
   * Tests the {@code getDouble} method with valid integer value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDoubleValidInteger()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: 64");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDouble("foo"));
    assertEquals(me.getDouble("foo"), Double.valueOf(64.0d));
  }



  /**
   * Tests the {@code getDouble} method with valid floating-point value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDoubleValidFloatingPoint()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: 64.5");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getDouble("foo"));
    assertEquals(me.getDouble("foo"), Double.valueOf(64.5d));
  }



  /**
   * Tests the {@code getDouble} method with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDoubleInvalid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: invalid");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getDouble("foo"));
  }



  /**
   * Tests the {@code getDouble} method with a missing value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetDoubleMissing()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getDouble("foo"));
  }



  /**
   * Tests the {@code getInteger} method with a valid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIntegerValid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: 1234");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getInteger("foo"));
    assertEquals(me.getInteger("foo"), Integer.valueOf(1234));
  }



  /**
   * Tests the {@code getInteger} method with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIntegerInvalid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: invalid");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getInteger("foo"));
  }



  /**
   * Tests the {@code getInteger} method with a missing value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetIntegerMissing()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getInteger("foo"));
  }



  /**
   * Tests the {@code getLong} method with a valid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLongValid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: 1234");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getLong("foo"));
    assertEquals(me.getLong("foo"), Long.valueOf(1234L));
  }



  /**
   * Tests the {@code getLong} method with an invalid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLongInvalid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: invalid");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getLong("foo"));
  }



  /**
   * Tests the {@code getLong} method with a missing value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetLongMissing()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getLong("foo"));
  }



  /**
   * Tests the {@code getString} method with a valid value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringValid()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: valid");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getString("foo"));
    assertEquals(me.getString("foo"), "valid");
  }



  /**
   * Tests the {@code getString} method with multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringMultiple()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: valid1",
                        "foo: valid2");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getString("foo"));
    assertEquals(me.getString("foo"), "valid1");
  }



  /**
   * Tests the {@code getString} method with a missing value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringMissing()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNull(me.getString("foo"));
  }



  /**
   * Tests the {@code getStrings} method with a single value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringsSingle()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: valid");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getStrings("foo"));
    assertEquals(me.getStrings("foo").size(), 1);
    assertEquals(me.getStrings("foo").get(0), "valid");
  }



  /**
   * Tests the {@code getStrings} method with multiple values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringsMultiple()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo",
                        "foo: valid1",
                        "foo: valid2");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getStrings("foo"));
    assertEquals(me.getStrings("foo").size(), 2);
    assertEquals(me.getStrings("foo").get(0), "valid1");
    assertEquals(me.getStrings("foo").get(1), "valid2");
  }



  /**
   * Tests the {@code getStrings} method with no values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testGetStringsNone()
         throws Exception
  {
    Entry e = new Entry("dn: cn=foo,cn=monitor",
                        "objectClass: top",
                        "objectClass: ds-monitor-entry",
                        "objectClass: ds-foo-monitor-entry",
                        "objectClass: extensibleObject",
                        "cn: foo");

    MonitorEntry me = new MonitorEntry(e);
    assertNotNull(me.toString());

    assertNotNull(me.getStrings("foo"));
    assertEquals(me.getStrings("foo").size(), 0);
  }



  /**
   * Tests the {@code addMonitorAttribute} variant that takes a Boolean value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMonitorAttributeBoolean()
         throws Exception
  {
    LinkedHashMap<String,MonitorAttribute> attrs = new
         LinkedHashMap<String,MonitorAttribute>();

    MonitorEntry.addMonitorAttribute(attrs, "name", "displayName",
                                     "description", Boolean.TRUE);

    assertFalse(attrs.isEmpty());
    assertEquals(attrs.size(), 1);

    assertNotNull(attrs.get("name"));
    assertEquals(attrs.get("name").getBooleanValue(), Boolean.TRUE);
  }



  /**
   * Tests the {@code addMonitorAttribute} variant that takes a Date value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMonitorAttributeDate()
         throws Exception
  {
    Date d = new Date();

    LinkedHashMap<String,MonitorAttribute> attrs = new
         LinkedHashMap<String,MonitorAttribute>();

    MonitorEntry.addMonitorAttribute(attrs, "name", "displayName",
                                     "description", d);

    assertFalse(attrs.isEmpty());
    assertEquals(attrs.size(), 1);

    assertNotNull(attrs.get("name"));
    assertEquals(attrs.get("name").getDateValue(), d);
  }



  /**
   * Tests the {@code addMonitorAttribute} variant that takes a Double value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMonitorAttributeDouble()
         throws Exception
  {
    LinkedHashMap<String,MonitorAttribute> attrs = new
         LinkedHashMap<String,MonitorAttribute>();

    MonitorEntry.addMonitorAttribute(attrs, "name", "displayName",
                                     "description", Double.valueOf(1.5D));

    assertFalse(attrs.isEmpty());
    assertEquals(attrs.size(), 1);

    assertNotNull(attrs.get("name"));
    assertEquals(attrs.get("name").getDoubleValue(), Double.valueOf(1.5D));
  }



  /**
   * Tests the {@code addMonitorAttribute} variant that takes a Long value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMonitorAttributeLong()
         throws Exception
  {
    LinkedHashMap<String,MonitorAttribute> attrs = new
         LinkedHashMap<String,MonitorAttribute>();

    MonitorEntry.addMonitorAttribute(attrs, "name", "displayName",
                                     "description", Long.valueOf(5L));

    assertFalse(attrs.isEmpty());
    assertEquals(attrs.size(), 1);

    assertNotNull(attrs.get("name"));
    assertEquals(attrs.get("name").getLongValue(), Long.valueOf(5L));
  }



  /**
   * Tests the {@code addMonitorAttribute} variant that takes a String value.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMonitorAttributeString()
         throws Exception
  {
    LinkedHashMap<String,MonitorAttribute> attrs = new
         LinkedHashMap<String,MonitorAttribute>();

    MonitorEntry.addMonitorAttribute(attrs, "name", "displayName",
                                     "description", "value");

    assertFalse(attrs.isEmpty());
    assertEquals(attrs.size(), 1);

    assertNotNull(attrs.get("name"));
    assertEquals(attrs.get("name").getStringValue(), "value");
  }



  /**
   * Tests the {@code addMonitorAttribute} variant that takes a list of string
   * values.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testAddMonitorAttributeStringList()
         throws Exception
  {
    LinkedHashMap<String,MonitorAttribute> attrs = new
         LinkedHashMap<String,MonitorAttribute>();

    MonitorEntry.addMonitorAttribute(attrs, "name", "displayName",
                                     "description",
                                     Arrays.asList("foo", "bar"));

    assertFalse(attrs.isEmpty());
    assertEquals(attrs.size(), 1);

    assertNotNull(attrs.get("name"));
    assertEquals(attrs.get("name").getStringValues(),
                 Arrays.asList("foo", "bar"));
  }
}
