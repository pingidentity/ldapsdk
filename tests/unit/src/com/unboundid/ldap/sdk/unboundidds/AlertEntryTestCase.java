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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.Date;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.util.StaticUtils;



/**
 * This class provides a set of test cases for the AlertEntry class.
 */
public class AlertEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the ability to parse a valid entry with all appropriate information.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFullEntry()
         throws Exception
  {
    Date d = new Date();

    Entry entry = new Entry(
         "dn: ds-alert-id=01234567-0123-0123-0123-012345678901,cn=alerts",
         "objectClass: top",
         "objectClass: ds-admin-alert",
         "ds-alert-id: 01234567-0123-0123-0123-012345678901",
         "ds-alert-type: server-started",
         "ds-alert-severity: info",
         "ds-alert-type-oid: 1.3.6.1.4.1.30221.2.11.33",
         "ds-alert-time: " + StaticUtils.encodeGeneralizedTime(d),
         "ds-alert-generator: com.unboundid.directory.server.core." +
              "DirectoryServer",
         "ds-alert-message: The Directory Server has started successfully");

    AlertEntry e = new AlertEntry(entry);
    assertNotNull(e);

    assertNotNull(e.getAlertGeneratorClass());
    assertEquals(e.getAlertGeneratorClass(),
                 "com.unboundid.directory.server.core.DirectoryServer");

    assertNotNull(e.getAlertID());
    assertEquals(e.getAlertID(), "01234567-0123-0123-0123-012345678901");

    assertNotNull(e.getAlertMessage());
    assertEquals(e.getAlertMessage(),
                 "The Directory Server has started successfully");

    assertNotNull(e.getAlertSeverity());
    assertEquals(e.getAlertSeverity(), AlertSeverity.INFO);

    assertNotNull(e.getAlertTime());
    assertEquals(e.getAlertTime(), d);

    assertNotNull(e.getAlertType());
    assertEquals(e.getAlertType(), "server-started");

    assertNotNull(e.getAlertTypeOID());
    assertEquals(e.getAlertTypeOID(), "1.3.6.1.4.1.30221.2.11.33");
  }



  /**
   * Tests the ability to parse a valid entry with invalid values for some
   * attributes.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testInvalidEntry()
         throws Exception
  {
    Date d = new Date();

    Entry entry = new Entry(
         "dn: ds-alert-id=01234567-0123-0123-0123-012345678901,cn=alerts",
         "objectClass: top",
         "objectClass: ds-admin-alert",
         "ds-alert-id: 01234567-0123-0123-0123-012345678901",
         "ds-alert-type: server-started",
         "ds-alert-severity: invalid",
         "ds-alert-type-oid: 1.3.6.1.4.1.30221.2.11.33",
         "ds-alert-time: invalid",
         "ds-alert-generator: com.unboundid.directory.server.core." +
              "DirectoryServer",
         "ds-alert-message: The Directory Server has started successfully");

    AlertEntry e = new AlertEntry(entry);
    assertNotNull(e);

    assertNotNull(e.getAlertGeneratorClass());
    assertEquals(e.getAlertGeneratorClass(),
                 "com.unboundid.directory.server.core.DirectoryServer");

    assertNotNull(e.getAlertID());
    assertEquals(e.getAlertID(), "01234567-0123-0123-0123-012345678901");

    assertNotNull(e.getAlertMessage());
    assertEquals(e.getAlertMessage(),
                 "The Directory Server has started successfully");

    assertNull(e.getAlertSeverity());

    assertNull(e.getAlertTime());

    assertNotNull(e.getAlertType());
    assertEquals(e.getAlertType(), "server-started");

    assertNotNull(e.getAlertTypeOID());
    assertEquals(e.getAlertTypeOID(), "1.3.6.1.4.1.30221.2.11.33");
  }



  /**
   * Tests the ability to parse an entry that does not represent a valid alert
   * notification.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testNotAlertEntry()
         throws Exception
  {
    Entry entry = new Entry(
         "dn: dc=example,dc=com",
         "objectClass: top",
         "objectClass: domain",
         "dc: example");

    AlertEntry e = new AlertEntry(entry);
    assertNotNull(e);

    assertNull(e.getAlertGeneratorClass());

    assertNull(e.getAlertID());

    assertNull(e.getAlertMessage());

    assertNull(e.getAlertSeverity());

    assertNull(e.getAlertTime());

    assertNull(e.getAlertType());

    assertNull(e.getAlertTypeOID());
  }
}
