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
package com.unboundid.ldap.sdk;



import java.util.LinkedList;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.controls.SubtreeDeleteRequestControl;



/**
 * This class provides a set of test cases for the {@code DNEntrySource} class.
 */
public final class DNEntrySourceTestCase
       extends LDAPSDKTestCase
{
  /**
   * Creates a set of test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createTestEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();

    LDAPResult r = connection.add(getTestBaseDN(), getBaseEntryAttributes());
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    r = connection.add(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectclass: organizationalUnit",
         "ou: People");
    assertEquals(r.getResultCode(), ResultCode.SUCCESS);

    for (int i=0; i < 10; i++)
    {
      r = connection.add(
           "dn: uid=user." + i + ",ou=People," + getTestBaseDN(),
           "objectClass: top",
           "objectclass: person",
           "objectclass: organizationalPerson",
           "objectclass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i,
           "userPassword: password");
      assertEquals(r.getResultCode(), ResultCode.SUCCESS);
    }

    connection.close();
  }



  /**
   * Deletes the test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void deleteTestEntries()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LDAPConnection connection = getAdminConnection();

    DeleteRequest deleteRequest = new DeleteRequest(getTestBaseDN());
    deleteRequest.addControl(new SubtreeDeleteRequestControl(true));

    assertEquals(connection.delete(deleteRequest).getResultCode(),
                 ResultCode.SUCCESS);

    connection.close();
  }



  /**
   * Tests the behavior when provided with an array of DNs.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDNArray()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    DN[] dns =
    {
      new DN(getTestBaseDN()),
      new DN("ou=People," + getTestBaseDN()),
      new DN("ou=Nonexistent," + getTestBaseDN()),
      new DN("uid=user.0,ou=People," + getTestBaseDN()),
      new DN("uid=user.1,ou=People," + getTestBaseDN()),
      new DN("uid=user.2,ou=People," + getTestBaseDN()),
      new DN("uid=user.3,ou=People," + getTestBaseDN()),
      new DN("uid=user.4,ou=People," + getTestBaseDN()),
      new DN("uid=user.5,ou=People," + getTestBaseDN()),
      new DN("uid=user.6,ou=People," + getTestBaseDN()),
      new DN("uid=user.7,ou=People," + getTestBaseDN()),
      new DN("uid=user.8,ou=People," + getTestBaseDN()),
      new DN("uid=user.9,ou=People," + getTestBaseDN()),
      new DN("uid=nonexistent,ou=People," + getTestBaseDN()),
    };

    LDAPConnection connection = getAdminConnection();


    // Test with no attributes.
    int entryCount = 0;
    int exceptionCount = 0;
    DNEntrySource entrySource = new DNEntrySource(connection, dns);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 2);
    entrySource.close();


    // Test with a null set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, (String[]) null);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 2);
    entrySource.close();


    // Test with an empty set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, new String[0]);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 2);
    entrySource.close();


    // Test with a non-empty set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, "objectClass");
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 2);
    entrySource.close();

    connection.close();
  }



  /**
   * Tests the behavior when provided with an array of Strings.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringArray()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    String[] dns =
    {
      getTestBaseDN(),
      "malformed",
      "ou=People," + getTestBaseDN(),
      "ou=Nonexistent," + getTestBaseDN(),
      "uid=user.0,ou=People," + getTestBaseDN(),
      "uid=user.1,ou=People," + getTestBaseDN(),
      "uid=user.2,ou=People," + getTestBaseDN(),
      "uid=user.3,ou=People," + getTestBaseDN(),
      "uid=user.4,ou=People," + getTestBaseDN(),
      "uid=user.5,ou=People," + getTestBaseDN(),
      "uid=user.6,ou=People," + getTestBaseDN(),
      "uid=user.7,ou=People," + getTestBaseDN(),
      "uid=user.8,ou=People," + getTestBaseDN(),
      "uid=user.9,ou=People," + getTestBaseDN(),
      "uid=nonexistent,ou=People," + getTestBaseDN(),
    };

    LDAPConnection connection = getAdminConnection();


    // Test with no attributes.
    int entryCount = 0;
    int exceptionCount = 0;
    DNEntrySource entrySource = new DNEntrySource(connection, dns);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();


    // Test with a null set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, (String[]) null);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();


    // Test with an empty set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, new String[0]);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();


    // Test with a non-empty set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, "objectClass");
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();

    connection.close();
  }



  /**
   * Tests the behavior when provided with a list of Strings.
   * <BR><BR>
   * Access to a Directory Server instance is required for complete processing.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testStringList()
         throws Exception
  {
    if (! isDirectoryInstanceAvailable())
    {
      return;
    }

    LinkedList<String> dns = new LinkedList<String>();
    dns.add(getTestBaseDN());
    dns.add("malformed");
    dns.add("ou=People," + getTestBaseDN());
    dns.add("ou=Nonexistent," + getTestBaseDN());
    dns.add("uid=user.0,ou=People," + getTestBaseDN());
    dns.add("uid=user.1,ou=People," + getTestBaseDN());
    dns.add("uid=user.2,ou=People," + getTestBaseDN());
    dns.add("uid=user.3,ou=People," + getTestBaseDN());
    dns.add("uid=user.4,ou=People," + getTestBaseDN());
    dns.add("uid=user.5,ou=People," + getTestBaseDN());
    dns.add("uid=user.6,ou=People," + getTestBaseDN());
    dns.add("uid=user.7,ou=People," + getTestBaseDN());
    dns.add("uid=user.8,ou=People," + getTestBaseDN());
    dns.add("uid=user.9,ou=People," + getTestBaseDN());
    dns.add("uid=nonexistent,ou=People," + getTestBaseDN());

    LDAPConnection connection = getAdminConnection();


    // Test with no attributes.
    int entryCount = 0;
    int exceptionCount = 0;
    DNEntrySource entrySource = new DNEntrySource(connection, dns);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();


    // Test with a null set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, (String[]) null);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();


    // Test with an empty set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, new String[0]);
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();


    // Test with a non-empty set of attributes.
    entryCount = 0;
    exceptionCount = 0;
    entrySource = new DNEntrySource(connection, dns, "objectClass");
    while (true)
    {
      try
      {
        Entry e = entrySource.nextEntry();
        if (e == null)
        {
          break;
        }
        else
        {
          entryCount++;
        }
      }
      catch (EntrySourceException e)
      {
        exceptionCount++;
      }
    }

    assertEquals(entryCount, 12);
    assertEquals(exceptionCount, 3);
    entrySource.close();

    connection.close();
  }
}
