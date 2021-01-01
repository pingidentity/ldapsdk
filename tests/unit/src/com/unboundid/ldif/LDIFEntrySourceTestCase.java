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
package com.unboundid.ldif;



import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;

import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.EntrySourceException;
import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.TestInputStream;



/**
 * This class provides a set of test cases for the LDIFEntrySource class.
 */
public class LDIFEntrySourceTestCase
       extends LDIFTestCase
{
  // The LDIF file to use for testing.
  private File ldifFile;



  /**
   * Creates an LDIF file with a set of test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @BeforeClass()
  public void createTestEntries()
         throws Exception
  {
    ldifFile = createTempFile();

    LDIFWriter writer = new LDIFWriter(ldifFile);

    writer.writeEntry(new Entry(getTestBaseDN(), getBaseEntryAttributes()));

    writer.writeEntry(new Entry(
         "dn: ou=People," + getTestBaseDN(),
         "objectClass: top",
         "objectclass: organizationalUnit",
         "ou: People"));

    for (int i=0; i < 250; i++)
    {
      writer.writeEntry(new Entry(
           "dn: uid=user." + i + ",ou=People," + getTestBaseDN(),
           "objectClass: top",
           "objectclass: person",
           "objectclass: organizationalPerson",
           "objectclass: inetOrgPerson",
           "uid: user." + i,
           "givenName: User",
           "sn: " + i,
           "cn: User " + i,
           "userPassword: password"));
    }

    writer.close();
  }



  /**
   * Deletes the file containing the test entries.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @AfterClass()
  public void deleteTestEntries()
         throws Exception
  {
    ldifFile.delete();
  }



  /**
   * Reads through all of the entries in the test file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadAll()
         throws Exception
  {
    LDIFEntrySource s = new LDIFEntrySource(new LDIFReader(ldifFile));

    int count = 0;
    while (true)
    {
      Entry e = s.nextEntry();
      if (e == null)
      {
        break;
      }

      count++;
    }

    assertEquals(count, 252);

    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }
  }



  /**
   * Reads through only some of the entries in the test file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadPartial()
         throws Exception
  {
    LDIFEntrySource s = new LDIFEntrySource(new LDIFReader(ldifFile));

    assertNotNull(s.nextEntry());

    s.close();
    for (int i=0; i < 10; i++)
    {
      assertNull(s.nextEntry());
    }
  }



  /**
   * Tests with a file containing invalid LDIF in which it should be possible
   * to continue reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { EntrySourceException.class })
  public void testInvalidLDIFCanKeepReading()
         throws Exception
  {
    File f = createTempFile("this isn't valid LDIF");
    LDIFEntrySource s = new LDIFEntrySource(new LDIFReader(f));

    try
    {
      s.nextEntry();
    }
    finally
    {
      s.close();
    }
  }



  /**
   * Tests with a file containing invalid LDIF in which it should not be
   * possible to continue reading.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { EntrySourceException.class })
  public void testInvalidLDIFCanNotKeepReading()
         throws Exception
  {
    File f = createTempFile(" The leading space is a problem");
    LDIFEntrySource s = new LDIFEntrySource(new LDIFReader(f));

    try
    {
      s.nextEntry();
    }
    finally
    {
      s.close();
    }
  }



  /**
   * Tests with an LDIF reader that will always throw an I/O exception.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { EntrySourceException.class })
  public void testReaderThrowsIOException()
         throws Exception
  {
    InputStream is = new TestInputStream(new FileInputStream(ldifFile),
                                        new IOException(), 0, true);
    LDIFEntrySource s = new LDIFEntrySource(new LDIFReader(is));

    try
    {
      s.nextEntry();
    }
    finally
    {
      s.close();
    }
  }



  /**
   * Tests with a {@code null} LDIF reader.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPSDKUsageException.class })
  public void testNullReader()
         throws Exception
  {
    new LDIFEntrySource(null);
  }
}
