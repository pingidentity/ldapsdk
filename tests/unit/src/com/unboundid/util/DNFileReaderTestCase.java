/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.util;



import java.io.File;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;
import com.unboundid.ldap.sdk.ResultCode;



/**
 * This class provides a set of test cases for the DN file reader.
 */
public final class DNFileReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when reading an empty file when providing the path as a
   * string.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testPathToEmptyFile()
         throws Exception
  {
    final File f = createTempFile();

    final DNFileReader r = new DNFileReader(f.getAbsolutePath());
    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only blank lines and
   * comments.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithOnlyBlankLinesAndComments()
         throws Exception
  {
    final File f = createTempFile(
         "# This is a comment",
         "",
         "# The above was a blank line",
         "# The below is also a blank line",
         "",
         "# And the file ends with a blank line",
         "");

    final DNFileReader r = new DNFileReader(f);
    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single valid DN
   * with no prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleValidRawDN()
         throws Exception
  {
    final File f = createTempFile("dc=example,dc=com");

    final DNFileReader r = new DNFileReader(f);

    final DN dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("dc=example,dc=com"));

    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single valid DN
   * prefixed with "dn:".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleValidRawDNWithPrefix()
         throws Exception
  {
    final File f = createTempFile("dn: dc=example,dc=com");

    final DNFileReader r = new DNFileReader(f);

    final DN dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("dc=example,dc=com"));

    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single valid
   * base64-encoded DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleValidBase64DN()
         throws Exception
  {
    final File f = createTempFile("dn:: " + Base64.encode("dc=example,dc=com"));

    final DNFileReader r = new DNFileReader(f);

    final DN dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("dc=example,dc=com"));

    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single invalid DN
   * with no prefix.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleInvalidRawDN()
         throws Exception
  {
    final File f = createTempFile("invalid DN");

    final DNFileReader r = new DNFileReader(f);

    try
    {
      final DN dn = r.readDN();
      fail("Expected an exception when trying to read an invalid DN, " +
           "but read " + dn);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single invalid DN
   * prefixed with "dn:".
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleInvalidRawDNWithPrefix()
         throws Exception
  {
    final File f = createTempFile("dn: invalid DN");

    final DNFileReader r = new DNFileReader(f);

    try
    {
      final DN dn = r.readDN();
      fail("Expected an exception when trying to read an invalid DN, " +
           "but read " + dn);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when reading a file containing only a single invalid
   * base64-encoded DN.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testFileWithSingleInvalidBase64DN()
         throws Exception
  {
    final File f = createTempFile("dn:: " + Base64.encode("invalid DN"));

    final DNFileReader r = new DNFileReader(f);

    try
    {
      final DN dn = r.readDN();
      fail("Expected an exception when trying to read an invalid DN, " +
           "but read " + dn);
    }
    catch (final LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    assertNull(r.readDN());
    r.close();
  }



  /**
   * Tests the behavior when trying to read from a file with a mix of valid and
   * invalid DNs, and also containing comments and blank lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testReadFileWithMultipleValidAndInvalidDNs()
         throws Exception
  {
    final File f = createTempFile(
         "",
         "# A comment before a valid DN",
         "ou=valid 1,dc=example,dc=com",
         "",
         "# A comment before an invalid DN",
         "dn:invalid 1",
         "",
         "# Another couple of valid DNs and then an invalid one",
         "dn:ou=valid 2,dc=example,dc=com",
         "dn::" + Base64.encode("ou=valid 3,dc=example,dc=com"),
         " ou=valid 4, dc=example, dc=com ",
         "dn::invalid 2",
         "",
         "",
         "",
         "#",
         "# One more valid DN",
         "#",
         "dn:     ou=valid 5,dc=example,dc=com",
         "");

    final DNFileReader r = new DNFileReader(f);

    DN dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("ou=valid 1,dc=example,dc=com"));

    try
    {
      dn = r.readDN();
      fail("Expected an exception when trying to read an invalid DN, " +
           "but read " + dn);
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.INVALID_DN_SYNTAX);
    }

    dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("ou=valid 2,dc=example,dc=com"));

    dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("ou=valid 3,dc=example,dc=com"));

    dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("ou=valid 4,dc=example,dc=com"));

    try
    {
      dn = r.readDN();
      fail("Expected an exception when trying to read an invalid DN, " +
           "but read " + dn);
    }
    catch (LDAPException le)
    {
      assertEquals(le.getResultCode(), ResultCode.DECODING_ERROR);
    }

    dn = r.readDN();
    assertNotNull(dn);
    assertEquals(dn, new DN("ou=valid 5,dc=example,dc=com"));

    assertNull(r.readDN());
    r.close();
  }
}
