/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.zip.GZIPOutputStream;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides a set of test cases for the password file reader class.
 */
public final class PasswordFileReaderTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the behavior when trying to read a password from a file that does not
   * exist.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testNonexistentFile()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File nonexistentFile = createTempFile();
    assertTrue(nonexistentFile.delete());

    reader.readPassword(nonexistentFile.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from a file that isn't
   * actually a file.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { IOException.class })
  public void testFileNotFile()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File f = createTempFile();
    assertTrue(f.delete());
    assertTrue(f.mkdir());

    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from a valid file that is
   * neither encrypted nor compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidUnencryptedAndUncompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File f = writeFile(null, false, "password");
    assertEquals(new String(reader.readPassword(f.getAbsolutePath())),
         "password");
    assertEquals(new String(reader.readPassword(f)),
         "password");
  }



  /**
   * Tests the behavior when trying to read a password from a valid file that is
   * encrypted but not compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEncryptedAndUncompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();
    reader.addToEncryptionPasswordCache("wrong-passphrase");
    reader.addToEncryptionPasswordCache("right-passphrase");
    reader.addToEncryptionPasswordCache("wrong-passphrase");

    final File f = writeFile("right-passphrase", false, "password");
    assertEquals(new String(reader.readPassword(f.getAbsolutePath())),
         "password");
    assertEquals(new String(reader.readPassword(f)),
         "password");

    reader.clearEncryptionPasswordCache(true);
    reader.clearEncryptionPasswordCache(false);
  }



  /**
   * Tests the behavior when trying to read a password from a valid file that is
   * compressed but not encrypted.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidUnencryptedAndCompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File f = writeFile(null, true, "password");
    assertEquals(new String(reader.readPassword(f.getAbsolutePath())),
         "password");
    assertEquals(new String(reader.readPassword(f)),
         "password");
  }



  /**
   * Tests the behavior when trying to read a password from a valid file that is
   * both encrypted and compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testValidEncryptedAndCompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();
    reader.addToEncryptionPasswordCache("wrong-passphrase");
    reader.addToEncryptionPasswordCache("right-passphrase");
    reader.addToEncryptionPasswordCache("wrong-passphrase");

    final File f = writeFile("right-passphrase", true, "password");
    assertEquals(new String(reader.readPassword(f.getAbsolutePath())),
         "password");
    assertEquals(new String(reader.readPassword(f)),
         "password");

    reader.clearEncryptionPasswordCache(true);
    reader.clearEncryptionPasswordCache(false);
  }



  /**
   * Tests the behavior when trying to read a password from an empty file that
   * is neither encrypted nor compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEmptyUnencryptedAndUncompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File f = writeFile(null, false);
    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from an empty file that
   * is both encrypted and compressed.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testEmptyEncryptedAndCompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();
    reader.addToEncryptionPasswordCache("wrong-passphrase");
    reader.addToEncryptionPasswordCache("right-passphrase");
    reader.addToEncryptionPasswordCache("wrong-passphrase");

    final File f = writeFile("right-passphrase", true);
    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from a file that contains
   * just an empty line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFileWithJustEmptyLineUnencryptedAndUncompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File f = writeFile(null, false, "");
    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from a file that contains
   * just an empty line.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testFileWithJustEmptyLineEncryptedAndCompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();
    reader.addToEncryptionPasswordCache("wrong-passphrase");
    reader.addToEncryptionPasswordCache("right-passphrase");
    reader.addToEncryptionPasswordCache("wrong-passphrase");

    final File f = writeFile("right-passphrase", true, "");
    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from a file that contains
   * multiple lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMultilineFileUnencryptedAndUncompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();

    final File f = writeFile(null, false, "line1", "line2");
    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Tests the behavior when trying to read a password from a file that contains
   * multiple lines.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test(expectedExceptions = { LDAPException.class })
  public void testMultilineFileEncryptedAndCompressed()
         throws Exception
  {
    final PasswordFileReader reader = new PasswordFileReader();
    reader.addToEncryptionPasswordCache("wrong-passphrase");
    reader.addToEncryptionPasswordCache("right-passphrase");
    reader.addToEncryptionPasswordCache("wrong-passphrase");

    final File f = writeFile("right-passphrase", true, "line1", "line2");
    reader.readPassword(f.getAbsolutePath());
  }



  /**
   * Creates a file with the provided information.
   *
   * @param  encryptionPassphrase  The passphrase used to encrypt the contents
   *                               of the file.  It may be {@code null} if the
   *                               file should not be encrypted.
   * @param  compress              Indicates whether the file should be
   *                               compressed.
   * @param  lines                 The lines to be written to the file.  It must
   *                               not be {@code null} but may be empty.
   *
   * @return  The file that was created.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  private static File writeFile(final String encryptionPassphrase,
                                final boolean compress,
                                final String... lines)
          throws Exception
  {
    final File f = createTempFile();
    assertTrue(f.delete());

    OutputStream outputStream  = new FileOutputStream(f);

    if (encryptionPassphrase != null)
    {
      outputStream = new PassphraseEncryptedOutputStream(encryptionPassphrase,
           outputStream, null, false, true);
    }

    if (compress)
    {
      outputStream = new GZIPOutputStream(outputStream);
    }

    try (PrintWriter writer = new PrintWriter(outputStream))
    {
      for (final String line : lines)
      {
        writer.println(line);
      }
    }

    return f;
  }
}
