/*
 * Copyright 2013-2019 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2019 Ping Identity Corporation
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
import java.text.ParseException;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class is primarily intended to ensure that code provided in javadoc
 * examples is valid.
 */
public final class ExampleUsagesTestCase
       extends LDAPSDKTestCase
{
  /**
   * Tests the example in the {@code Base32} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBase32Example()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final byte[] rawDataBytes = "test".getBytes("UTF-8");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Base32-encode some raw data:
    String base32String = Base32.encode(rawDataBytes);

    // Decode a base32 string back to raw data:
    byte[] decodedRawDataBytes;
    try
    {
      decodedRawDataBytes = Base32.decode(base32String);
    }
    catch (ParseException pe)
    {
      // The string did not represent a valid base32 encoding.
      decodedRawDataBytes = null;
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertEquals(decodedRawDataBytes, rawDataBytes);
  }



  /**
   * Tests the example in the {@code Base64} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testBase64Example()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final byte[] rawDataBytes = "test".getBytes("UTF-8");


    /* ----- BEGIN EXAMPLE CODE ----- */
    // Base64-encode some raw data:
    String base64String = Base64.encode(rawDataBytes);

    // Decode a base64 string back to raw data:
    byte[] decodedRawDataBytes;
    try
    {
      decodedRawDataBytes = Base64.decode(base64String);
    }
    catch (ParseException pe)
    {
      // The string did not represent a valid base64 encoding.
      decodedRawDataBytes = null;
    }
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    assertEquals(decodedRawDataBytes, rawDataBytes);
  }



  /**
   * Tests the example in the {@code Debug} class.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testDebugExample()
         throws Exception
  {
    /* ----- BEGIN PRE-EXAMPLE SETUP ----- */
    final File logFile = createTempFile();
    assertTrue(logFile.delete());
    final String logFilePath = logFile.getAbsolutePath();


    /* ----- BEGIN EXAMPLE CODE ----- */
    Debug.setEnabled(true);
    Logger logger = Debug.getLogger();

    FileHandler fileHandler = new FileHandler(logFilePath);
    fileHandler.setLevel(Level.WARNING);
    logger.addHandler(fileHandler);
    /* ----- END EXAMPLE CODE ----- */


    /* ----- BEGIN POST-EXAMPLE CLEANUP ----- */
    Debug.setEnabled(false);
    logger.removeHandler(fileHandler);
  }
}
