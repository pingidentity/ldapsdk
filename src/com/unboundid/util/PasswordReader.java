/*
 * Copyright 2013-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2018 Ping Identity Corporation
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



import java.io.BufferedReader;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;

import static com.unboundid.util.UtilityMessages.*;



/**
 * This class provides a mechanism for reading a password from the command line
 * in a way that attempts to prevent it from being displayed.  If it is
 * available (i.e., Java SE 6 or later), the
 * {@code java.io.Console.readPassword} method will be used to accomplish this.
 * For Java SE 5 clients, a more primitive approach must be taken, which
 * requires flooding standard output with backspace characters using a
 * high-priority thread.  This has only a limited effectiveness, but it is the
 * best option available for older Java versions.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordReader
       extends Thread
{
  /**
   * The input stream from which to read the password.  This should only be set
   * when running unit tests.
   */
  private static volatile BufferedReader TEST_READER = null;



  // Indicates whether a request has been made for the backspace thread to
  // stop running.
  private final AtomicBoolean stopRequested;

  // An object that will be used to wait for the reader thread to be started.
  private final Object startMutex;



  /**
   * Creates a new instance of this password reader thread.
   */
  private PasswordReader()
  {
    startMutex = new Object();
    stopRequested = new AtomicBoolean(false);

    setName("Password Reader Thread");
    setDaemon(true);
    setPriority(Thread.MAX_PRIORITY);
  }



  /**
   * Reads a password from the console as a character array.
   *
   * @return  The characters that comprise the password that was read.
   *
   * @throws  LDAPException  If a problem is encountered while trying to read
   *                         the password.
   */
  public static char[] readPasswordChars()
         throws LDAPException
  {
    // If an input stream is available, then read the password from it.
    final BufferedReader testReader = TEST_READER;
    if (testReader != null)
    {
      try
      {
        return testReader.readLine().toCharArray();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_PW_READER_FAILURE.get(StaticUtils.getExceptionMessage(e)),
             e);
      }
    }

    return System.console().readPassword();
  }



  /**
   * Reads a password from the console as a byte array.
   *
   * @return  The characters that comprise the password that was read.
   *
   * @throws  LDAPException  If a problem is encountered while trying to read
   *                         the password.
   */
  public static byte[] readPassword()
         throws LDAPException
  {
    // Get the characters that make up the password.
    final char[] pwChars = readPasswordChars();

    // Convert the password to bytes.
    final ByteStringBuffer buffer = new ByteStringBuffer();
    buffer.append(pwChars);
    Arrays.fill(pwChars, '\u0000');
    final byte[] pwBytes = buffer.toByteArray();
    buffer.clear(true);
    return pwBytes;
  }



  /**
   * Repeatedly sends backspace and space characters to standard output in an
   * attempt to try to hide what the user enters.
   */
  @Override()
  public void run()
  {
    synchronized (startMutex)
    {
      startMutex.notifyAll();
    }

    while (! stopRequested.get())
    {
      System.out.print("\u0008 ");
      yield();
    }
  }



  /**
   * Specifies the input stream from which to read the password.  This should
   * only be set when running unit tests.
   *
   * @param  reader  The input stream from which to read the password.  It may
   *                 be {@code null} to obtain the password from the normal
   *                 means.
   */
  @InternalUseOnly()
  public static void setTestReader(final BufferedReader reader)
  {
    TEST_READER = reader;
  }
}
