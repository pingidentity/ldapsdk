/*
 * Copyright 2013-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2013-2014 UnboundID Corp.
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



import java.lang.reflect.Method;
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
   * Reads a password from the console.
   *
   * @return  The characters that comprise the password that was read.
   *
   * @throws  LDAPException  If a problem is encountered while trying to read
   *                         the password.
   */
  public static byte[] readPassword()
         throws LDAPException
  {
    // Try to use the Java SE 6 approach first.
    try
    {
      final Method consoleMethod = System.class.getMethod("console");
      final Object consoleObject = consoleMethod.invoke(null);

      final Method readPasswordMethod =
        consoleObject.getClass().getMethod("readPassword");
      final char[] pwChars = (char[]) readPasswordMethod.invoke(consoleObject);

      final ByteStringBuffer buffer = new ByteStringBuffer();
      buffer.append(pwChars);
      Arrays.fill(pwChars, '\u0000');
      final byte[] pwBytes = buffer.toByteArray();
      buffer.clear(true);
      return pwBytes;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    // Fall back to the an approach that should work with Java SE 5.
    try
    {
      final PasswordReader r = new PasswordReader();
      try
      {
        synchronized (r.startMutex)
        {
          r.start();
          r.startMutex.wait();
        }

        // NOTE:  0x0A is '\n' and 0x0D is '\r'.
        final ByteStringBuffer buffer = new ByteStringBuffer();
        while (true)
        {
          final int byteRead = System.in.read();
          if ((byteRead < 0) || (byteRead == 0x0A))
          {
            // This is the end of the value, as indicated by a UNIX line
            // terminator sequence.
            break;
          }
          else if (byteRead == 0x0D)
          {
            final int nextCharacter = System.in.read();
            if ((nextCharacter < 0) || (byteRead == 0x0A))
            {
              // This is the end of the value as indicated by a Windows line
              // terminator sequence.
              break;
            }
            else
            {
              buffer.append((byte) byteRead);
              buffer.append((byte) nextCharacter);
            }
          }
          else
          {
            buffer.append((byte) byteRead);
          }
        }

        final byte[] pwBytes = buffer.toByteArray();
        buffer.clear(true);
        return pwBytes;
      }
      finally
      {
        r.stopRequested.set(true);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_PW_READER_FAILURE.get(StaticUtils.getExceptionMessage(e)),
           e);
    }
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
}
