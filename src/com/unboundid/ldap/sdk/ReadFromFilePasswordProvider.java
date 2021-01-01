/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.io.File;
import java.io.FileInputStream;
import java.util.Arrays;

import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an implementation of a password provider that will obtain
 * the password from a specified file.  All bytes up to (but not including) the
 * first end-of-line character (or to the end of the file if it does not contain
 * an end-of-line character) will be considered part of the password.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ReadFromFilePasswordProvider
       extends PasswordProvider
{
  /**
   * The serial version UID for this serializable file.
   */
  private static final long serialVersionUID = -3343425971796985100L;



  // The password file to use.
  @NotNull private final File passwordFile;



  /**
   * Creates a new instance of this password provider that will read passwords
   * from the specified file.
   *
   * @param  passwordFile  The path to the file containing the password to use.
   *                       It must not be {@code null}.
   */
  public ReadFromFilePasswordProvider(@NotNull final String passwordFile)
  {
    Validator.ensureNotNull(passwordFile);

    this.passwordFile = new File(passwordFile);
  }



  /**
   * Creates a new instance of this password provider that will read passwords
   * from the specified file.
   *
   * @param  passwordFile  The file containing the password to use.  It must not
   *                       be {@code null}.
   */
  public ReadFromFilePasswordProvider(@NotNull final File passwordFile)
  {
    Validator.ensureNotNull(passwordFile);

    this.passwordFile = passwordFile;
  }



  /**
   * Retrieves a password in a newly-created byte array.  Once the password is
   * no longer required, the contents of the array will be overwritten so that
   * the password is no longer contained in memory.
   *
   * @return  A byte array containing the password that should be used.
   *
   * @throws  LDAPException  If a problem is encountered while attempting to
   *                         obtain the password.
   */
  @Override()
  @NotNull()
  public byte[] getPasswordBytes()
         throws LDAPException
  {
    byte[] pwBytes = null;

    try
    {
      final int fileLength = (int) passwordFile.length();
      pwBytes = new byte[fileLength];

      final FileInputStream inputStream = new FileInputStream(passwordFile);

      try
      {
        int pos = 0;
        while (pos < fileLength)
        {
          final int bytesRead =
               inputStream.read(pwBytes, pos, pwBytes.length - pos);
          if (bytesRead < 0)
          {
            break;
          }

          pos += bytesRead;
        }
      }
      finally
      {
        inputStream.close();
      }

      // If there is an end-of-line marker before the end of the file, then
      // create a password only up to that point and zero out the current array.
      for (int i=0; i < pwBytes.length; i++)
      {
        if ((pwBytes[i] == '\n') || (pwBytes[i] == '\r'))
        {
          final byte[] pwWithoutEOL = new byte[i];
          System.arraycopy(pwBytes, 0, pwWithoutEOL, 0, i);
          Arrays.fill(pwBytes, (byte) 0x00);
          pwBytes = pwWithoutEOL;
          break;
        }
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (pwBytes != null)
      {
        Arrays.fill(pwBytes, (byte) 0x00);
      }

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_FILE_PW_PROVIDER_ERROR_READING_PW.get(
                passwordFile.getAbsolutePath(),
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    if (pwBytes.length == 0)
    {
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_FILE_PW_PROVIDER_EMPTY_PW.get(passwordFile.getAbsolutePath()));
    }

    return pwBytes;
  }
}
