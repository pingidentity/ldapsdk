/*
 * Copyright 2016-2017 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2017 Ping Identity Corporation
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
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;



/**
 * This class provides a helper class that can be used to allow the password
 * reader to obtain the password from somewhere other than standard input.
 */
public final class PasswordReaderHelper
{
  /**
   * Updates the password reader to read the specified string as a password.
   *
   * @param  password  The password to be read.
   */
  public static void setTestPasswordReader(final String password)
  {
    final ByteArrayInputStream in = new ByteArrayInputStream(
         (password + StaticUtils.EOL).getBytes());
    setTestPasswordReader(new BufferedReader(new InputStreamReader(in)));
  }



  /**
   * Updates the password reader to read a password from the provided reader.
   *
   * @param  reader  The reader from which the password should be read.
   */
  public static void setTestPasswordReader(final BufferedReader reader)
  {
    PasswordReader.setTestReader(reader);
  }



  /**
   * Updates the password reader so that it will try to obtain passwords from
   * standard input.
   */
  public static void resetTestPasswordReader()
  {
    PasswordReader.setTestReader(null);
  }
}
