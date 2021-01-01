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



import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;



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
         (password + StaticUtils.EOL).getBytes(StandardCharsets.UTF_8));
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
