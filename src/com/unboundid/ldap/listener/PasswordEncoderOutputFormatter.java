/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.listener;



import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Extensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class defines an API that may be used to format and un-format encoded
 * passwords for use with the in-memory directory server.
 */
@Extensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class PasswordEncoderOutputFormatter
{
  /**
   * Formats the provided data in accordance with this output format.
   *
   * @param  unformattedData  The data to be formatted.  It must not be
   *                          {@code null}.
   *
   * @return  A formatted representation of the provided data.
   *
   * @throws  LDAPException  If a problem is encountered while formatting the
   *                         provided data.
   */
  @NotNull()
  public abstract byte[] format(@NotNull byte[] unformattedData)
         throws LDAPException;



  /**
   * Reverses the formatting that has been applied to the provided data.
   *
   * @param  formattedData  The formatted data to be un-formatted.  It must not
   *                        be {@code null}.
   *
   * @return  The un-formatted version of the provided data.
   *
   * @throws  LDAPException  If the provided data does not represent a valid
   *                         encoding, or if a problem is encountered while
   *                         un-formatting the provided data.
   */
  @NotNull()
  public abstract byte[] unFormat(@NotNull byte[] formattedData)
         throws LDAPException;



  /**
   * Retrieves a string representation of this password encoder output
   * formatter.
   *
   * @return  A string representation of this password encoder output formatter.
   */
  @Override()
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this password encoder output formatter
   * to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);
}
