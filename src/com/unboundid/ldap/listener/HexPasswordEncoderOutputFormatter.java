/*
 * Copyright 2017-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2025 Ping Identity Corporation
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
 * Copyright (C) 2017-2025 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of a password encoder output formatter
 * that will use hexadecimal digits to represent the bytes of the encoded
 * password.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class HexPasswordEncoderOutputFormatter
       extends PasswordEncoderOutputFormatter
{
  /**
   * The singleton instance of this hex password encoder output formatter that
   * uses lowercase versions of the hexadecimal digits 'a' through 'f'.
   */
  @NotNull private static final HexPasswordEncoderOutputFormatter
       LOWERCASE_INSTANCE = new HexPasswordEncoderOutputFormatter(true);



  /**
   * The singleton instance of this hex password encoder output formatter that
   * uses uppercase versions of the hexadecimal digits 'A' through 'F'.
   */
  @NotNull private static final HexPasswordEncoderOutputFormatter
       UPPERCASE_INSTANCE = new HexPasswordEncoderOutputFormatter(false);



  // Indicates whether to use lowercase letters for hexadecimal digits 'A'
  // through 'F'.
  private final boolean useLowercaseLetters;



  /**
   * Creates an instance of this hex password encoder output formatter with the
   * specified configuration.
   *
   * @param  useLowercaseLetters Indicates whether the hexadecimal digits 'A'
   *                             through 'F' should be output as lowercase
   *                             letters (if {@code true} or as uppercase
   *                             letters (if {@code false}).
   */
  private HexPasswordEncoderOutputFormatter(final boolean useLowercaseLetters)
  {
    this.useLowercaseLetters = useLowercaseLetters;
  }



  /**
   * Retrieves a singleton instance of this hex password encoder that will
   * represent the hexadecimal digits 'A' through 'F' as lowercase letters.
   *
   * @return  The hex password encoder instance.
   */
  @NotNull()
  public static HexPasswordEncoderOutputFormatter getLowercaseInstance()
  {
    return LOWERCASE_INSTANCE;
  }



  /**
   * Retrieves a singleton instance of this hex password encoder that will
   * represent the hexadecimal digits 'A' through 'F' as uppercase letters.
   *
   * @return  The hex password encoder instance.
   */
  @NotNull()
  public static HexPasswordEncoderOutputFormatter getUppercaseInstance()
  {
    return UPPERCASE_INSTANCE;
  }



  /**
   * Indicates whether to represent the hexadecimal digits 'A' through 'F' as
   * lowercase letters or uppercase letters.  Note that this setting only
   * applies when formatting an encoded password.  When un-formatting a
   * password, either uppercase or lowercase letters will be properly handled.
   *
   * @return  {@code true} if hexadecimal digits 'A' through 'F' should be
   *          represented as lowercase letters, or {@code false} if they should
   *          be represented as uppercase letters.
   */
  public boolean useLowercaseLetters()
  {
    return useLowercaseLetters;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public byte[] format(@NotNull final byte[] unformattedData)
         throws LDAPException
  {
    String hexString = StaticUtils.toHex(unformattedData);
    if (! useLowercaseLetters)
    {
      hexString = hexString.toUpperCase();
    }

    return StaticUtils.getBytes(hexString);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public byte[] unFormat(@NotNull final byte[] formattedData)
         throws LDAPException
  {
    try
    {
      return StaticUtils.fromHex(StaticUtils.toUTF8String(formattedData));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_HEX_PW_FORMATTER_CANNOT_DECODE.get(), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("HexPasswordEncoderOutputFormatter(useLowercaseLetters=");
    buffer.append(useLowercaseLetters);
    buffer.append(')');
  }
}
