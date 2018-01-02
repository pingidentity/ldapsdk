/*
 * Copyright 2017-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2017-2018 Ping Identity Corporation
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
import com.unboundid.util.Base64;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.listener.ListenerMessages.*;



/**
 * This class provides an implementation of a password encoder output formatter
 * that will format the encoded password using the base64 mechanism described in
 * <A HREF="http://www.ietf.org/rfc/rfc4648.txt">RFC 4648</A>.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class Base64PasswordEncoderOutputFormatter
       extends PasswordEncoderOutputFormatter
{
  /**
   * The singleton instance of this base64 password encoder output formatter.
   */
  private static final Base64PasswordEncoderOutputFormatter INSTANCE =
       new Base64PasswordEncoderOutputFormatter();



  /**
   * Creates an instance of this base64 password encoder output formatter.
   */
  private Base64PasswordEncoderOutputFormatter()
  {
    // No implementation is required.
  }



  /**
   * Retrieves the singleton instance of this base64 password encoder output
   * formatter.
   *
   * @return  The singleton instance of this base64 password encoder output
   *          formatter.
   */
  public static Base64PasswordEncoderOutputFormatter getInstance()
  {
    return INSTANCE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte[] format(final byte[] unformattedData)
         throws LDAPException
  {
    return StaticUtils.getBytes(Base64.encode(unformattedData));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public byte[] unFormat(final byte[] formattedData)
         throws LDAPException
  {
    try
    {
      return Base64.decode(StaticUtils.toUTF8String(formattedData));
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_BASE64_PW_FORMATTER_CANNOT_DECODE.get(), e);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("Base64PasswordEncoderOutputFormatter()");
  }
}
