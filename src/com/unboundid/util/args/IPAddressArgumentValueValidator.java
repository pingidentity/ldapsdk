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
package com.unboundid.util.args;



import java.io.Serializable;

import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that
 * ensures that values can be parsed as valid IPv4 or IPV6 addresses.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class IPAddressArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3923873375428600467L;



  // Indicates whether to accept IPv4 addresses.
  private final boolean acceptIPv4Addresses;

  // Indicates whether to accept IPv6 addresses.
  private final boolean acceptIPv6Addresses;



  /**
   * Creates a new IP address argument value validator that will accept both
   * IPv4 and IPv6 addresses.
   */
  public IPAddressArgumentValueValidator()
  {
    this(true, true);
  }



  /**
   * Creates a new IP address argument value validator that will accept both
   * IPv4 and IPv6 addresses.  At least one of the {@code acceptIPv4Addresses}
   * and {@code acceptIPv6Addresses} arguments must have a value of
   * {@code true}.
   *
   * @param  acceptIPv4Addresses  Indicates whether IPv4 addresses will be
   *                              accepted.  If this is {@code false}, then the
   *                              {@code acceptIPv6Addresses} argument must be
   *                              {@code true}.
   * @param  acceptIPv6Addresses  Indicates whether IPv6 addresses will be
   *                              accepted.  If this is {@code false}, then the
   *                              {@code acceptIPv4Addresses} argument must be
   *                              {@code true}.
   */
  public IPAddressArgumentValueValidator(final boolean acceptIPv4Addresses,
                                         final boolean acceptIPv6Addresses)
  {
    Validator.ensureTrue(acceptIPv4Addresses || acceptIPv6Addresses,
         "One or both of the acceptIPv4Addresses and acceptIPv6Addresses " +
              "arguments must have a value of 'true'.");

    this.acceptIPv4Addresses = acceptIPv4Addresses;
    this.acceptIPv6Addresses = acceptIPv6Addresses;
  }



  /**
   * Indicates whether to accept IPv4 addresses.
   *
   * @return  {@code true} if IPv4 addresses should be accepted, or
   *          {@code false} if not.
   */
  public boolean acceptIPv4Addresses()
  {
    return acceptIPv4Addresses;
  }



  /**
   * Indicates whether to accept IPv6 addresses.
   *
   * @return  {@code true} if IPv6 addresses should be accepted, or
   *          {@code false} if not.
   */
  public boolean acceptIPv6Addresses()
  {
    return acceptIPv6Addresses;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    // Look at the provided value to determine whether it has any colons.  If
    // so, then we'll assume that it's an IPv6 address and we can ensure that
    // it is only comprised of colons, periods (in case it ends with an IPv4
    // address), and hexadecimal digits.  If it doesn't have any colons but it
    // does have one or more periods, then assume that it's an IPv4 address and
    // ensure that it is only comprised of base-10 digits and periods.  This
    // initial examination will only perform a very coarse validation.
    final boolean isIPv6 = (valueString.indexOf(':') >= 0);
    if (isIPv6)
    {
      for (final char c : valueString.toCharArray())
      {
        if ((c == ':') || (c == '.') || ((c >= '0') && (c <= '9')) ||
             ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')))
        {
          // This character is allowed in an IPv6 address.
        }
        else
        {
          throw new ArgumentException(ERR_IP_VALIDATOR_ILLEGAL_IPV6_CHAR.get(
               valueString, argument.getIdentifierString(), c));
        }
      }
    }
    else if (valueString.indexOf('.') >= 0)
    {
      for (final char c : valueString.toCharArray())
      {
        if ((c == '.') || ((c >= '0') && (c <= '9')))
        {
          // This character is allowed in an IPv4 address.
        }
        else
        {
          throw new ArgumentException(ERR_IP_VALIDATOR_ILLEGAL_IPV4_CHAR.get(
               valueString, argument.getIdentifierString(), c));
        }
      }
    }
    else
    {
      throw new ArgumentException(ERR_IP_VALIDATOR_MALFORMED.get(valueString,
           argument.getIdentifierString()));
    }


    // If we've gotten here, then we know that the value string contains only
    // characters that are allowed in IP address literal.  Let
    // InetAddress.getByName do the heavy lifting for the rest of the
    // validation.
    try
    {
      LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.getByName(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_IP_VALIDATOR_MALFORMED.get(valueString,
                argument.getIdentifierString()),
           e);
    }


    if (isIPv6)
    {
      if (! acceptIPv6Addresses)
      {
        throw new ArgumentException(ERR_IP_VALIDATOR_IPV6_NOT_ACCEPTED.get(
             valueString, argument.getIdentifierString()));
      }
    }
    else if (! acceptIPv4Addresses)
    {
      throw new ArgumentException(ERR_IP_VALIDATOR_IPV4_NOT_ACCEPTED.get(
           valueString, argument.getIdentifierString()));
    }
  }



  /**
   * Indicates whether the provided string represents a valid IPv4 or IPv6
   * address.
   *
   * @param  s  The string for which to make the determination.
   *
   * @return  {@code true} if the provided string represents a valid IPv4 or
   *          IPv6 address, or {@code false} if not.
   */
  public static boolean isValidNumericIPAddress(@Nullable final String s)
  {
    return isValidNumericIPv4Address(s) ||
         isValidNumericIPv6Address(s);
  }



  /**
   * Indicates whether the provided string is a valid IPv4 address.
   *
   * @param  s  The string for which to make the determination.
   *
   * @return  {@code true} if the provided string represents a valid IPv4
   *          address, or {@code false} if not.
   */
  public static boolean isValidNumericIPv4Address(@Nullable final String s)
  {
    if ((s == null) || (s.length() == 0))
    {
      return false;
    }

    for (final char c : s.toCharArray())
    {
      if ((c == '.') || ((c >= '0') && (c <= '9')))
      {
        // This character is allowed in an IPv4 address.
      }
      else
      {
        return false;
      }
    }

    try
    {
      LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.getByName(s);
      return true;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }
  }



  /**
   * Indicates whether the provided string is a valid IPv6 address.
   *
   * @param  s  The string for which to make the determination.
   *
   * @return  {@code true} if the provided string represents a valid IPv6
   *          address, or {@code false} if not.
   */
  public static boolean isValidNumericIPv6Address(@Nullable final String s)
  {
    if ((s == null) || (s.length() == 0))
    {
      return false;
    }

    boolean colonFound = false;
    for (final char c : s.toCharArray())
    {
      if (c == ':')
      {
        // This character is allowed in an IPv6 address, and you can't have a
        // valid IPv6 address without colons.
        colonFound = true;
      }
      else if ((c == '.') || ((c >= '0') && (c <= '9')) ||
           ((c >= 'a') && (c <= 'f')) || ((c >= 'A') && (c <= 'F')))
      {
        // This character is allowed in an IPv6 address.
      }
      else
      {
        return false;
      }
    }

    if (colonFound)
    {
      try
      {
        LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.getByName(s);
        return true;
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return false;
  }



  /**
   * Retrieves a string representation of this argument value validator.
   *
   * @return  A string representation of this argument value validator.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this argument value validator to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull  final StringBuilder buffer)
  {
    buffer.append("IPAddressArgumentValueValidator(acceptIPv4Addresses=");
    buffer.append(acceptIPv4Addresses);
    buffer.append(", acceptIPv6Addresses=");
    buffer.append(acceptIPv6Addresses);
    buffer.append(')');
  }
}
