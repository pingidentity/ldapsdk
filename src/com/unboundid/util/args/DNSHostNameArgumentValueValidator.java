/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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
import com.unboundid.ldap.sdk.NameResolver;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that
 * ensures that values can be parsed as valid DNS host names.  As per
 * <A HREF="https://www.ietf.org/rfc/rfc952.txt">RFC 952</A> and
 * <A HREF="https://www.ietf.org/rfc/rfc1123.txt">RFC 1123</A>, valid DNS host
 * names must satisfy the following constraints:
 * <UL>
 *   <LI>Host names are split into one or more components, which are separated
 *       by periods.</LI>
 *   <LI>Each component may contain only ASCII letters, digits, and hyphens.
 *       While host names may contain non-ASCII characters in some contexts,
 *       they are not valid in all contexts, and host names with non-ASCII
 *       characters should be represented in an ASCII-only encoding called
 *       punycode (as described in
 *       <A HREF="https://www.ietf.org/rfc/rfc3492.txt">RFC 3492</A>).  This
 *       implementation expects any hostnames with non-ASCII characters to use
 *       the punycode representation, but it does not currently attempt to
 *       validate the punycode representation.</LI>
 *   <LI>Components must not start with a hyphen.</LI>
 *   <LI>Each component of a hostname must be between 1 and 63 characters.</LI>
 *   <LI>The entire hostname (including the periods between components) must
 *       not exceed 255 characters.</LI>
 *   <LI>Host names must not contain consecutive periods, as that would
 *       indicate an empty internal component.</LI>
 *   <LI>Host names must not start with a period, as that would indicate an
 *       empty initial component.</LI>
 *   <LI>Host names may end with a period as a way of explicitly indicating that
 *       it is fully qualified.  This is primarily used for host names that
 *       only contain a single component (for example, "localhost."), but it is
 *       allowed for any fully qualified host name.</LI>
 *   <LI>This implementation may optionally require fully qualified host
 *       names.</LI>
 *   <LI>This implementation may optionally reject host names that cannot be
 *       resolved to IP addresses.</LI>
 *   <LI>This implementation may optionally reject values that are numeric IP
 *       addresses rather than host names.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DNSHostNameArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1525611526290885612L;



  // Indicates whether to allow IP addresses in addition to DNS host names.
  private final boolean allowIPAddresses;

  // Indicates whether to allow unqualified names.
  private final boolean allowUnqualifiedNames;

  // Indicates whether to allow unresolvable names.
  private final boolean allowUnresolvableNames;

  // The name resolver that will be used to attempt to resolve host names to IP
  // addresses.
  @NotNull private final NameResolver nameResolver;



  /**
   * Creates a new DNS host name argument value validator with the default
   * settings.  It will allow IP addresses in addition to host names, it will
   * allow unqualified names, and it will allow unresolvable names.
   */
  public DNSHostNameArgumentValueValidator()
  {
    this(true, true, true, null);
  }



  /**
   * Creates a new DNS host name argument value validator with the provided
   * settings.
   *
   * @param  allowIPAddresses        Indicates whether this validator will allow
   *                                 values that represent numeric IP addresses
   *                                 rather than DNS host names.  If this is
   *                                 {@code true}, then valid IP addresses will
   *                                 be accepted as well as valid DNS host
   *                                 names.  If this is {@code false}, then only
   *                                 valid DNS host names will be accepted.
   * @param  allowUnqualifiedNames   Indicates whether this validator will allow
   *                                 values that represent unqualified host
   *                                 names.  If this is {@code true}, then
   *                                 unqualified names will be accepted as long
   *                                 as they are otherwise acceptable.  If this
   *                                 is {@code false}, then only fully qualified
   *                                 host names will be accepted.
   * @param  allowUnresolvableNames  Indicates whether this validator will allow
   *                                 host name values that do not resolve to
   *                                 IP addresses.  If this is {@code true},
   *                                 then this validator will not attempt to
   *                                 resolve host names.  If this is
   *                                 {@code false}, then this validator will
   *                                 reject any host name that cannot be
   *                                 resolved to an IP address.
   * @param  nameResolver            The name resolver that will be used when
   *                                 attempting to resolve host names to IP
   *                                 addresses.  If this is {@code null}, then
   *                                 the LDAP SDK's default name resolver will
   *                                 be used.
   */
  public DNSHostNameArgumentValueValidator(
              final boolean allowIPAddresses,
              final boolean allowUnqualifiedNames,
              final boolean allowUnresolvableNames,
              @Nullable final NameResolver nameResolver)
  {
    this.allowIPAddresses = allowIPAddresses;
    this.allowUnqualifiedNames = allowUnqualifiedNames;
    this.allowUnresolvableNames = allowUnresolvableNames;

    if (nameResolver == null)
    {
      this.nameResolver = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER;
    }
    else
    {
      this.nameResolver = nameResolver;
    }
  }



  /**
   * Indicates whether this validator will allow values that represent valid
   * numeric IP addresses rather than DNS host names.
   *
   * @return  {@code true} if this validator will accept values that represent
   *          either valid numeric IP addresses or numeric DNS host names, or
   *          {@code false} if it will reject values that represent numeric
   *          IP addresses.
   */
  public boolean allowIPAddresses()
  {
    return allowIPAddresses;
  }



  /**
   * Indicates whether this validator will allow unqualified DNS host names
   * (that is, host names that do not include a domain component).
   *
   * @return  {@code true} if this validator will allow both unqualified and
   *          fully qualified host names, or {@code false} if it will only
   *          accept fully qualified host names.
   */
  public boolean allowUnqualifiedNames()
  {
    return allowUnqualifiedNames;
  }



  /**
   * Indicates whether this validator will allow DNS host names that cannot be
   * resolved to IP addresses.
   *
   * @return  {@code true} if this validator will only validate the syntax for
   *          DNS host names and will not make any attempt to resolve them to
   *          IP addresses, or {@code false} if it will attempt to resolve host
   *          names to IP addresses and will reject any names that cannot be
   *          resolved.
   */
  public boolean allowUnresolvableNames()
  {
    return allowUnresolvableNames;
  }



  /**
   * Retrieves the name resolver that will be used when attempting to resolve
   * host names to IP addresses.
   *
   * @return  The name resolver that will be used when attempting to resolve
   *          host names to IP addresses.
   */
  @NotNull()
  public NameResolver getNameResolver()
  {
    return nameResolver;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    try
    {
      validateDNSHostName(valueString, allowIPAddresses, allowUnqualifiedNames,
           allowUnresolvableNames, nameResolver);
    }
    catch (final ArgumentException e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_DNS_NAME_VALIDATOR_INVALID_ARG_VALUE.get(
                String.valueOf(valueString), argument.getIdentifierString(),
                e.getMessage()),
           e);
    }
  }



  /**
   * Ensures that the provided name represents a valid DNS host name using the
   * default settings.  IP addresses, unqualified names, and unresolvable names
   * will all be allowed as long as the provided name is otherwise syntactically
   * valid.
   *
   * @param  name  The name to validate as a DNS host name.  It must not be
   *               {@code null} or empty.
   *
   * @throws  ArgumentException  If the provided name is not considered valid.
   */
  public static void validateDNSHostName(@NotNull final String name)
         throws ArgumentException
  {
    validateDNSHostName(name, true, true, true, null);
  }



  /**
   * Ensures that the provided name represents a valid DNS host name using the
   * provided settings.
   *
   * @param  name                    The name to validate as a DNS host name.
   * @param  allowIPAddresses        Indicates whether this validator will allow
   *                                 values that represent numeric IP addresses
   *                                 rather than DNS host names.  If this is
   *                                 {@code true}, then valid IP addresses will
   *                                 be accepted as well as valid DNS host
   *                                 names.  If this is {@code false}, then only
   *                                 valid DNS host names will be accepted.
   * @param  allowUnqualifiedNames   Indicates whether this validator will allow
   *                                 values that represent unqualified host
   *                                 names.  If this is {@code true}, then
   *                                 unqualified names will be accepted as long
   *                                 as they are otherwise acceptable.  If this
   *                                 is {@code false}, then only fully qualified
   *                                 host names will be accepted.
   * @param  allowUnresolvableNames  Indicates whether this validator will allow
   *                                 host name values that do not resolve to
   *                                 IP addresses.  If this is {@code true},
   *                                 then this validator will not attempt to
   *                                 resolve host names.  If this is
   *                                 {@code false}, then this validator will
   *                                 reject any host name that cannot be
   *                                 resolved to an IP address.
   * @param  nameResolver            The name resolver that will be used when
   *                                 attempting to resolve host names to IP
   *                                 addresses.  If this is {@code null}, then
   *                                 the LDAP SDK's default name resolver will
   *                                 be used.
   *
   * @throws  ArgumentException  If the provided name is not considered valid.
   */
  public static void validateDNSHostName(
              @Nullable final String name,
              final boolean allowIPAddresses,
              final boolean allowUnqualifiedNames,
              final boolean allowUnresolvableNames,
              @Nullable final NameResolver nameResolver)
         throws ArgumentException
  {
    // Make sure that the provided name is not null or empty.
    if ((name == null) || name.isEmpty())
    {
      throw new ArgumentException(ERR_DNS_NAME_VALIDATOR_NULL_OR_EMPTY.get());
    }


    // Make sure that the provided name does not contain consecutive periods.
    if (name.contains(".."))
    {
      throw new ArgumentException(
           ERR_DNS_NAME_VALIDATOR_CONSECUTIVE_PERIODS.get());
    }


    // See if the provided name represents an IP address.  If so, then see if
    // that's acceptable.
    if (IPAddressArgumentValueValidator.isValidNumericIPAddress(name))
    {
      if (allowIPAddresses)
      {
        // If an IP address was provided and allowed, then we don't require any
        // more validation.
        return;
      }
      else
      {
        throw new ArgumentException(ERR_DNS_NAME_VALIDATOR_IP_ADDRESS.get());
      }
    }


    // Make sure that the host name looks like it's syntactically valid.
    validateDNSHostNameSyntax(name);


    // If we should require fully qualified names, then make sure that the
    // original name contains at least one period.
    if ((! allowUnqualifiedNames) && (name.indexOf('.') < 0))
    {
      throw new ArgumentException(ERR_DNS_NAME_VALIDATOR_NOT_QUALIFIED.get());
    }


    // If we should attempt to resolve the address, then do so now.
    if (! allowUnresolvableNames)
    {
      try
      {
        final NameResolver resolver;
        if (nameResolver == null)
        {
          resolver = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER;
        }
        else
        {
          resolver = nameResolver;
        }

        resolver.getByName(name);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        throw new ArgumentException(ERR_DNS_NAME_VALIDATOR_NOT_RESOLVABLE.get(),
             e);
      }
    }
  }



  /**
   * Validates the provided name to ensure that it conforms to the expected
   * syntax.
   *
   * @param  name  The name to validate.
   *
   * @throws  ArgumentException  If the provided name is not considered valid.
   */
  private static void validateDNSHostNameSyntax(@NotNull final String name)
          throws ArgumentException
  {
    // If the name ends with a trailing period, then strip it off and used the
    // stripped host name for the rest of the validation.  Note that
    // technically, a string containing just a period is a valid fully qualified
    // host name that represents the root label, so if we end up with an empty
    // string after removing a trailing period, then just return without doing
    // any more validation.
    final String nameWithoutTrailingPeriod;
    if (name.endsWith("."))
    {
      nameWithoutTrailingPeriod = name.substring(0, (name.length() - 1));
      if (nameWithoutTrailingPeriod.isEmpty())
      {
        return;
      }
    }
    else
    {
      nameWithoutTrailingPeriod = name;
    }


    // Make sure that the provided name is not more than 255 characters long.
    if (nameWithoutTrailingPeriod.length() > 255)
    {
      throw new ArgumentException(
           ERR_DNS_NAME_VALIDATOR_NAME_TOO_LONG.get(
                nameWithoutTrailingPeriod.length()));
    }


    // Make sure that the provided name does not start with a period.
    if (nameWithoutTrailingPeriod.startsWith("."))
    {
      throw new ArgumentException(
           ERR_DNS_NAME_VALIDATOR_STARTS_WITH_PERIOD.get());
    }


    // Iterate through and validate each of the components.
    int startPos = 0;
    int periodPos = nameWithoutTrailingPeriod.indexOf('.');
    while (periodPos > 0)
    {
      final String component =
           nameWithoutTrailingPeriod.substring(startPos, periodPos);
      if (component.length() > 63)
      {
        throw new ArgumentException(
             ERR_DNS_NAME_VALIDATOR_COMPONENT_TOO_LONG.get(
                  component, component.length()));
      }

      if (component.charAt(0) == '-')
      {
        throw new ArgumentException(
             ERR_DNS_NAME_VALIDATOR_COMPONENT_STARTS_WITH_HYPHEN.get(
                  component));
      }

      for (int i=0; i < component.length(); i++)
      {
        final char c = component.charAt(i);
        if (! isLetterDigitOrDash(c))
        {
          if (c <= 127)
          {
            throw new ArgumentException(
                 ERR_DNS_NAME_VALIDATOR_COMPONENT_ILLEGAL_ASCII_CHARACTER. get(
                      component, (i+1)));
          }
          else
          {
            throw new ArgumentException(
                 ERR_DNS_NAME_VALIDATOR_COMPONENT_NON_ASCII_CHARACTER.get(
                      component, (i+1)));
          }
        }
      }

      startPos = periodPos+1;
      periodPos = nameWithoutTrailingPeriod.indexOf('.', startPos);
    }
  }



  /**
   * Indicates whether the provided character is an ASCII letter, digit, or
   * dash.
   *
   * @param  c  The character for which to make the determination.
   *
   * @return  {@code true} if the provided character is an ASCII letter, digit,
   *          or dash, or {@code false} if not.
   */
  private static boolean isLetterDigitOrDash(final char c)
  {
    if ((c >= 'a') && (c <= 'z'))
    {
      return true;
    }

    if ((c >= 'A') && (c <= 'Z'))
    {
      return true;
    }

    if ((c >= '0') && (c <= '9'))
    {
      return true;
    }

    return (c == '-');
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
    buffer.append("DNSHostNameArgumentValueValidator(allowIPAddresses=");
    buffer.append(allowIPAddresses);
    buffer.append(", allowUnqualifiedNames=");
    buffer.append(allowUnqualifiedNames);
    buffer.append(", allowUnresolvableNames=");
    buffer.append(allowUnresolvableNames);
    buffer.append(')');
  }
}
