/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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

import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPURL;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that is
 * expected to be used with a string argument and ensures that all values for
 * the argument are valid LDAP URLs.  It can optionally indicate which elements
 * are required to be present in the URL.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPURLArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -8867023666922488786L;



  // Indicates whether the attributes element is required to be present in the
  // URL with at least one value.
  private final boolean requireAttributes;

  // Indicates whether a non-empty base DN element is required to be present in
  // the URL.
  private final boolean requireBaseDN;

  // Indicates whether the filter element is required to be present in the URL.
  private final boolean requireFilter;

  // Indicates whether the host element is required to be present in the URL.
  private final boolean requireHost;

  // Indicates whether the port element is required to be present in the URL.
  private final boolean requirePort;

  // Indicates whether the scope element is required to be present in the URL.
  private final boolean requireScope;



  /**
   * Creates a new instance of this LDAP URL argument value validator that will
   * accept values that represent any valid LDAP URL.
   */
  public LDAPURLArgumentValueValidator()
  {
    this(false, false, false, false, false, false);
  }



  /**
   * Creates a new instance of this LDAP URL argument value validator that will
   * accept values that represent valid LDAP URLs with the specified
   * constraints.
   *
   * @param  requireHost        Indicates whether LDAP URL values are required
   *                            to include the host element.
   * @param  requirePort        Indicates whether LDAP URL values are required
   *                            to include the port element.
   * @param  requireBaseDN      Indicates whether LDAP URL values are required
   *                            to include a non-empty base DN element.
   * @param  requireAttributes  Indicates whether LDAP URL values are required
   *                            to include an attribute list with at least one
   *                            attribute description.
   * @param  requireScope       Indicates whether LDAP URL values are required
   *                            to include the scope element.
   * @param  requireFilter      Indicates whether LDAP URL values are required
   *                            to include the filter element.
   */
  public LDAPURLArgumentValueValidator(final boolean requireHost,
                                       final boolean requirePort,
                                       final boolean requireBaseDN,
                                       final boolean requireAttributes,
                                       final boolean requireScope,
                                       final boolean requireFilter)
  {
    this.requireHost       = requireHost;
    this.requirePort       = requirePort;
    this.requireBaseDN     = requireBaseDN;
    this.requireAttributes = requireAttributes;
    this.requireScope      = requireScope;
    this.requireFilter     = requireFilter;
  }



  /**
   * Indicates whether LDAP URL values are required to include the host element.
   *
   * @return  {@code true} if LDAP URL values are required to include the host
   *          element, or {@code false} if not.
   */
  public boolean requireHost()
  {
    return requireHost;
  }



  /**
   * Indicates whether LDAP URL values are required to include the port element.
   *
   * @return  {@code true} if LDAP URL values are required to include the port
   *          element, or {@code false} if not.
   */
  public boolean requirePort()
  {
    return requirePort;
  }



  /**
   * Indicates whether LDAP URL values are required to include a non-empty base
   * DN element.
   *
   * @return  {@code true} if LDAP URL values are required to include a
   *          non-empty base DN element, or {@code false} if not.
   */
  public boolean requireBaseDN()
  {
    return requireBaseDN;
  }



  /**
   * Indicates whether LDAP URL values are required to include the attributes
   * element with at least one attribute description.
   *
   * @return  {@code true} if LDAP URL values are required to include the
   *          attributes element, or {@code false} if not.
   */
  public boolean requireAttributes()
  {
    return requireAttributes;
  }



  /**
   * Indicates whether LDAP URL values are required to include the scope
   * element.
   *
   * @return  {@code true} if LDAP URL values are required to include the scope
   *          element, or {@code false} if not.
   */
  public boolean requireScope()
  {
    return requireScope;
  }



  /**
   * Indicates whether LDAP URL values are required to include the filter
   * element.
   *
   * @return  {@code true} if LDAP URL values are required to include the filter
   *          element, or {@code false} if not.
   */
  public boolean requireFilter()
  {
    return requireFilter;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    final LDAPURL ldapURL;
    try
    {
      ldapURL = new LDAPURL(valueString);
    }
    catch (final LDAPException e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_VALUE_NOT_LDAP_URL.get(valueString,
                argument.getIdentifierString(), e.getMessage()),
           e);
    }

    if (requireHost && (! ldapURL.hostProvided()))
    {
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_MISSING_HOST.get(valueString,
                argument.getIdentifierString()));
    }

    if (requirePort && (! ldapURL.portProvided()))
    {
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_MISSING_PORT.get(valueString,
                argument.getIdentifierString()));
    }

    if (requireBaseDN && (! ldapURL.baseDNProvided()))
    {
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_MISSING_BASE_DN.get(valueString,
                argument.getIdentifierString()));
    }

    if (requireAttributes && (! ldapURL.attributesProvided()))
    {
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_MISSING_ATTRIBUTES.get(valueString,
                argument.getIdentifierString()));
    }

    if (requireScope && (! ldapURL.scopeProvided()))
    {
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_MISSING_SCOPE.get(valueString,
                argument.getIdentifierString()));
    }

    if (requireFilter && (! ldapURL.filterProvided()))
    {
      throw new ArgumentException(
           ERR_LDAP_URL_VALIDATOR_MISSING_FILTER.get(valueString,
                argument.getIdentifierString()));
    }
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
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("LDAPURLArgumentValueValidator(requireHost=");
    buffer.append(requireHost);
    buffer.append(", requirePort=");
    buffer.append(requirePort);
    buffer.append(", requireBaseDN=");
    buffer.append(requireBaseDN);
    buffer.append(", requireAttributes=");
    buffer.append(requireAttributes);
    buffer.append(", requireScope=");
    buffer.append(requireScope);
    buffer.append(", requireFilter=");
    buffer.append(requireFilter);
    buffer.append(')');
  }
}
