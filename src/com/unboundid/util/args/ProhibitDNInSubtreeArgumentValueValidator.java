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
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class provides an implementation of an argument value validator that is
 * expected to be used with string or DN arguments and ensures that all values
 * for the argument are valid DNs that are not within one or more specified
 * subtrees.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ProhibitDNInSubtreeArgumentValueValidator
       extends ArgumentValueValidator
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 171827460774234825L;



  // The set of prohibited base DNs for values of the associated argument.
  @NotNull private final List<DN> baseDNs;



  /**
   * Creates a new instance of this argument value validator with the provided
   * information.
   *
   * @param  baseDNs  The set of prohibited base DNs for values of the
   *                  associated argument.  It must not be {@code null} or
   *                  empty.
   */
  public ProhibitDNInSubtreeArgumentValueValidator(
              @NotNull final DN... baseDNs)
  {
    this(StaticUtils.toList(baseDNs));
  }



  /**
   * Creates a new instance of this argument value validator with the provided
   * information.
   *
   * @param  baseDNs  The set of prohibited base DNs for values of the
   *                  associated argument.  It must not be {@code null} or
   *                  empty.
   */
  public ProhibitDNInSubtreeArgumentValueValidator(
              @NotNull final Collection<DN> baseDNs)
  {
    Validator.ensureNotNull(baseDNs);
    Validator.ensureFalse(baseDNs.isEmpty());

    this.baseDNs = Collections.unmodifiableList(new ArrayList<>(baseDNs));
  }



  /**
   * Retrieves a list of the prohibited base DNs for this argument value
   * validator.
   *
   * @return  A list of the prohibited base DNs for this argument value
   *          validator.
   */
  @NotNull()
  public List<DN> getBaseDNs()
  {
    return baseDNs;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void validateArgumentValue(@NotNull final Argument argument,
                                    @NotNull final String valueString)
         throws ArgumentException
  {
    final DN dn;
    try
    {
      dn = new DN(valueString);
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      throw new ArgumentException(
           ERR_PROHIBIT_DN_IN_SUBTREE_VALIDATOR_VALUE_NOT_DN.get(valueString,
                argument.getIdentifierString()),
           e);
    }

    for (final DN baseDN : baseDNs)
    {
      if (dn.isDescendantOf(baseDN, true))
      {
        throw new ArgumentException(
             ERR_PROHIBIT_DN_IN_SUBTREE_VALIDATOR_VALUE_IN_SUBTREE.get(
                  valueString, argument.getIdentifierString(),
                  String.valueOf(baseDN)));
      }
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
    buffer.append("ProhibitDNInSubtreeArgumentValueValidator(baseDNs={");

    final Iterator<DN> iterator = baseDNs.iterator();
    while (iterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(iterator.next().toString());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
