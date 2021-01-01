/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldif;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashSet;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.matchingrules.MatchingRule;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an attribute implementation that may be used to improve
 * performance of the LDIF reader when dealing with large entries, and
 * especially with attributes with large numbers of values.  It provides the
 * ability to add new values without creating new attribute objects, and it is
 * faster to ensure that there are no duplicate values.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
class LDIFAttribute
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3771917482408643188L;



  // The set of normalized values for this attribute.
  @Nullable private LinkedHashSet<ASN1OctetString> normalizedValues;

  // The list of values for this attribute.
  @NotNull private final ArrayList<ASN1OctetString> values;

  // The matching rule to use when comparing values.
  @NotNull private final MatchingRule matchingRule;

  // The name for this attribute.
  @NotNull private final String name;



  /**
   * Creates a new LDIF attribute with the provided name and value.
   *
   * @param  name          The name for this attribute.
   * @param  matchingRule  The matching rule for this attribute.
   * @param  value         The first value for this attribute.
   */
  LDIFAttribute(@NotNull final String name,
                @NotNull final MatchingRule matchingRule,
                @NotNull final ASN1OctetString value)
  {
    this.name         = name;
    this.matchingRule = matchingRule;

    values = new ArrayList<>(5);
    values.add(value);

    normalizedValues = null;
  }



  /**
   * Adds the provided value to this attribute, if it does not already exist.
   *
   * @param  value                   The value to be added.
   * @param  duplicateValueBehavior  The behavior that should be exhibited if
   *                                 the LDIF reader encounters an entry with
   *                                 duplicate values.
   *
   * @return  {@code true} if the value was added to this attribute, or
   *          {@code false} if the value was already present.
   *
   * @throws  LDAPException  If the provided value is invalid according to the
   *                         associated syntax.
   */
  boolean addValue(@NotNull final ASN1OctetString value,
                   @NotNull final DuplicateValueBehavior duplicateValueBehavior)
          throws LDAPException
  {
    if (normalizedValues == null)
    {
      normalizedValues = new LinkedHashSet<>(
           StaticUtils.computeMapCapacity(values.size() + 1));
      for (final ASN1OctetString s : values)
      {
        normalizedValues.add(matchingRule.normalize(s));
      }
    }

    if (normalizedValues.add(matchingRule.normalize(value)))
    {
      values.add(value);
      return true;
    }
    else
    {
      // This means the attribute already had the value.  Even though this is
      // illegal, we may allow it based on the configuration.
      if (duplicateValueBehavior == DuplicateValueBehavior.RETAIN)
      {
        values.add(value);
        return true;
      }
      else
      {
        return false;
      }
    }
  }



  /**
   * Converts this LDIF attribute to an SDK attribute.
   *
   * @return  An SDK attribute with the name and values of this LDIF attribute.
   */
  @NotNull()
  Attribute toAttribute()
  {
    final ASN1OctetString[] valueArray = new ASN1OctetString[values.size()];
    values.toArray(valueArray);

    return new Attribute(name, matchingRule, valueArray);
  }
}
