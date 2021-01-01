/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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



import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;



/**
 * This class provides a data structure which holds information about a SASL
 * mechanism supported for use with the {@link SASLUtils} class.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLMechanismInfo
{
  // Indicates whether this SASL mechanism allows a password to be provided.
  private final boolean acceptsPassword;

  // Indicates whether this SASL mechanism requires a password to be provided.
  private final boolean requiresPassword;

  // The list of options available for use with this mechanism.
  @NotNull private final List<SASLOption> options;

  // A description for this SASL mechanism.
  @NotNull private final String description;

  // The name for this SASL mechanism.
  @NotNull private final String name;



  /**
   * Creates a new SASL mechanism info object with the provided information.
   *
   * @param  name              The name for the SASL mechanism.
   * @param  description       A description for the SASL mechanism.
   * @param  acceptsPassword   Indicates whether the SASL mechanism allows a
   *                           password to be provided.
   * @param  requiresPassword  Indicates whether the SASL mechanism requires a
   *                           password to be provided.
   * @param  options           The set of options that are associated with the
   *                           SASL mechanism.
   */
  public SASLMechanismInfo(@NotNull final String name,
                           @NotNull final String description,
                           final boolean acceptsPassword,
                           final boolean requiresPassword,
                           @Nullable final SASLOption... options)
  {
    this.name             = name;
    this.description      = description;
    this.acceptsPassword  = acceptsPassword;
    this.requiresPassword = requiresPassword;

    if ((options == null) || (options.length == 0))
    {
      this.options = Collections.emptyList();
    }
    else
    {
      this.options = Collections.unmodifiableList(Arrays.asList(options));
    }
  }



  /**
   * Retrieves the name of the SASL mechanism.
   *
   * @return  The name of the SASL mechanism.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a description for the SASL mechanism.
   *
   * @return  A description for the SASL mechanism.
   */
  @NotNull()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether the SASL mechanism accepts a password for authentication
   * processing.
   *
   * @return  {@code true} if the SASL mechanism accepts a password for
   *          authentication processing, or {@code false} if not.
   */
  public boolean acceptsPassword()
  {
    return acceptsPassword;
  }



  /**
   * Indicates whether the SASL mechanism requires a password for authentication
   * processing.
   *
   * @return  {@code true} if the SASL mechanism requires a password for
   *          authentication processing, or {@code false} if not.
   */
  public boolean requiresPassword()
  {
    return requiresPassword;
  }



  /**
   * Retrieves a list of the options that may be used with the SASL mechanism.
   *
   * @return  A list of the options that may be used with the SASL mechanism, or
   *          an empty list if there are no supported SASL options for the
   *          associated mechanism.
   */
  @NotNull()
  public List<SASLOption> getOptions()
  {
    return options;
  }



  /**
   * Retrieves a string representation of this SASL mechanism info object.
   *
   * @return  A string representation of this SASL mechanism info object.
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
   * Appends a string representation of this SASL mechanism info object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SASLMechanismInfo(name='");
    buffer.append(name);
    buffer.append("', description='");
    buffer.append(description);
    buffer.append("', acceptsPassword=");
    buffer.append(acceptsPassword);
    buffer.append(", requiresPassword=");
    buffer.append(requiresPassword);
    buffer.append(", options={");

    final Iterator<SASLOption> iterator = options.iterator();
    while (iterator.hasNext())
    {
      iterator.next().toString(buffer);
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
