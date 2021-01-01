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



import java.io.Serializable;



/**
 * This class provides a data structure that holds information about an option
 * that can be used in the course of SASL authentication.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SASLOption
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -683675804002105357L;



  // Indicates whether this option is allowed to be specified multiple times for
  // a single bind request.
  private final boolean isMultiValued;

  // Indicates whether this SASL option is required for use in conjunction with
  // the associated SASL mechanism.
  private final boolean isRequired;

  // A description for this SASL option.
  @NotNull private final String description;

  // The name for this SASL option.
  @NotNull private final String name;



  /**
   * Creates a new SASL option with the provided information.
   *
   * @param  name           The name for this SASL option.
   * @param  description    A description for this SASL option.
   * @param  isRequired     Indicates whether this option is required for use in
   *                        conjunction with the associated SASL mechanism.
   * @param  isMultiValued  Indicates whether this option is allowed to be
   *                        specified multiple times for a single bind request.
   */
  public SASLOption(@NotNull final String name,
                    @NotNull final String description,
                    final boolean isRequired, final boolean isMultiValued)
  {
    this.name          = name;
    this.description   = description;
    this.isRequired    = isRequired;
    this.isMultiValued = isMultiValued;
  }



  /**
   * Retrieves the name for this SASL option.
   *
   * @return  The name for this SASL option.
   */
  @NotNull()
  public String getName()
  {
    return name;
  }



  /**
   * Retrieves a description for this SASL option.
   *
   * @return  A description for this SASL option.
   */
  @NotNull()
  public String getDescription()
  {
    return description;
  }



  /**
   * Indicates whether this SASL option must be provided when attempting to bind
   * with the associated mechanism.
   *
   * @return  {@code true} if this SASL option must be specified when trying to
   *          bind with the associated mechanism, or {@code false} if not.
   */
  public boolean isRequired()
  {
    return isRequired;
  }



  /**
   * Indicates whether this SASL option may be provided multiple times when
   * trying to bind with the associated mechanism.
   *
   * @return  {@code true} if this SASL option may be provided multiple times
   *          when trying to bind with the associated mechanism, or
   *          {@code false} if not.
   */
  public boolean isMultiValued()
  {
    return isMultiValued;
  }



  /**
   * Retrieves a string representation for this SASL option.
   *
   * @return  A string representation for this SASL option.
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
   * Appends a string representation of this SASL option to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SASLOption(name='");
    buffer.append(name);
    buffer.append("', description='");
    buffer.append(description);
    buffer.append("', isRequired=");
    buffer.append(isRequired);
    buffer.append(", isMultiValued=");
    buffer.append(isMultiValued);
    buffer.append(')');
  }
}
