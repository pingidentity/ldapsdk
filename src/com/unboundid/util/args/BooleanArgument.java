/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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



import java.util.Collections;
import java.util.List;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * Creates a new argument that is intended to represent Boolean states based on
 * whether it was present in the provided set of command-line arguments.
 * Boolean arguments never have values, since the argument identifier itself is
 * sufficient to indicate presence.  If the argument is present in the set of
 * provided command-line arguments, then it will be assumed to have a value of
 * {@code true}.  If the argument is not present, then it will be assumed to
 * have a value of {@code false}.
 * <BR><BR>
 * Note that it may be beneficial in some cases to allow multiple occurrences of
 * the same Boolean argument if that has special meaning (e.g., if "-v" is used
 * to enable verbose output, then perhaps "-v -v" would be even more verbose).
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class BooleanArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -3366354214909534696L;



  /**
   * Creates a new Boolean argument with the provided information.  The
   * argument will be allowed at most one time in a set of command line
   * arguments.
   *
   * @param  shortIdentifier  The short identifier for this argument.  It may
   *                          not be {@code null} if the long identifier is
   *                          {@code null}.
   * @param  longIdentifier   The long identifier for this argument.  It may
   *                          not be {@code null} if the short identifier is
   *                          {@code null}.
   * @param  description      A human-readable description for this argument.
   *                          It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public BooleanArgument(@Nullable final Character shortIdentifier,
                         @Nullable final String longIdentifier,
                         @NotNull final String description)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, false, 1, null, description);
  }



  /**
   * Creates a new Boolean argument with the provided information.
   *
   * @param  shortIdentifier  The short identifier for this argument.  It may
   *                          not be {@code null} if the long identifier is
   *                          {@code null}.
   * @param  longIdentifier   The long identifier for this argument.  It may
   *                          not be {@code null} if the short identifier is
   *                          {@code null}.
   * @param  maxOccurrences   The maximum number of times this argument may be
   *                          provided on the command line.  A value less than
   *                          or equal to zero indicates that it may be present
   *                          any number of times.
   * @param  description      A human-readable description for this argument.
   *                          It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public BooleanArgument(@Nullable final Character shortIdentifier,
                         @Nullable final String longIdentifier,
                         final int maxOccurrences,
                         @NotNull final String description)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, false, maxOccurrences, null,
          description);
  }



  /**
   * Creates a new Boolean argument that is a "clean" copy of the provided
   * source argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private BooleanArgument(@NotNull final BooleanArgument source)
  {
    super(source);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(@NotNull final String valueString)
            throws ArgumentException
  {
    throw new ArgumentException(ERR_BOOLEAN_VALUES_NOT_ALLOWED.get(
                                     getIdentifierString()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    return Collections.singletonList(String.valueOf(isPresent()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return false;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDataTypeName()
  {
    return INFO_BOOLEAN_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    return INFO_BOOLEAN_CONSTRAINTS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public BooleanArgument getCleanCopy()
  {
    return new BooleanArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    for (int i=0; i < getNumOccurrences(); i++)
    {
      argStrings.add(getIdentifierString());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("BooleanArgument(");
    appendBasicToStringInfo(buffer);
    buffer.append(')');
  }
}
