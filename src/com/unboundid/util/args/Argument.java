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



import java.io.Serializable;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.util.LDAPSDKUsageException;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines a generic command line argument, which provides
 * functionality applicable to all argument types.  Subclasses may enforce
 * additional constraints or provide additional functionality.
 */
@NotExtensible()
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public abstract class Argument
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6938320885602903919L;



  // Indicates whether this argument should be excluded from usage information.
  private boolean isHidden;

  // Indicates whether this argument has been registered with the argument
  // parser.
  private boolean isRegistered;

  // Indicates whether this argument is required to be present.
  private final boolean isRequired;

  // Indicates whether values of this argument should be considered sensitive.
  private boolean isSensitive;

  // Indicates whether this argument is used to display usage information.
  private boolean isUsageArgument;

  // The maximum number of times this argument is allowed to be provided.
  private int maxOccurrences;

  // The number of times this argument was included in the provided command line
  // arguments.
  private int numOccurrences;

  // The set of short identifiers for this argument, associated with an
  // indication as to whether the identifier should be hidden.
  @NotNull private final Map<Character,Boolean> shortIdentifiers;

  // The set of long identifiers for this argument, associated with an
  // indication as to whether the identifier should be hidden.
  @NotNull private final Map<String,Boolean> longIdentifiers;

  // The argument group name for this argument, if any.
  @Nullable private String argumentGroupName;

  // The description for this argument.
  @NotNull private final String description;

  // The value placeholder for this argument, or {@code null} if it does not
  // take a value.
  @Nullable private final String valuePlaceholder;



  /**
   * Creates a new argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
   * @param  maxOccurrences    The maximum number of times this argument may be
   *                           provided on the command line.  A value less than
   *                           or equal to zero indicates that it may be present
   *                           any number of times.
   * @param  valuePlaceholder  A placeholder to display in usage information to
   *                           indicate that a value must be provided.  If this
   *                           is {@code null}, then the argument will not be
   *                           allowed to take a value.  If it is not
   *                           {@code null}, then the argument will be required
   *                           to take a value.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  protected Argument(@Nullable final Character shortIdentifier,
                     @Nullable final String longIdentifier,
                     final boolean isRequired, final int maxOccurrences,
                     @Nullable final String valuePlaceholder,
                     @NotNull final String description)
            throws ArgumentException
  {
    if (description == null)
    {
      throw new ArgumentException(ERR_ARG_DESCRIPTION_NULL.get());
    }

    if ((shortIdentifier == null) && (longIdentifier == null))
    {
      throw new ArgumentException(ERR_ARG_NO_IDENTIFIERS.get());
    }

    shortIdentifiers = new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    if (shortIdentifier != null)
    {
      shortIdentifiers.put(shortIdentifier, false);
    }

    longIdentifiers = new LinkedHashMap<>(StaticUtils.computeMapCapacity(5));
    if (longIdentifier != null)
    {
      longIdentifiers.put(longIdentifier, false);
    }

    this.isRequired       = isRequired;
    this.valuePlaceholder = valuePlaceholder;
    this.description      = description;

    if (maxOccurrences > 0)
    {
      this.maxOccurrences = maxOccurrences;
    }
    else
    {
      this.maxOccurrences = Integer.MAX_VALUE;
    }

    argumentGroupName = null;
    numOccurrences    = 0;
    isHidden          = false;
    isRegistered      = false;
    isSensitive       = false;
    isUsageArgument   = false;
  }



  /**
   * Creates a new argument with the same generic information as the provided
   * argument.  It will not be registered with any argument parser.
   *
   * @param  source  The argument to use as the source for this argument.
   */
  protected Argument(@NotNull final Argument source)
  {
    argumentGroupName = source.argumentGroupName;
    isHidden          = source.isHidden;
    isRequired        = source.isRequired;
    isSensitive       = source.isSensitive;
    isUsageArgument   = source.isUsageArgument;
    maxOccurrences    = source.maxOccurrences;
    description       = source.description;
    valuePlaceholder  = source.valuePlaceholder;

    isRegistered   = false;
    numOccurrences = 0;

    shortIdentifiers = new LinkedHashMap<>(source.shortIdentifiers);
    longIdentifiers  = new LinkedHashMap<>(source.longIdentifiers);
  }



  /**
   * Indicates whether this argument has a short identifier.
   *
   * @return  {@code true} if it has a short identifier, or {@code false} if
   *          not.
   */
  public final boolean hasShortIdentifier()
  {
    return (! shortIdentifiers.isEmpty());
  }



  /**
   * Retrieves the short identifier for this argument.  If there is more than
   * one, then the first will be returned.
   *
   * @return  The short identifier for this argument, or {@code null} if none is
   *          defined.
   */
  @Nullable()
  public final Character getShortIdentifier()
  {
    for (final Map.Entry<Character,Boolean> e : shortIdentifiers.entrySet())
    {
      if (e.getValue())
      {
        continue;
      }

      return e.getKey();
    }

    return null;
  }



  /**
   * Retrieves the list of all short identifiers, including hidden identifiers,
   * for this argument.
   *
   * @return  The list of all short identifiers for this argument, or an empty
   *          list if there are no short identifiers.
   */
  @NotNull()
  public final List<Character> getShortIdentifiers()
  {
    return getShortIdentifiers(true);
  }



  /**
   * Retrieves the list of short identifiers for this argument.
   *
   * @param  includeHidden  Indicates whether to include hidden identifiers in
   *                        the list that is returned.
   *
   * @return  The list of short identifiers for this argument, or an empty list
   *          if there are none.
   */
  @NotNull()
  public final List<Character> getShortIdentifiers(final boolean includeHidden)
  {
    final ArrayList<Character> identifierList =
         new ArrayList<>(shortIdentifiers.size());
    for (final Map.Entry<Character,Boolean> e : shortIdentifiers.entrySet())
    {
      if (includeHidden || (! e.getValue()))
      {
        identifierList.add(e.getKey());
      }
    }

    return Collections.unmodifiableList(identifierList);
  }



  /**
   * Adds the provided character to the set of short identifiers for this
   * argument.  It will not be hidden.  Note that this must be called before
   * this argument is registered with the argument parser.
   *
   * @param  c  The character to add to the set of short identifiers for this
   *            argument.  It must not be {@code null}.
   *
   * @throws  ArgumentException  If this argument is already registered with the
   *                             argument parser.
   */
  public final void addShortIdentifier(@NotNull final Character c)
         throws ArgumentException
  {
    addShortIdentifier(c, false);
  }



  /**
   * Adds the provided character to the set of short identifiers for this
   * argument.  Note that this must be called before this argument is registered
   * with the argument parser.
   *
   * @param  c         The character to add to the set of short identifiers for
   *                   this argument.  It must not be {@code null}.
   * @param  isHidden  Indicates whether the provided identifier should be
   *                   hidden.  If this is {@code true}, then the identifier can
   *                   be used to target this argument on the command line, but
   *                   it will not be included in usage information.
   *
   * @throws  ArgumentException  If this argument is already registered with the
   *                             argument parser.
   */
  public final void addShortIdentifier(@NotNull final Character c,
                                       final boolean isHidden)
         throws ArgumentException
  {
    if (isRegistered)
    {
      throw new ArgumentException(ERR_ARG_ID_CHANGE_AFTER_REGISTERED.get(
                                       getIdentifierString()));
    }

    shortIdentifiers.put(c, isHidden);
  }



  /**
   * Indicates whether this argument has a long identifier.
   *
   * @return  {@code true} if it has a long identifier, or {@code false} if
   *          not.
   */
  public final boolean hasLongIdentifier()
  {
    return (! longIdentifiers.isEmpty());
  }



  /**
   * Retrieves the long identifier for this argument.  If it has multiple long
   * identifiers, then the first will be returned.
   *
   * @return  The long identifier for this argument, or {@code null} if none is
   *          defined.
   */
  @Nullable()
  public final String getLongIdentifier()
  {
    for (final Map.Entry<String,Boolean> e : longIdentifiers.entrySet())
    {
      if (e.getValue())
      {
        continue;
      }

      return e.getKey();
    }

    return null;
  }



  /**
   * Retrieves the list of all long identifiers, including hidden identifiers,
   * for this argument.
   *
   * @return  The list of all long identifiers for this argument, or an empty
   *          list if there are no long identifiers.
   */
  @NotNull()
  public final List<String> getLongIdentifiers()
  {
    return getLongIdentifiers(true);
  }



  /**
   * Retrieves the list of long identifiers for this argument.
   *
   * @param  includeHidden  Indicates whether to include hidden identifiers in
   *                        the list that is returned.
   *
   * @return  The long identifier for this argument, or an empty list if there
   *          are none.
   */
  @NotNull()
  public final List<String> getLongIdentifiers(final boolean includeHidden)
  {
    final ArrayList<String> identifierList =
         new ArrayList<>(longIdentifiers.size());
    for (final Map.Entry<String,Boolean> e : longIdentifiers.entrySet())
    {
      if (includeHidden || (! e.getValue()))
      {
        identifierList.add(e.getKey());
      }
    }

    return Collections.unmodifiableList(identifierList);
  }



  /**
   * Adds the provided string to the set of short identifiers for this argument.
   * It will not be hidden.  Note that this must be called before this argument
   * is registered with the argument parser.
   *
   * @param  s  The string to add to the set of short identifiers for this
   *            argument.  It must not be {@code null}.
   *
   * @throws  ArgumentException  If this argument is already registered with the
   *                             argument parser.
   */
  public final void addLongIdentifier(@NotNull final String s)
         throws ArgumentException
  {
    addLongIdentifier(s, false);
  }



  /**
   * Adds the provided string to the set of short identifiers for this argument.
   * Note that this must be called before this argument is registered with the
   * argument parser.
   *
   * @param  s         The string to add to the set of short identifiers for
   *                   this argument.  It must not be {@code null}.
   * @param  isHidden  Indicates whether the provided identifier should be
   *                   hidden.  If this is {@code true}, then the identifier can
   *                   be used to target this argument on the command line, but
   *                   it will not be included in usage information.
   *
   * @throws  ArgumentException  If this argument is already registered with the
   *                             argument parser.
   */
  public final void addLongIdentifier(@NotNull final String s,
                                      final boolean isHidden)
         throws ArgumentException
  {
    if (isRegistered)
    {
      throw new ArgumentException(ERR_ARG_ID_CHANGE_AFTER_REGISTERED.get(
                                       getIdentifierString()));
    }

    longIdentifiers.put(s, isHidden);
  }



  /**
   * Retrieves a string that may be used to identify this argument.  If a long
   * identifier is defined, then the value returned will be two dashes followed
   * by that string.  Otherwise, the value returned will be a single dash
   * followed by the short identifier.
   *
   * @return  A string that may be used to identify this argument.
   */
  @NotNull()
  public final String getIdentifierString()
  {
    for (final Map.Entry<String,Boolean> e : longIdentifiers.entrySet())
    {
      if (! e.getValue())
      {
        return "--" + e.getKey();
      }
    }

    for (final Map.Entry<Character,Boolean> e : shortIdentifiers.entrySet())
    {
      if (! e.getValue())
      {
        return "-" + e.getKey();
      }
    }

    // This should never happen.
    throw new LDAPSDKUsageException(
         ERR_ARG_NO_NON_HIDDEN_IDENTIFIER.get(toString()));
  }



  /**
   * Indicates whether this argument is required to be provided.
   *
   * @return  {@code true} if this argument is required to be provided, or
   *          {@code false} if not.
   */
  public final boolean isRequired()
  {
    return isRequired;
  }



  /**
   * Retrieves the maximum number of times that this argument may be provided.
   *
   * @return  The maximum number of times that this argument may be provided.
   */
  public final int getMaxOccurrences()
  {
    return maxOccurrences;
  }



  /**
   * Specifies the maximum number of times that this argument may be provided.
   *
   * @param  maxOccurrences  The maximum number of times that this argument
   *                         may be provided.  A value less than or equal to
   *                         zero indicates that there should be no limit on the
   *                         maximum number of occurrences.
   */
  public final void setMaxOccurrences(final int maxOccurrences)
  {
    if (maxOccurrences <= 0)
    {
      this.maxOccurrences = Integer.MAX_VALUE;
    }
    else
    {
      this.maxOccurrences = maxOccurrences;
    }
  }



  /**
   * Indicates whether this argument takes a value.
   *
   * @return  {@code true} if this argument takes a value, or {@code false} if
   *          not.
   */
  public boolean takesValue()
  {
    return (valuePlaceholder != null);
  }



  /**
   * Retrieves the value placeholder string for this argument.
   *
   * @return  The value placeholder string for this argument, or {@code null} if
   *          it does not take a value.
   */
  @Nullable()
  public final String getValuePlaceholder()
  {
    return valuePlaceholder;
  }



  /**
   * Retrieves a list containing the string representations of the values for
   * this argument, if any.  The list returned does not necessarily need to
   * include values that will be acceptable to the argument, but it should imply
   * what the values are (e.g., in the case of a boolean argument that doesn't
   * take a value, it may be the string "true" or "false" even if those values
   * are not acceptable to the argument itself).
   *
   * @param  useDefault  Indicates whether to use any configured default value
   *                     if the argument doesn't have a user-specified value.
   *
   * @return  A string representation of the value for this argument, or an
   *          empty list if the argument does not have a value.
   */
  @NotNull()
  public abstract List<String> getValueStringRepresentations(
                                    boolean useDefault);



  /**
   * Retrieves the description for this argument.
   *
   * @return  The description for this argument.
   */
  @NotNull()
  public final String getDescription()
  {
    return description;
  }



  /**
   * Retrieves the name of the argument group to which this argument belongs.
   *
   * @return  The name of the argument group to which this argument belongs, or
   *          {@code null} if this argument has not been assigned to any group.
   */
  @Nullable()
  public final String getArgumentGroupName()
  {
    return argumentGroupName;
  }



  /**
   * Sets the name of the argument group to which this argument belongs.  If
   * a tool updates arguments to specify an argument group for some or all of
   * the arguments, then the usage information will have the arguments listed
   * together in their respective groups.  Note that usage arguments should
   * generally not be assigned to an argument group.
   *
   * @param  argumentGroupName  The argument group name for this argument.  It
   *                            may be {@code null} if this argument should not
   *                            be assigned to any particular group.
   */
  public final void setArgumentGroupName(
                         @Nullable final String argumentGroupName)
  {
    this.argumentGroupName = argumentGroupName;
  }



  /**
   * Indicates whether this argument should be excluded from usage information.
   *
   * @return  {@code true} if this argument should be excluded from usage
   *          information, or {@code false} if not.
   */
  public final boolean isHidden()
  {
    return isHidden;
  }



  /**
   * Specifies whether this argument should be excluded from usage information.
   *
   * @param  isHidden  Specifies whether this argument should be excluded from
   *                   usage information.
   */
  public final void setHidden(final boolean isHidden)
  {
    this.isHidden = isHidden;
  }



  /**
   * Indicates whether this argument is intended to be used to trigger the
   * display of usage information.  If a usage argument is provided on the
   * command line, then the argument parser will not complain about missing
   * required arguments or unresolved dependencies.
   *
   * @return  {@code true} if this argument is a usage argument, or
   *          {@code false} if not.
   */
  public final boolean isUsageArgument()
  {
    return isUsageArgument;
  }



  /**
   * Specifies whether this argument should be considered a usage argument.
   *
   * @param  isUsageArgument  Specifies whether this argument should be
   *                          considered a usage argument.
   */
  public final void setUsageArgument(final boolean isUsageArgument)
  {
    this.isUsageArgument = isUsageArgument;
  }



  /**
   * Indicates whether this argument was either included in the provided set of
   * command line arguments or has a default value that can be used instead.
   * This method should not be called until after the argument parser has
   * processed the provided set of arguments.
   *
   * @return  {@code true} if this argument was included in the provided set of
   *          command line arguments, or {@code false} if not.
   */
  public final boolean isPresent()
  {
    return ((numOccurrences > 0) || hasDefaultValue());
  }



  /**
   * Retrieves the number of times that this argument was included in the
   * provided set of command line arguments.  This method should not be called
   * until after the argument parser has processed the provided set of
   * arguments.
   *
   * @return  The number of times that this argument was included in the
   *          provided set of command line arguments.
   */
  public final int getNumOccurrences()
  {
    return numOccurrences;
  }



  /**
   * Increments the number of occurrences for this argument in the provided set
   * of command line arguments.  This method should only be called by the
   * argument parser.
   *
   * @throws  ArgumentException  If incrementing the number of occurrences would
   *                             exceed the maximum allowed number.
   */
  final void incrementOccurrences()
        throws ArgumentException
  {
    if (numOccurrences >= maxOccurrences)
    {
      throw new ArgumentException(ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(
                                       getIdentifierString()));
    }

    numOccurrences++;
  }



  /**
   * Adds the provided value to the set of values for this argument.  This
   * method should only be called by the argument parser.
   *
   * @param  valueString  The string representation of the value.
   *
   * @throws  ArgumentException  If the provided value is not acceptable, if
   *                             this argument does not accept values, or if
   *                             this argument already has the maximum allowed
   *                             number of values.
   */
  protected abstract void addValue(@NotNull String valueString)
            throws ArgumentException;



  /**
   * Indicates whether this argument has one or more default values that will be
   * used if it is not provided on the command line.
   *
   * @return  {@code true} if this argument has one or more default values, or
   *          {@code false} if not.
   */
  protected abstract boolean hasDefaultValue();



  /**
   * Indicates whether values of this argument are considered sensitive.
   * Argument values that are considered sensitive will be obscured in places
   * where they may be shown.
   *
   * @return  {@code true} if values of this argument are considered sensitive,
   *          or {@code false} if not.
   */
  public final boolean isSensitive()
  {
    return isSensitive;
  }



  /**
   * Specifies whether values of this argument are considered sensitive.
   * Argument values that are considered sensitive will be obscured in places
   * where they may be shown.
   *
   * @param  isSensitive  Indicates whether values of this argument are
   *                      considered sensitive.
   */
  public final void setSensitive(final boolean isSensitive)
  {
    this.isSensitive = isSensitive;
  }



  /**
   * Indicates whether this argument has been registered with the argument
   * parser.
   *
   * @return  {@code true} if this argument has been registered with the
   *          argument parser, or {@code false} if not.
   */
  boolean isRegistered()
  {
    return isRegistered;
  }



  /**
   * Specifies that this argument has been registered with the argument parser.
   * This method should only be called by the argument parser method used to
   * register the argument.
   *
   * @throws  ArgumentException  If this argument has already been registered.
   */
  void setRegistered()
       throws ArgumentException
  {
    if (isRegistered)
    {
      throw new ArgumentException(ERR_ARG_ALREADY_REGISTERED.get(
                                       getIdentifierString()));
    }

    isRegistered = true;
  }



  /**
   * Retrieves a concise name of the data type with which this argument is
   * associated.
   *
   * @return  A concise name of the data type with which this argument is
   *          associated.
   */
  @NotNull()
  public abstract String getDataTypeName();



  /**
   * Retrieves a human-readable string with information about any constraints
   * that may be imposed for values of this argument.
   *
   * @return  A human-readable string with information about any constraints
   *          that may be imposed for values of this argument, or {@code null}
   *          if there are none.
   */
  @Nullable()
  public String getValueConstraints()
  {
    return null;
  }



  /**
   * Resets this argument so that it appears in the same form as before it was
   * used to parse arguments.  Subclasses that override this method must call
   * {@code super.reset()} to ensure that all necessary reset processing is
   * performed.
   */
  protected void reset()
  {
    numOccurrences = 0;
  }



  /**
   * Creates a copy of this argument that is "clean" and appears as if it has
   * not been used in the course of parsing an argument set.  The new argument
   * will have all of the same identifiers and constraints as this parser.
   *
   * @return  The "clean" copy of this argument.
   */
  @NotNull()
  public abstract Argument getCleanCopy();



  /**
   * Updates the provided list to add any strings that should be included on the
   * command line in order to represent this argument's current state.
   *
   * @param  argStrings  The list to update with the string representation of
   *                     the command-line arguments.
   */
  protected abstract void addToCommandLine(@NotNull List<String> argStrings);



  /**
   * Retrieves a string representation of this argument.
   *
   * @return  A string representation of this argument.
   */
  @NotNull()
  public final String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this argument to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public abstract void toString(@NotNull StringBuilder buffer);



  /**
   * Appends a basic set of information for this argument to the provided
   * buffer in a form suitable for use in the {@code toString} method.
   *
   * @param  buffer  The buffer to which information should be appended.
   */
  protected void appendBasicToStringInfo(@NotNull final StringBuilder buffer)
  {
    switch (shortIdentifiers.size())
    {
      case 0:
        // Nothing to add.
        break;

      case 1:
        buffer.append("shortIdentifier='-");
        buffer.append(shortIdentifiers.keySet().iterator().next());
        buffer.append('\'');
        break;

      default:
        buffer.append("shortIdentifiers={");

        final Iterator<Character> iterator =
             shortIdentifiers.keySet().iterator();
        while (iterator.hasNext())
        {
          buffer.append("'-");
          buffer.append(iterator.next());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }
        buffer.append('}');
        break;
    }

    if (! shortIdentifiers.isEmpty())
    {
      buffer.append(", ");
    }

    switch (longIdentifiers.size())
    {
      case 0:
        // Nothing to add.
        break;

      case 1:
        buffer.append("longIdentifier='--");
        buffer.append(longIdentifiers.keySet().iterator().next());
        buffer.append('\'');
        break;

      default:
        buffer.append("longIdentifiers={");

        final Iterator<String> iterator = longIdentifiers.keySet().iterator();
        while (iterator.hasNext())
        {
          buffer.append("'--");
          buffer.append(iterator.next());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }
        buffer.append('}');
        break;
    }

    buffer.append(", description='");
    buffer.append(description);

    if (argumentGroupName != null)
    {
      buffer.append("', argumentGroup='");
      buffer.append(argumentGroupName);
    }

    buffer.append("', isRequired=");
    buffer.append(isRequired);

    buffer.append(", maxOccurrences=");
    if (maxOccurrences == 0)
    {
      buffer.append("unlimited");
    }
    else
    {
      buffer.append(maxOccurrences);
    }

    if (valuePlaceholder == null)
    {
      buffer.append(", takesValue=false");
    }
    else
    {
      buffer.append(", takesValue=true, valuePlaceholder='");
      buffer.append(valuePlaceholder);
      buffer.append('\'');
    }

    if (isHidden)
    {
      buffer.append(", isHidden=true");
    }
  }
}
