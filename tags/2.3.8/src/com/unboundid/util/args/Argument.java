/*
 * Copyright 2008-2014 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2014 UnboundID Corp.
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
import java.util.List;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotExtensible;
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

  // Indicates whether this argument is used to display usage information.
  private boolean isUsageArgument;

  // The short identifier for this argument, or an empty list if there are none.
  private final ArrayList<Character> shortIdentifiers;

  // The maximum number of times this argument is allowed to be provided.
  private int maxOccurrences;

  // The number of times this argument was included in the provided command line
  // arguments.
  private int numOccurrences;

  // The description for this argument.
  private final String description;

  // The long identifier(s) for this argument, or an empty list if there are
  // none.
  private final ArrayList<String> longIdentifiers;

  // The value placeholder for this argument, or {@code null} if it does not
  // take a value.
  private final String valuePlaceholder;



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
  protected Argument(final Character shortIdentifier,
                     final String longIdentifier,
                     final boolean isRequired, final int maxOccurrences,
                     final String valuePlaceholder, final String description)
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

    shortIdentifiers = new ArrayList<Character>(1);
    if (shortIdentifier != null)
    {
      shortIdentifiers.add(shortIdentifier);
    }

    longIdentifiers = new ArrayList<String>(1);
    if (longIdentifier != null)
    {
      longIdentifiers.add(longIdentifier);
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

    numOccurrences  = 0;
    isHidden        = false;
    isRegistered    = false;
    isUsageArgument = false;
  }



  /**
   * Creates a new argument with the same generic information as the provided
   * argument.  It will not be registered with any argument parser.
   *
   * @param  source  The argument to use as the source for this argument.
   */
  protected Argument(final Argument source)
  {
    isHidden         = source.isHidden;
    isRequired       = source.isRequired;
    isUsageArgument  = source.isUsageArgument;
    maxOccurrences   = source.maxOccurrences;
    description      = source.description;
    valuePlaceholder = source.valuePlaceholder;

    isRegistered   = false;
    numOccurrences = 0;

    shortIdentifiers = new ArrayList<Character>(source.shortIdentifiers);
    longIdentifiers  = new ArrayList<String>(source.longIdentifiers);
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
  public final Character getShortIdentifier()
  {
    if (shortIdentifiers.isEmpty())
    {
      return null;
    }
    else
    {
      return shortIdentifiers.get(0);
    }
  }



  /**
   * Retrieves the list of short identifiers for this argument.
   *
   * @return  The list of short identifiers for this argument, or an empty list
   *          if there are none.
   */
  public final List<Character> getShortIdentifiers()
  {
    return Collections.unmodifiableList(shortIdentifiers);
  }



  /**
   * Adds the provided character to the set of short identifiers for this
   * argument.  Note that this must be called before this argument is registered
   * with the argument parser.
   *
   * @param  c  The character to add to the set of short identifiers for this
   *            argument.  It must not be {@code null}.
   *
   * @throws  ArgumentException  If this argument is already registered with the
   *                             argument parser.
   */
  public final void addShortIdentifier(final Character c)
         throws ArgumentException
  {
    if (isRegistered)
    {
      throw new ArgumentException(ERR_ARG_ID_CHANGE_AFTER_REGISTERED.get(
                                       getIdentifierString()));
    }

    shortIdentifiers.add(c);
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
  public final String getLongIdentifier()
  {
    if (longIdentifiers.isEmpty())
    {
      return null;
    }
    else
    {
      return longIdentifiers.get(0);
    }
  }



  /**
   * Retrieves the list of long identifiers for this argument.
   *
   * @return  The long identifier for this argument, or an empty list if there
   *          are none.
   */
  public final List<String> getLongIdentifiers()
  {
    return Collections.unmodifiableList(longIdentifiers);
  }



  /**
   * Adds the provided string to the set of short identifiers for this argument.
   * Note that this must be called before this argument is registered with the
   * argument parser.
   *
   * @param  s  The string to add to the set of short identifiers for this
   *            argument.  It must not be {@code null}.
   *
   * @throws  ArgumentException  If this argument is already registered with the
   *                             argument parser.
   */
  public final void addLongIdentifier(final String s)
         throws ArgumentException
  {
    if (isRegistered)
    {
      throw new ArgumentException(ERR_ARG_ID_CHANGE_AFTER_REGISTERED.get(
                                       getIdentifierString()));
    }

    longIdentifiers.add(s);
  }



  /**
   * Retrieves a string that may be used to identify this argument.  If a long
   * identifier is defined, then the value returned will be two dashes followed
   * by that string.  Otherwise, the value returned will be a single dash
   * followed by the short identifier.
   *
   * @return  A string that may be used to identify this argument.
   */
  public final String getIdentifierString()
  {
    if (longIdentifiers.isEmpty())
    {
      return "-" + shortIdentifiers.get(0);
    }
    else
    {
      return "--" + longIdentifiers.get(0);
    }
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
  public final String getValuePlaceholder()
  {
    return valuePlaceholder;
  }



  /**
   * Retrieves the description for this argument.
   *
   * @return  The description for this argument.
   */
  public final String getDescription()
  {
    return description;
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
  protected abstract void addValue(final String valueString)
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
  public abstract String getDataTypeName();



  /**
   * Retrieves a human-readable string with information about any constraints
   * that may be imposed for values of this argument.
   *
   * @return  A human-readable string with information about any constraints
   *          that may be imposed for values of this argument, or {@code null}
   *          if there are none.
   */
  public String getValueConstraints()
  {
    return null;
  }



  /**
   * Creates a copy of this argument that is "clean" and appears as if it has
   * not been used in the course of parsing an argument set.  The new argument
   * will have all of the same identifiers and
   *
   * The new parser will have all
   * of the same arguments and constraints as this parser.
   *
   * @return  The "clean" copy of this argument.
   */
  public abstract Argument getCleanCopy();



  /**
   * Retrieves a string representation of this argument.
   *
   * @return  A string representation of this argument.
   */
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
  public abstract void toString(final StringBuilder buffer);



  /**
   * Appends a basic set of information for this argument to the provided
   * buffer in a form suitable for use in the {@code toString} method.
   *
   * @param  buffer  The buffer to which information should be appended.
   */
  protected void appendBasicToStringInfo(final StringBuilder buffer)
  {
    switch (shortIdentifiers.size())
    {
      case 0:
        // Nothing to add.
        break;

      case 1:
        buffer.append("shortIdentifier='-");
        buffer.append(shortIdentifiers.get(0));
        buffer.append('\'');
        break;

      default:
        buffer.append("shortIdentifiers={");

        final Iterator<Character> iterator = shortIdentifiers.iterator();
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
        buffer.append(longIdentifiers.get(0));
        buffer.append('\'');
        break;

      default:
        buffer.append("longIdentifiers={");

        final Iterator<String> iterator = longIdentifiers.iterator();
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
