/*
 * Copyright 2008-2010 UnboundID Corp.
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2010 UnboundID Corp.
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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold one or more string
 * values.  String arguments must take values.  By default, any value will be
 * allowed, but it is possible to restrict the set of values so that only values
 * from a specified set (ignoring differences in capitalization) will be
 * allowed.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class StringArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 1088032496970585118L;



  // The set of values assigned to this argument.
  private final ArrayList<String> values;

  // The list of default values that will be used if no values were provided.
  private final List<String> defaultValues;

  // The set of allowed values for this argument.
  private final Set<String> allowedValues;



  /**
   * Creates a new string argument with the provided information.  There will
   * not be any default values, nor will there be any restriction on values that
   * may be assigned to this argument.
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
   *                           indicate that a value must be provided.  It must
   *                           not be {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public StringArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, null, (List<String>) null);
  }



  /**
   * Creates a new string argument with the provided information.  There will
   * not be any default values.
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
   *                           indicate that a value must be provided.  It must
   *                           not be {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  allowedValues     The set of allowed values for this argument, or
   *                           {@code null} if it should not be restricted.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public StringArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final Set<String> allowedValues)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, allowedValues, (List<String>) null);
  }



  /**
   * Creates a new string argument with the provided information.  There will
   * not be any restriction on values that may be assigned to this argument.
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
   *                           indicate that a value must be provided.  It must
   *                           not be {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValue      The default value that will be used for this
   *                           argument if no values are provided.  It may be
   *                           {@code null} if there should not be a default
   *                           value.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public StringArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final String defaultValue)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, null,
         ((defaultValue == null) ? null : Arrays.asList(defaultValue)));
  }



  /**
   * Creates a new string argument with the provided information.  There will
   * not be any restriction on values that may be assigned to this argument.
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
   *                           indicate that a value must be provided.  It must
   *                           not be {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValues     The set of default values that will be used for
   *                           this argument if no values are provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public StringArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final List<String> defaultValues)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, null, defaultValues);
  }



  /**
   * Creates a new string argument with the provided information.
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
   *                           indicate that a value must be provided.  It must
   *                           not be {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  allowedValues     The set of allowed values for this argument, or
   *                           {@code null} if it should not be restricted.
   * @param  defaultValue      The default value that will be used for this
   *                           argument if no values are provided.  It may be
   *                           {@code null} if there should not be a default
   *                           value.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public StringArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final Set<String> allowedValues,
                        final String defaultValue)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, allowedValues,
         ((defaultValue == null) ? null : Arrays.asList(defaultValue)));
  }



  /**
   * Creates a new string argument with the provided information.
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
   *                           indicate that a value must be provided.  It must
   *                           not be {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  allowedValues     The set of allowed values for this argument, or
   *                           {@code null} if it should not be restricted.
   * @param  defaultValues     The set of default values that will be used for
   *                           this argument if no values are provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public StringArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final Set<String> allowedValues,
                        final List<String> defaultValues)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
          valuePlaceholder, description);

    if (valuePlaceholder == null)
    {
      throw new ArgumentException(ERR_ARG_MUST_TAKE_VALUE.get(
                                       getIdentifierString()));
    }

    if ((allowedValues == null) || allowedValues.isEmpty())
    {
      this.allowedValues = null;
    }
    else
    {
      final HashSet<String> lowerValues =
           new HashSet<String>(allowedValues.size());
      for (final String s : allowedValues)
      {
        lowerValues.add(toLowerCase(s));
      }
      this.allowedValues = Collections.unmodifiableSet(lowerValues);
    }

    if ((defaultValues == null) || defaultValues.isEmpty())
    {
      this.defaultValues = null;
    }
    else
    {
      this.defaultValues = Collections.unmodifiableList(defaultValues);
    }

    values = new ArrayList<String>();
  }



  /**
   * Retrieves the set of allowed values for this argument, if applicable.
   *
   * @return  The set of allowed values for this argument, or {@code null} if
   *          there is no restriction on the allowed values.
   */
  public Set<String> getAllowedValues()
  {
    return allowedValues;
  }



  /**
   * Retrieves the list of default values for this argument, which will be used
   * if no values were provided.
   *
   * @return   The list of default values for this argument, or {@code null} if
   *           there are no default values.
   */
  public List<String> getDefaultValues()
  {
    return defaultValues;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(final String valueString)
            throws ArgumentException
  {
    final String lowerValue = toLowerCase(valueString);
    if (allowedValues != null)
    {
      if (! allowedValues.contains(lowerValue))
      {
        throw new ArgumentException(ERR_ARG_VALUE_NOT_ALLOWED.get(
                                         valueString, getIdentifierString()));
      }
    }

    if (values.size() >= getMaxOccurrences())
    {
      throw new ArgumentException(ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(
                                       getIdentifierString()));
    }

    values.add(valueString);
  }



  /**
   * Retrieves the value for this argument, or the default value if none was
   * provided.  If this argument has multiple values, then the first will be
   * returned.
   *
   * @return  The value for this argument, or the default value if none was
   *          provided, or {@code null} if it does not have any values or
   *          default values.
   */
  public String getValue()
  {
    if (values.isEmpty())
    {
      if ((defaultValues == null) || defaultValues.isEmpty())
      {
        return null;
      }
      else
      {
        return defaultValues.get(0);
      }
    }

    return values.get(0);
  }



  /**
   * Retrieves the set of values for this argument, or the default values if
   * none were provided.
   *
   * @return  The set of values for this argument, or the default values if none
   *          were provided.
   */
  public List<String> getValues()
  {
    if (values.isEmpty() && (defaultValues != null))
    {
      return defaultValues;
    }

    return Collections.unmodifiableList(values);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return ((defaultValues != null) && (! defaultValues.isEmpty()));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getDataTypeName()
  {
    return INFO_STRING_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getValueConstraints()
  {
    if ((allowedValues == null) || allowedValues.isEmpty())
    {
      return null;
    }

    final StringBuilder buffer = new StringBuilder();
    buffer.append(INFO_STRING_CONSTRAINTS.get());
    buffer.append("  ");

    final Iterator<String> iterator = allowedValues.iterator();
    while (iterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(iterator.next());
      buffer.append('\'');

      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    return buffer.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("StringArgument(");
    appendBasicToStringInfo(buffer);

    if ((allowedValues != null) && (! allowedValues.isEmpty()))
    {
      buffer.append(", allowedValues={");
      final Iterator<String> iterator = allowedValues.iterator();
      while (iterator.hasNext())
      {
        buffer.append('\'');
        buffer.append(iterator.next());
        buffer.append('\'');

        if (iterator.hasNext())
        {
          buffer.append(", ");
        }
      }
      buffer.append('}');
    }

    if ((defaultValues != null) && (! defaultValues.isEmpty()))
    {
      if (defaultValues.size() == 1)
      {
        buffer.append(", defaultValue='");
        buffer.append(defaultValues.get(0));
      }
      else
      {
        buffer.append(", defaultValues={");

        final Iterator<String> iterator = defaultValues.iterator();
        while (iterator.hasNext())
        {
          buffer.append('\'');
          buffer.append(iterator.next());
          buffer.append('\'');

          if (iterator.hasNext())
          {
            buffer.append(", ");
          }
        }

        buffer.append('}');
      }
    }

    buffer.append(')');
  }
}
