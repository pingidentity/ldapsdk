/*
 * Copyright 2008-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2008-2018 Ping Identity Corporation
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
import java.util.Iterator;
import java.util.List;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Mutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.Debug.*;
import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold one or more
 * search filter values.  Filter arguments must take values, and those values
 * must be able to be parsed as LDAP search filters.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class FilterArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1889200072476038957L;



  // The set of values assigned to this argument.
  private final ArrayList<Filter> values;

  // The argument value validators that have been registered for this argument.
  private final List<ArgumentValueValidator> validators;

  // The list of default values for this argument.
  private final List<Filter> defaultValues;



  /**
   * Creates a new filter argument with the provided information.  It will not
   * be required, will permit at most one occurrence, will use a default
   * placeholder, and will not have a default value.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FilterArgument(final Character shortIdentifier,
                        final String longIdentifier, final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, 1, null, description);
  }



  /**
   * Creates a new filter argument with the provided information.  It will not
   * have a default value.
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
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FilterArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, (List<Filter>) null);
  }



  /**
   * Creates a new filter argument with the provided information.
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
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValue      The default value to use for this argument if no
   *                           values were provided.  It may be {@code null} if
   *                           there should be no default values.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FilterArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final Filter defaultValue)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired, maxOccurrences,
         valuePlaceholder, description,
         ((defaultValue == null) ? null : Arrays.asList(defaultValue)));
  }



  /**
   * Creates a new filter argument with the provided information.
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
   *                           indicate that a value must be provided.  It may
   *                           be {@code null} if a default placeholder should
   *                           be used.
   * @param  description       A human-readable description for this argument.
   *                           It must not be {@code null}.
   * @param  defaultValues     The set of default values to use for this
   *                           argument if no values were provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public FilterArgument(final Character shortIdentifier,
                        final String longIdentifier, final boolean isRequired,
                        final int maxOccurrences, final String valuePlaceholder,
                        final String description,
                        final List<Filter> defaultValues)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_FILTER.get()
              : valuePlaceholder,
         description);

    if ((defaultValues == null) || defaultValues.isEmpty())
    {
      this.defaultValues = null;
    }
    else
    {
      this.defaultValues = Collections.unmodifiableList(defaultValues);
    }

    values = new ArrayList<Filter>(5);
    validators = new ArrayList<ArgumentValueValidator>(5);
  }



  /**
   * Creates a new filter argument that is a "clean" copy of the provided source
   * argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private FilterArgument(final FilterArgument source)
  {
    super(source);

    defaultValues = source.defaultValues;
    validators    = new ArrayList<ArgumentValueValidator>(source.validators);
    values        = new ArrayList<Filter>(5);
  }



  /**
   * Retrieves the list of default values for this argument, which will be used
   * if no values were provided.
   *
   * @return   The list of default values for this argument, or {@code null} if
   *           there are no default values.
   */
  public List<Filter> getDefaultValues()
  {
    return defaultValues;
  }



  /**
   * Updates this argument to ensure that the provided validator will be invoked
   * for any values provided to this argument.  This validator will be invoked
   * after all other validation has been performed for this argument.
   *
   * @param  validator  The argument value validator to be invoked.  It must not
   *                    be {@code null}.
   */
  public void addValueValidator(final ArgumentValueValidator validator)
  {
    validators.add(validator);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(final String valueString)
            throws ArgumentException
  {
    final Filter filter;
    try
    {
      filter = Filter.create(valueString);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new ArgumentException(ERR_FILTER_VALUE_NOT_FILTER.get(valueString,
                                       getIdentifierString(), le.getMessage()),
                                  le);
    }

    if (values.size() >= getMaxOccurrences())
    {
      throw new ArgumentException(ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(
                                       getIdentifierString()));
    }

    for (final ArgumentValueValidator v : validators)
    {
      v.validateArgumentValue(this, valueString);
    }

    values.add(filter);
  }



  /**
   * Retrieves the value for this argument, or the default value if none was
   * provided.  If there are multiple values, then the first will be returned.
   *
   * @return  The value for this argument, or the default value if none was
   *          provided, or {@code null} if there is no value and no default
   *          value.
   */
  public Filter getValue()
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
    else
    {
      return values.get(0);
    }
  }



  /**
   * Retrieves the set of values for this argument, or the default values if
   * none were provided.
   *
   * @return  The set of values for this argument, or the default values if none
   *          were provided.
   */
  public List<Filter> getValues()
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
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    final List<Filter> filters;
    if (values.isEmpty())
    {
      if (useDefault)
      {
        filters = defaultValues;
      }
      else
      {
        return Collections.emptyList();
      }
    }
    else
    {
      filters = values;
    }

    if ((filters == null) || filters.isEmpty())
    {
      return Collections.emptyList();
    }

    final ArrayList<String> valueStrings =
         new ArrayList<String>(filters.size());
    for (final Filter f : filters)
    {
      valueStrings.add(f.toString());
    }
    return Collections.unmodifiableList(valueStrings);
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
    return INFO_FILTER_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getValueConstraints()
  {
    return INFO_FILTER_CONSTRAINTS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void reset()
  {
    super.reset();
    values.clear();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public FilterArgument getCleanCopy()
  {
    return new FilterArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(final List<String> argStrings)
  {
    if (values != null)
    {
      for (final Filter f : values)
      {
        argStrings.add(getIdentifierString());
        if (isSensitive())
        {
          argStrings.add("***REDACTED***");
        }
        else
        {
          argStrings.add(f.toString());
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append("FilterArgument(");
    appendBasicToStringInfo(buffer);

    if ((defaultValues != null) && (! defaultValues.isEmpty()))
    {
      if (defaultValues.size() == 1)
      {
        buffer.append(", defaultValue='");
        buffer.append(defaultValues.get(0).toString());
      }
      else
      {
        buffer.append(", defaultValues={");

        final Iterator<Filter> iterator = defaultValues.iterator();
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

        buffer.append('}');
      }
    }

    buffer.append(')');
  }
}
