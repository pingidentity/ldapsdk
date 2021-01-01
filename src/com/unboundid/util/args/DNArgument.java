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



import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.util.Debug;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold one or more
 * distinguished name values.  DN arguments must take values, and those values
 * must be able to be parsed as distinguished names.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class DNArgument
       extends Argument
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7956577383262400167L;



  // The set of values assigned to this argument.
  @NotNull private final ArrayList<DN> values;

  // The argument value validators that have been registered for this argument.
  @NotNull private final List<ArgumentValueValidator> validators;

  // The list of default values for this argument.
  @Nullable private final List<DN> defaultValues;



  /**
   * Creates a new DN argument with the provided information.  It will not be
   * required, will permit at most one occurrence, will use a default
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
  public DNArgument(@Nullable final Character shortIdentifier,
                    @Nullable final String longIdentifier,
                    @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, 1, null, description);
  }



  /**
   * Creates a new DN argument with the provided information.  It will not have
   * a default value.
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
  public DNArgument(@Nullable final Character shortIdentifier,
                    @Nullable final String longIdentifier,
                    final boolean isRequired,
                    final int maxOccurrences,
                    @Nullable final String valuePlaceholder,
                    @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         valuePlaceholder, description, (List<DN>) null);
  }



  /**
   * Creates a new DN argument with the provided information.
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
   *                           values were provided.
   *
   * @throws  ArgumentException  If there is a problem with the definition of
   *                             this argument.
   */
  public DNArgument(@Nullable final Character shortIdentifier,
                    @Nullable final String longIdentifier,
                    final boolean isRequired, final int maxOccurrences,
                    @Nullable final String valuePlaceholder,
                    @NotNull final String description,
                    @Nullable final DN defaultValue)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired, maxOccurrences,
         valuePlaceholder, description,
         ((defaultValue == null)
              ? null :
              Collections.singletonList(defaultValue)));
  }



  /**
   * Creates a new DN argument with the provided information.
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
  public DNArgument(@Nullable final Character shortIdentifier,
                    @Nullable final String longIdentifier,
                    final boolean isRequired, final int maxOccurrences,
                    @Nullable final String valuePlaceholder,
                    @NotNull final String description,
                    @Nullable final List<DN> defaultValues)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  maxOccurrences,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_DN.get()
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

    values = new ArrayList<>(5);
    validators = new ArrayList<>(5);
  }



  /**
   * Creates a new DN argument that is a "clean" copy of the provided source
   * argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private DNArgument(@NotNull final DNArgument source)
  {
    super(source);

    defaultValues = source.defaultValues;
    values        = new ArrayList<>(5);
    validators    = new ArrayList<>(source.validators);
  }



  /**
   * Retrieves the list of default values for this argument, which will be used
   * if no values were provided.
   *
   * @return   The list of default values for this argument, or {@code null} if
   *           there are no default values.
   */
  @Nullable()
  public List<DN> getDefaultValues()
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
  public void addValueValidator(@NotNull final ArgumentValueValidator validator)
  {
    validators.add(validator);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(@NotNull final String valueString)
            throws ArgumentException
  {
    final DN parsedDN;
    try
    {
      parsedDN = new DN(valueString);
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw new ArgumentException(ERR_DN_VALUE_NOT_DN.get(valueString,
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

    values.add(parsedDN);
  }



  /**
   * Retrieves the value for this argument, or the default value if none was
   * provided.  If there are multiple values, then the first will be returned.
   *
   * @return  The value for this argument, or the default value if none was
   *          provided, or {@code null} if there is no value and no default
   *          value.
   */
  @Nullable()
  public DN getValue()
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
   * Retrieves the set of values for this argument.
   *
   * @return  The set of values for this argument.
   */
  @NotNull()
  public List<DN> getValues()
  {
    if (values.isEmpty() && (defaultValues != null))
    {
      return defaultValues;
    }

    return Collections.unmodifiableList(values);
  }



  /**
   * Retrieves a string representation of the value for this argument, or a
   * string representation of the default value if none was provided.  If there
   * are multiple values, then the first will be returned.
   *
   * @return  The string representation of the value for this argument, or the
   *          string representation of the default value if none was provided,
   *          or {@code null} if there is no value and no default value.
   */
  @Nullable()
  public String getStringValue()
  {
    final DN valueDN = getValue();
    if (valueDN == null)
    {
      return null;
    }

    return valueDN.toString();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    if (values.isEmpty())
    {
      if (useDefault && (defaultValues != null))
      {
        final ArrayList<String> valueStrings =
             new ArrayList<>(defaultValues.size());
        for (final DN dn : defaultValues)
        {
          valueStrings.add(dn.toString());
        }
        return Collections.unmodifiableList(valueStrings);
      }
      else
      {
        return Collections.emptyList();
      }
    }
    else
    {
      final ArrayList<String> valueStrings = new ArrayList<>(values.size());
      for (final DN dn : values)
      {
        valueStrings.add(dn.toString());
      }
      return Collections.unmodifiableList(valueStrings);
    }
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
  @NotNull()
  public String getDataTypeName()
  {
    return INFO_DN_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    return INFO_DN_CONSTRAINTS.get();
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
  @NotNull()
  public DNArgument getCleanCopy()
  {
    return new DNArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    for (final DN dn : values)
    {
      argStrings.add(getIdentifierString());
      if (isSensitive())
      {
        argStrings.add("***REDACTED***");
      }
      else
      {
        argStrings.add(String.valueOf(dn));
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DNArgument(");
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

        final Iterator<DN> iterator = defaultValues.iterator();
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
