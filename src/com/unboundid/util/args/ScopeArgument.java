/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.util.args.ArgsMessages.*;



/**
 * This class defines an argument that is intended to hold one search scope
 * values.  Scope arguments must take values, and those arguments must represent
 * valid search scopes.  Supported scope values include:
 * <UL>
 *   <LI>baseObject scope -- base, baseObject, base-object, 0</LI>
 *   <LI>singleLevel scope -- one, singleLevel, single-level, oneLevel,
 *       one-level, 1</LI>
 *   <LI>wholeSubtree scope -- sub, subtree, wholeSubtree, whole-subtree, 2</LI>
 *   <LI>subordinateSubtree scope -- subord, subordinate, subordinates,
 *       subordinateSubtree, subordinate-subtree, 3</LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class ScopeArgument
       extends Argument
{
  /**
   * A map of value strings to the corresponding search scopes.
   */
  @NotNull private static final Map<String,SearchScope> SCOPE_STRINGS;

  static
  {
    final HashMap<String,SearchScope> scopeMap =
         new HashMap<>(StaticUtils.computeMapCapacity(21));

    scopeMap.put("base", SearchScope.BASE);
    scopeMap.put("baseobject", SearchScope.BASE);
    scopeMap.put("base-object", SearchScope.BASE);
    scopeMap.put("0", SearchScope.BASE);

    scopeMap.put("one", SearchScope.ONE);
    scopeMap.put("singlelevel", SearchScope.ONE);
    scopeMap.put("single-level", SearchScope.ONE);
    scopeMap.put("onelevel", SearchScope.ONE);
    scopeMap.put("one-level", SearchScope.ONE);
    scopeMap.put("1", SearchScope.ONE);

    scopeMap.put("sub", SearchScope.SUB);
    scopeMap.put("subtree", SearchScope.SUB);
    scopeMap.put("wholesubtree", SearchScope.SUB);
    scopeMap.put("whole-subtree", SearchScope.SUB);
    scopeMap.put("2", SearchScope.SUB);

    scopeMap.put("subord", SearchScope.SUBORDINATE_SUBTREE);
    scopeMap.put("subordinate", SearchScope.SUBORDINATE_SUBTREE);
    scopeMap.put("subordinates", SearchScope.SUBORDINATE_SUBTREE);
    scopeMap.put("subordinatesubtree", SearchScope.SUBORDINATE_SUBTREE);
    scopeMap.put("subordinate-subtree", SearchScope.SUBORDINATE_SUBTREE);
    scopeMap.put("3", SearchScope.SUBORDINATE_SUBTREE);

    SCOPE_STRINGS = Collections.unmodifiableMap(scopeMap);
  }



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5962857448814911423L;



  // The value assigned to this argument.
  @NotNull private final AtomicReference<SearchScope> value;

  // The default value for this argument.
  @Nullable private final SearchScope defaultValue;



  /**
   * Creates a new search scope argument with the provided information.  It will
   * not be required, will use a default placeholder, and will not have a
   * default value.
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
  public ScopeArgument(@Nullable final Character shortIdentifier,
                       @Nullable final String longIdentifier,
                       @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, false, null, description);
  }



  /**
   * Creates a new search scope argument with the provided information.  It will
   * not have a default value.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
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
  public ScopeArgument(@Nullable final Character shortIdentifier,
                       @Nullable final String longIdentifier,
                       final boolean isRequired,
                       @Nullable final String valuePlaceholder,
                       @NotNull final String description)
         throws ArgumentException
  {
    this(shortIdentifier, longIdentifier, isRequired,  valuePlaceholder,
         description, null);
  }



  /**
   * Creates a new search scope argument with the provided information.
   *
   * @param  shortIdentifier   The short identifier for this argument.  It may
   *                           not be {@code null} if the long identifier is
   *                           {@code null}.
   * @param  longIdentifier    The long identifier for this argument.  It may
   *                           not be {@code null} if the short identifier is
   *                           {@code null}.
   * @param  isRequired        Indicates whether this argument is required to
   *                           be provided.
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
  public ScopeArgument(@Nullable final Character shortIdentifier,
                       @Nullable final String longIdentifier,
                       final boolean isRequired,
                       @Nullable final String valuePlaceholder,
                       @NotNull final String description,
                       @Nullable final SearchScope defaultValue)
         throws ArgumentException
  {
    super(shortIdentifier, longIdentifier, isRequired,  1,
         (valuePlaceholder == null)
              ? INFO_PLACEHOLDER_SCOPE.get()
              : valuePlaceholder,
         description);

    this.defaultValue = defaultValue;

    value = new AtomicReference<>();
  }



  /**
   * Creates a new scope argument that is a "clean" copy of the provided
   * source argument.
   *
   * @param  source  The source argument to use for this argument.
   */
  private ScopeArgument(@NotNull final ScopeArgument source)
  {
    super(source);

    defaultValue = source.defaultValue;
    value        = new AtomicReference<>();
  }



  /**
   * Retrieves the default value for this argument, which will be used if no
   * value was provided.
   *
   * @return  The default value for this argument, or {@code null} if there is
   *          no default value.
   */
  @Nullable()
  public SearchScope getDefaultValue()
  {
    return defaultValue;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addValue(@NotNull final String valueString)
            throws ArgumentException
  {
    final SearchScope scope =
         SCOPE_STRINGS.get(StaticUtils.toLowerCase(valueString));
    if (scope == null)
    {
      throw new ArgumentException(ERR_SCOPE_VALUE_NOT_VALID.get(valueString,
           getIdentifierString()));
    }

    if (! value.compareAndSet(null, scope))
    {
      throw new ArgumentException(ERR_ARG_MAX_OCCURRENCES_EXCEEDED.get(
                                       getIdentifierString()));
    }
  }



  /**
   * Retrieves the value for this argument, or the default value if none was
   * provided.
   *
   * @return  The value for this argument, or the default value if none was
   *          provided, or {@code null} if there is no value and no default
   *          value.
   */
  @Nullable()
  public SearchScope getValue()
  {
    final SearchScope s = value.get();
    if (s == null)
    {
      return defaultValue;
    }
    else
    {
      return s;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<String> getValueStringRepresentations(final boolean useDefault)
  {
    SearchScope s = value.get();
    if (useDefault && (s == null))
    {
      s = defaultValue;
    }

    if (s == null)
    {
      return Collections.emptyList();
    }

    final String scopeStr;
    switch (s.intValue())
    {
      case SearchScope.BASE_INT_VALUE:
        scopeStr = "base";
        break;
      case SearchScope.ONE_INT_VALUE:
        scopeStr = "one";
        break;
      case SearchScope.SUB_INT_VALUE:
        scopeStr = "sub";
        break;
      case SearchScope.SUBORDINATE_SUBTREE_INT_VALUE:
        scopeStr = "subordinates";
        break;
      default:
        scopeStr = s.getName();
        break;
    }

    return Collections.singletonList(scopeStr);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected boolean hasDefaultValue()
  {
    return (defaultValue != null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDataTypeName()
  {
    return INFO_SCOPE_TYPE_NAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getValueConstraints()
  {
    return INFO_SCOPE_CONSTRAINTS.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void reset()
  {
    super.reset();
    value.set(null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ScopeArgument getCleanCopy()
  {
    return new ScopeArgument(this);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected void addToCommandLine(@NotNull final List<String> argStrings)
  {
    final SearchScope s = value.get();
    if (s != null)
    {
      if (isSensitive())
      {
        argStrings.add(getIdentifierString());
        argStrings.add("***REDACTED***");
        return;
      }

      switch (s.intValue())
      {
        case SearchScope.BASE_INT_VALUE:
          argStrings.add(getIdentifierString());
          argStrings.add("base");
          break;
        case SearchScope.ONE_INT_VALUE:
          argStrings.add(getIdentifierString());
          argStrings.add("one");
          break;
        case SearchScope.SUB_INT_VALUE:
          argStrings.add(getIdentifierString());
          argStrings.add("sub");
          break;
        case SearchScope.SUBORDINATE_SUBTREE_INT_VALUE:
          argStrings.add(getIdentifierString());
          argStrings.add("subordinates");
          break;
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ScopeArgument(");
    appendBasicToStringInfo(buffer);

    if (defaultValue != null)
    {
      buffer.append(", defaultValue='");
      switch (defaultValue.intValue())
      {
        case SearchScope.BASE_INT_VALUE:
          buffer.append("base");
          break;
        case SearchScope.ONE_INT_VALUE:
          buffer.append("one");
          break;
        case SearchScope.SUB_INT_VALUE:
          buffer.append("sub");
          break;
        case SearchScope.SUBORDINATE_SUBTREE_INT_VALUE:
          buffer.append("subordinate");
          break;
        default:
          buffer.append(defaultValue.intValue());
          break;
      }
      buffer.append('\'');
    }

    buffer.append(')');
  }
}
