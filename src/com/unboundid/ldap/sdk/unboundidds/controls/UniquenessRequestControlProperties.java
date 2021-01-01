/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure that holds a set of properties for use
 * in conjunction with the {@link UniquenessRequestControl}.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and
 *   Nokia/Alcatel-Lucent 8661 server products.  These classes provide support
 *   for proprietary functionality or for external specifications that are not
 *   considered stable or mature enough to be guaranteed to work in an
 *   interoperable way with other types of LDAP servers.
 * </BLOCKQUOTE>
 * <BR>
 * The control must be created with either a set of attribute types or a filter
 * (or both).  See the {@link UniquenessRequestControl} class-level
 * documentation for details about how the server will behave if either or both
 * of these values are provided.
 * <BR><BR>
 * The following default values will be used for properties that are not
 * specified:
 * <UL>
 *   <LI>
 *     An empty set of attribute types.
 *   </LI>
 *   <LI>
 *     A multiple attribute behavior of
 *     {@link UniquenessMultipleAttributeBehavior#UNIQUE_WITHIN_EACH_ATTRIBUTE}.
 *   </LI>
 *   <LI>
 *     No base DN.
 *   </LI>
 *   <LI>
 *     No filter.
 *   </LI>
 *   <LI>
 *     The control will not prevent conflicts with soft-deleted entries.
 *   </LI>
 *   <LI>
 *     A pre-commit validation level of
 *     {@link UniquenessValidationLevel#ALL_SUBTREE_VIEWS}.
 *   </LI>
 *   <LI>
 *     A post-commit validation level of
 *     {@link UniquenessValidationLevel#ALL_SUBTREE_VIEWS}.
 *   </LI>
 *   <LI>
 *     Do alert on conflicts detected during post-commit validation.
 *   </LI>
 *   <LI>
 *     Do not create a conflict prevention details entry.
 *   </LI>
 * </UL>
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class UniquenessRequestControlProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4330352906527176309L;



  // Indicates whether the server should raise an administrative alert if a
  // conflict is detected during post-commit validation.
  private boolean alertOnPostCommitConflictDetection = true;

  // Indicates whether the server should create a conflict prevention details
  // entry before pre-commit validation as a means of helping to avoid
  // conflicts.
  private boolean createConflictPreventionDetailsEntry = false;

  // Indicates whether to prevent conflicts with soft-deleted entries.
  private boolean preventConflictsWithSoftDeletedEntries = false;

  // An optional filter that should be used in the course of identifying
  // uniqueness conflicts.
  @Nullable private Filter filter = null;

  // A potentially-empty set of attribute types that should be checked for
  // uniqueness conflicts.
  @NotNull private Set<String> attributeTypes = Collections.emptySet();

  // An optional base DN to use when checking for conflicts.
  @Nullable private String baseDN = null;

  // The behavior that the server should exhibit if multiple attribute types
  // are configured.
  @NotNull private
       UniquenessMultipleAttributeBehavior multipleAttributeBehavior =
            UniquenessMultipleAttributeBehavior.UNIQUE_WITHIN_EACH_ATTRIBUTE;

  // The level of validation that the server should perform before processing
  // the associated change.
  @NotNull private UniquenessValidationLevel postCommitValidationLevel =
       UniquenessValidationLevel.ALL_SUBTREE_VIEWS;

  // The level of validation that the server should perform after processing the
  // associated change.
  @NotNull private UniquenessValidationLevel preCommitValidationLevel =
       UniquenessValidationLevel.ALL_SUBTREE_VIEWS;



  /**
   * Creates a new instance of this uniqueness request control properties object
   * with no attribute types and all default values.  This is primarily intended
   * for supporting deserialization, since it will not include any .
   */
  private UniquenessRequestControlProperties()
  {
    // No implementation is required.
  }



  /**
   * Creates a new instance of this uniqueness request control properties object
   * with the provided set of attribute types and default values for all other
   * properties as specified in the class-level javadoc documentation.
   *
   * @param  attributeTypes  The set of attribute types that the server will
   *                         check for uniqueness conflicts.  It must not be
   *                         {@code null} or empty.  The server should be
   *                         configured with equality indexes for each of these
   *                         attribute types.
   */
  public UniquenessRequestControlProperties(
              @NotNull final String... attributeTypes)
  {
    this();

    Validator.ensureTrue(
         ((attributeTypes != null) && (attributeTypes.length > 0)),
         "The set of attribute types must not be null or empty.");
    this.attributeTypes = Collections.unmodifiableSet(new LinkedHashSet<>(
         StaticUtils.toList(attributeTypes)));
  }



  /**
   * Creates a new instance of this uniqueness request control properties object
   * with the provided set of attribute types and default values for all other
   * properties as specified in the class-level javadoc documentation.
   *
   * @param  attributeTypes  The set of attribute types that the server will
   *                         check for uniqueness conflicts.  It must not be
   *                         {@code null} or empty.  The server should be
   *                         configured with equality indexes for each of these
   *                         attribute types.
   */
  public UniquenessRequestControlProperties(
              @NotNull final Collection<String> attributeTypes)
  {
    this();

    Validator.ensureTrue(
         ((attributeTypes != null) && (! attributeTypes.isEmpty())),
         "The set of attribute types must not be null or empty.");
    this.attributeTypes =
         Collections.unmodifiableSet(new LinkedHashSet<>(attributeTypes));
  }



  /**
   * Creates a new instance of this uniqueness request control properties object
   * with the provided filter and default values for all other properties as
   * specified in the class-level javadoc documentation.
   *
   * @param  filter  The filter that the server will use to check for uniqueness
   *                 conflicts.  It must not be {@code null}.
   */
  public UniquenessRequestControlProperties(@NotNull final Filter filter)
  {
    this();

    Validator.ensureNotNull(filter);
    this.filter = filter;
  }



  /**
   * Retrieves the set of attribute types that the server will check for
   * uniqueness conflicts.
   *
   * @return  The set of attribute types that the server will check for
   *          uniqueness conflicts, or an empty set if only a filter should be
   *          used to identify conflicts.
   */
  @NotNull()
  public Set<String> getAttributeTypes()
  {
    return attributeTypes;
  }



  /**
   * Specifies the set of attribute types that the server will check for
   * uniqueness conflicts.
   *
   * @param  attributeTypes  The set of attribute types that the server will
   *                         check for uniqueness conflicts.  It must not be
   *                         {@code null} or empty if no filter is configured.
   *                         It may optionally be {@code null} or empty if
   *                         a filter is provided.  The server should be
   *                         configured with an equality index for each of the
   *                         provided attribute types.
   */
  public void setAttributeTypes(@Nullable final String... attributeTypes)
  {
    if (attributeTypes == null)
    {
      this.attributeTypes = Collections.emptySet();
    }
    else
    {
      this.attributeTypes = Collections.unmodifiableSet(new LinkedHashSet<>(
           StaticUtils.toList(attributeTypes)));
    }
  }



  /**
   * Specifies the set of attribute types that the server will check for
   * uniqueness conflicts.
   *
   * @param  attributeTypes  The set of attribute types that the server will
   *                         check for uniqueness conflicts.  It must not be
   *                         {@code null} or empty if no filter is configured.
   *                         It may optionally be {@code null} or empty if
   *                         a filter is provided.  The server should be
   *                         configured with an equality index for each of the
   *                         provided attribute types.
   */
  public void setAttributeTypes(
                   @Nullable final Collection<String> attributeTypes)
  {
    if (attributeTypes == null)
    {
      this.attributeTypes = Collections.emptySet();
    }
    else
    {
      this.attributeTypes =
           Collections.unmodifiableSet(new LinkedHashSet<>(attributeTypes));
    }
  }



  /**
   * Retrieves the behavior that the server should exhibit if multiple attribute
   * types are configured.
   *
   * @return  The behavior that the server should exhibit if multiple attribute
   *          types are configured.
   */
  @NotNull()
  public UniquenessMultipleAttributeBehavior getMultipleAttributeBehavior()
  {
    return multipleAttributeBehavior;
  }



  /**
   * Specifies the behavior that the server should exhibit if multiple attribute
   * types are configured.
   *
   * @param  multipleAttributeBehavior  The behavior that the server should
   *                                    exhibit if multiple attribute types are
   *                                    configured.  This must not be
   *                                    {@code null}.
   */
  public void setMultipleAttributeBehavior(
       @NotNull
       final UniquenessMultipleAttributeBehavior multipleAttributeBehavior)
  {
    Validator.ensureNotNull(multipleAttributeBehavior);
    this.multipleAttributeBehavior = multipleAttributeBehavior;
  }



  /**
   * Retrieves the base DN that will be used for searches used to identify
   * uniqueness conflicts, if defined.
   *
   * @return  The base DN that will be used for searches used to identify
   *          uniqueness conflicts, or {@code null} if the server should search
   *          below all public naming contexts.
   */
  @Nullable()
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Specifies the base DN that will be used for searches used to identify
   * uniqueness conflicts.
   *
   * @param  baseDN  The base DN that will be used for searches used to identify
   *                 uniqueness conflicts.  It may be {@code null} to indicate
   *                 that the server should search below all public naming
   *                 contexts.
   */
  public void setBaseDN(@Nullable final String baseDN)
  {
    this.baseDN = baseDN;
  }



  /**
   * Retrieves a filter that will be used to identify uniqueness conflicts, if
   * defined.
   *
   * @return  A filter that will be used to identify uniqueness conflicts, or
   *          {@code null} if no filter has been defined.
   */
  @Nullable()
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Specifies a filter that will be used to identify uniqueness conflicts.
   *
   * @param  filter  A filter that will be used to identify uniqueness
   *                 conflicts.  It must not be {@code null} if no set of
   *                 attribute types has been configured.  It may optionally be
   *                 {@code null} if a set of attribute types has been
   *                 configured.  If no attribute types are provided, then this
   *                 filter should be indexed within the server.
   */
  public void setFilter(@Nullable final Filter filter)
  {
    this.filter = filter;
  }



  /**
   * Indicates whether the server should attempt to identify conflicts with
   * soft-deleted entries.
   *
   * @return  {@code true} if the server should identify conflicts with both
   *          regular entries and soft-deleted entries, or {@code false} if the
   *          server should only identify conflicts with regular entries.
   */
  public boolean preventConflictsWithSoftDeletedEntries()
  {
    return preventConflictsWithSoftDeletedEntries;
  }



  /**
   * Specifies whether the server should attempt to identify conflicts with
   * soft-deleted entries.
   *
   * @param  preventConflictsWithSoftDeletedEntries  Indicates whether the
   *                                                 server should attempt to
   *                                                 identify conflicts with
   *                                                 soft-deleted entries.
   */
  public void setPreventConflictsWithSoftDeletedEntries(
                   final boolean preventConflictsWithSoftDeletedEntries)
  {
    this.preventConflictsWithSoftDeletedEntries =
         preventConflictsWithSoftDeletedEntries;
  }



  /**
   * Retrieves the pre-commit validation level, which will be used to identify
   * any conflicts before the associated request is processed.
   *
   * @return  The pre-commit validation level.
   */
  @NotNull()
  public UniquenessValidationLevel getPreCommitValidationLevel()
  {
    return preCommitValidationLevel;
  }



  /**
   * Specifies the pre-commit validation level, which will be used to identify
   * any conflicts before the associated request is processed.
   *
   * @param  preCommitValidationLevel  The pre-commit validation level.  It must
   *                                   not be {@code null}.
   */
  public void setPreCommitValidationLevel(
       @NotNull final UniquenessValidationLevel preCommitValidationLevel)
  {
    Validator.ensureNotNull(preCommitValidationLevel);
    this.preCommitValidationLevel = preCommitValidationLevel;
  }



  /**
   * Retrieves the post-commit validation level, which will be used to identify
   * any conflicts that were introduced by the request with which the control is
   * associated, or by some other concurrent changed processed in the server.
   *
   * @return  The post-commit validation level.
   */
  @NotNull()
  public UniquenessValidationLevel getPostCommitValidationLevel()
  {
    return postCommitValidationLevel;
  }



  /**
   * Specifies the post-commit validation level, which will be used to identify
   * any conflicts that were introduced by the request with which the control is
   * associated, or by some other concurrent changed processed in the server.
   *
   * @param  postCommitValidationLevel  The post-commit validation level.  It
   *                                    must not be {@code null}.
   */
  public void setPostCommitValidationLevel(
       @NotNull final UniquenessValidationLevel postCommitValidationLevel)
  {
    Validator.ensureNotNull(postCommitValidationLevel);
    this.postCommitValidationLevel = postCommitValidationLevel;
  }



  /**
   * Indicates whether the server should raise an administrative alert if a
   * conflict is detected during post-commit validation processing.
   *
   * @return  {@code true} if the server should raise an administrative alert if
   *          a conflict is detected during post-commit validation processing,
   *          or {@code false} if not.
   */
  public boolean alertOnPostCommitConflictDetection()
  {
    return alertOnPostCommitConflictDetection;
  }



  /**
   * Specifies whether the server should raise an administrative alert if a
   * conflict is detected during post-commit validation processing.
   *
   * @param  alertOnPostCommitConflictDetection  Indicates whether the server
   *                                             should raise an administrative
   *                                             alert if a conflict is detected
   *                                             during post-commit validation
   *                                             processing.
   */
  public void setAlertOnPostCommitConflictDetection(
                   final boolean alertOnPostCommitConflictDetection)
  {
    this.alertOnPostCommitConflictDetection =
         alertOnPostCommitConflictDetection;
  }



  /**
   * Indicates whether the server should create a temporary conflict prevention
   * details entry before beginning pre-commit validation to provide better
   * support for preventing conflicts.  If created, the entry will be removed
   * after post-commit validation processing has completed.
   *
   * @return  {@code true} if the server should create a temporary conflict
   *          prevention details entry before beginning pre-commit validation,
   *          or {@code false} if not.
   */
  public boolean createConflictPreventionDetailsEntry()
  {
    return createConflictPreventionDetailsEntry;
  }



  /**
   * Specifies whether the server should create a temporary conflict prevention
   * details entry before beginning pre-commit validation to provide better
   * support for preventing conflicts.  If created, the entry will be removed
   * after post-commit validation processing has completed.
   *
   * @param  createConflictPreventionDetailsEntry  Indicates whether the server
   *                                               should create a temporary
   *                                               conflict prevention details
   *                                               entry before beginning
   *                                               pre-commit validation.
   */
  public void setCreateConflictPreventionDetailsEntry(
                   final boolean createConflictPreventionDetailsEntry)
  {
    this.createConflictPreventionDetailsEntry =
         createConflictPreventionDetailsEntry;
  }



  /**
   * Retrieves a string representation of this uniqueness request control
   * properties object.
   *
   * @return  A string representation of this uniqueness request control
   *          properties object.
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
   * Appends a string representation of this uniqueness request control
   * properties object to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("UniquenessRequestControlProperties(attributeTypes={");

    final Iterator<String> attributeTypesIterator = attributeTypes.iterator();
    while (attributeTypesIterator.hasNext())
    {
      buffer.append('\'');
      buffer.append(attributeTypesIterator.next());
      buffer.append('\'');

      if (attributeTypesIterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("}, multipleAttributeBehavior=");
    buffer.append(multipleAttributeBehavior);

    if (baseDN != null)
    {
      buffer.append(", baseDN='");
      buffer.append(baseDN);
      buffer.append('\'');
    }

    if (filter != null)
    {
      buffer.append(", filter='");
      buffer.append(filter);
      buffer.append('\'');
    }

    buffer.append(", preventConflictsWithSoftDeletedEntries=");
    buffer.append(preventConflictsWithSoftDeletedEntries);
    buffer.append(", preCommitValidationLevel=");
    buffer.append(preCommitValidationLevel);
    buffer.append(", postCommitValidationLevel=");
    buffer.append(postCommitValidationLevel);
    buffer.append(", alertOnPostCommitConflictDetection=");
    buffer.append(alertOnPostCommitConflictDetection);
    buffer.append(", createConflictPreventionDetailsEntry=");
    buffer.append(createConflictPreventionDetailsEntry);
    buffer.append(')');
  }
}
