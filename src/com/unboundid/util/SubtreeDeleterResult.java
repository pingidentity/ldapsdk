/*
 * Copyright 2019-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2019-2021 Ping Identity Corporation
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
 * Copyright (C) 2019-2021 Ping Identity Corporation
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
import java.util.Collections;
import java.util.SortedMap;
import java.util.TreeMap;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.SearchResult;



/**
 * This class provides a data structure with information about the results of
 * a subtree delete attempt.
 *
 * @see  SubtreeDeleter
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SubtreeDeleterResult
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4801520019525316763L;



  // Indicates whether the target subtree is inaccessible.
  private final boolean subtreeInaccessible;

  // An error that occurred during an attempt to make the target subtree
  // inaccessible.
  @Nullable private final LDAPResult setSubtreeAccessibilityError;

  // The number of entries that were successfully deleted.
  private final long entriesDeleted;

  // An error that occurred during search processing that prevented identifying
  // all of the entries in the target subtree.
  @Nullable private final SearchResult searchError;

  // A map that contains the DNs of the entries that could not be deleted,
  // associated with a result indicating the reason for the delete failure.
  // It will be sorted in descending order
  @NotNull private final TreeMap<DN,LDAPResult> deleteErrors;



  /**
   * Creates a new subtree deleter result with the provided information.
   *
   * @param  setSubtreeAccessibilityError
   *              An {@code LDAPResult} object with information about an error
   *              that occurred while trying to make the target subtree
   *              inaccessible, or while trying to remove that accessibility
   *              restriction after all other processing completed successfully
   *              (and the two cases can be differentiated using the value of
   *              the {@code subtreeInaccessible} argument).  This may be
   *              {@code null} if no attempt was made to alter the accessibility
   *              of the target subtree, or if its accessibility was
   *              successfully altered.
   * @param  subtreeInaccessible
   *              Indicates whether the target subtree was left inaccessible
   *              after processing completed.  If the subtree was made
   *              inaccessible, it will be left in an inaccessible state if any
   *              error occurs during search or delete processing.  The
   *              accessibility restriction will be removed if all processing
   *              completes successfully.
   * @param  searchError
   *              A search result with information about an error that occurred
   *              during search processing that prevented identifying all of the
   *              entries in the target subtree.  It may be {@code null} if
   *              there was no error during search processing.
   * @param  entriesDeleted
   *              The number of entries that were successfully deleted.
   * @param  deleteErrors
   *              A map that contains the DNs of entries that could not be
   *              deleted, associated with a result indicating the reason for
   *              the delete failure.  It must not be {@code null} but may be
   *              empty.
   */
  SubtreeDeleterResult(@Nullable final LDAPResult setSubtreeAccessibilityError,
                       final boolean subtreeInaccessible,
                       @Nullable final SearchResult searchError,
                       final long entriesDeleted,
                       @NotNull final TreeMap<DN,LDAPResult> deleteErrors)
  {
    this.setSubtreeAccessibilityError = setSubtreeAccessibilityError;
    this.subtreeInaccessible = subtreeInaccessible;
    this.searchError = searchError;
    this.entriesDeleted = entriesDeleted;
    this.deleteErrors = deleteErrors;
  }



  /**
   * Indicates whether the {@link SubtreeDeleter} processing was completely
   * successful.
   *
   * @return  {@code true} if the subtree deleter processing was completely
   *          successful, or {@code false} if not.
   */
  public boolean completelySuccessful()
  {
    return ((setSubtreeAccessibilityError == null) &&
         (! subtreeInaccessible) &&
         (searchError == null) &&
         deleteErrors.isEmpty());
  }



  /**
   * Retrieves an {@code LDAPResult} that provides information about an error
   * that occurred while trying to make the target subtree inaccessible before
   * subtree delete processing, or if an error occurred while trying to remove
   * the subtree accessibility restriction after all other processing had
   * completed successfully.  This may be {@code null} if no attempts was made
   * to alter the subtree accessibility, or if no error occurred during
   * processing.
   * <BR><BR>
   * If the return value is non-{@code null} and {@link #subtreeInaccessible}
   * returns {@code false}, then the error occurred while attempting to make the
   * target subtree inaccessible.  If the return value is non-{@code null} and
   * {@code isSubtreeInaccessible} returns {@code true}, then the error occurred
   * while attempting to remove the subtree accessibility restriction.
   *
   * @return  An {@code LDAPResult} that provides information about an error
   *          that occurred while attempting to alter the accessibility of the
   *          target subtree, or {@code null} if no such error occurred.
   */
  @Nullable()
  public LDAPResult getSetSubtreeAccessibilityError()
  {
    return setSubtreeAccessibilityError;
  }



  /**
   * Indicates whether the target subtree was left in an inaccessible state
   * after some error occurred during subtree delete processing.
   *
   * @return  {@code true} if the subtree was set inaccessible at the start of
   *          subtree delete processing and remains inaccessible after an error
   *          occurred during processing, or {@code false} if the subtree
   *          accessibility was not altered or if the accessibility restriction
   *          was removed after all processing completed successfully.
   */
  public boolean subtreeInaccessible()
  {
    return subtreeInaccessible;
  }



  /**
   * Retrieves a search result with information about an error that occurred
   * during search processing that prevented identifying all of the entries in
   * the target subtree.
   *
   * @return  A search result with information about an error that occurred
   *          during search processing that prevented identifying all of the
   *          entries in the target subtree, or {@code null} if no error
   *          occurred during search processing.
   */
  @Nullable()
  public SearchResult getSearchError()
  {
    return searchError;
  }



  /**
   * Retrieves the number of entries that were successfully deleted.
   *
   * @return  The number of entries that were successfully deleted.
   */
  public long getEntriesDeleted()
  {
    return entriesDeleted;
  }



  /**
   * Retrieves an unmodifiable sorted map of the DNs of entries that could not
   * be successfully deleted, each of which is associated with an
   * {@code LDAPResult} indicating the reason for the delete failure.  The map
   * will be ordered in ascending order using the comparator provided by the
   * {@code DN} class (that is, with ancestor entries before their descendants).
   *
   * @return  An unmodifiable sorted map of the DNs of the entries that could
   *          not be deleted, each of which is associated with an
   *          {@code LDAPResult} indicating the reason for the delete failure.
   */
  @NotNull()
  public SortedMap<DN,LDAPResult> getDeleteErrors()
  {
    return Collections.unmodifiableSortedMap(deleteErrors);
  }



  /**
   * Retrieves an unmodifiable sorted map of the DNs of entries that could not
   * be successfully deleted, each of which is associated with an
   * {@code LDAPResult} indicating the reason for the delete failure.  The map
   * will be ordered in descending order using the comparator provided by the
   * {@code DN} class (that is, with descendant entries before their ancestors).
   *
   * @return  An unmodifiable sorted map of the DNs of the entries that could
   *          not be deleted, each of which is associated with an
   *          {@code LDAPResult} indicating the reason for the delete failure.
   */
  @NotNull()
  public SortedMap<DN,LDAPResult> getDeleteErrorsDescendingMap()
  {
    return Collections.unmodifiableSortedMap(deleteErrors.descendingMap());
  }



  /**
   * Retrieves the delete errors as a {@code TreeMap}.
   *
   * @return  Retrieves the delete errors as a {@code TreeMap}.
   */
  @NotNull()
  TreeMap<DN,LDAPResult> getDeleteErrorsTreeMap()
  {
    return deleteErrors;
  }



  /**
   * Retrieves a string representation of this subtree deleter result.
   *
   * @return  A string representation of this subtree deleter result.
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
   * Appends a string representation of this subtree deleter result to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the string representation should be
   *                 appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SubtreeDeleterResult=(completelySuccessful=");
    buffer.append(completelySuccessful());

    if (setSubtreeAccessibilityError != null)
    {
      buffer.append(", setSubtreeAccessibilityError=");
      setSubtreeAccessibilityError.toString(buffer);
    }

    if (subtreeInaccessible)
    {
      buffer.append(", subtreeInaccessible=true");
    }

    if (searchError != null)
    {
      buffer.append(", searchError=");
      searchError.toString(buffer);
    }

    buffer.append(", entriesDeleted=");
    buffer.append(entriesDeleted);

    if (! deleteErrors.isEmpty())
    {
      buffer.append(", deleteErrors=");
      buffer.append(deleteErrors);
    }
  }
}
