/*
 * Copyright 2019-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2019-2020 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.transformations;



import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.util.NotMutable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides an LDIF change record transformation that can exclude
 * change records that can exclude LDIF change records that match any of a
 * provided set of change types.  It will not have any effect on LDIF records
 * that do not contain a change type (which must be entries).
 */
@NotMutable()
@ThreadSafety(level = ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ExcludeChangeTypeTransformation
       implements LDIFChangeRecordTransformation, Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6927917616913251572L;



  // The set of change types for records to be excluded.
  private final Set<ChangeType> excludedChangeTypes;



  /**
   * Creates a new exclude change type transformation that will exclude change
   * records with any of the provided change types.
   *
   * @param  changeTypes  The set of change types to exclude.
   */
  public ExcludeChangeTypeTransformation(final ChangeType... changeTypes)
  {
    this(StaticUtils.toList(changeTypes));
  }



  /**
   * Creates a new exclude change type transformation that will exclude change
   * records with any of the provided change types.
   *
   * @param  changeTypes  The set of change types to exclude.
   */
  public ExcludeChangeTypeTransformation(
              final Collection<ChangeType> changeTypes)
  {
    if (changeTypes == null)
    {
      excludedChangeTypes = Collections.emptySet();
    }
    else
    {
      final EnumSet<ChangeType> ctSet = EnumSet.noneOf(ChangeType.class);
      ctSet.addAll(changeTypes);
      excludedChangeTypes = Collections.unmodifiableSet(ctSet);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFChangeRecord transformChangeRecord(
                               final LDIFChangeRecord changeRecord)
  {
    if (excludedChangeTypes.contains(changeRecord.getChangeType()))
    {
      return null;
    }
    else
    {
      return changeRecord;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFChangeRecord translate(final LDIFChangeRecord original,
                                    final long firstLineNumber)
  {
    if (excludedChangeTypes.contains(original.getChangeType()))
    {
      return null;
    }
    else
    {
      return original;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFChangeRecord translateChangeRecordToWrite(
                               final LDIFChangeRecord original)
  {
    if (excludedChangeTypes.contains(original.getChangeType()))
    {
      return null;
    }
    else
    {
      return original;
    }
  }
}
