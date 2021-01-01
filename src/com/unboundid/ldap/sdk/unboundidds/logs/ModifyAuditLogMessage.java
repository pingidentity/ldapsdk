/*
 * Copyright 2018-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2018-2021 Ping Identity Corporation
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
 * Copyright (C) 2018-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.LogMessages.*;



/**
 * This class provides a data structure that holds information about an audit
 * log message that represents a modify operation.
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
 */
@ThreadSafety(level= ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class ModifyAuditLogMessage
       extends AuditLogMessage
{
  /**
   * Retrieves the serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5262466264778465574L;



  // Indicates whether the modify operation targets a soft-deleted entry.
  @Nullable private final Boolean isSoftDeletedEntry;

  // An LDIF change record that encapsulates the change represented by this
  // modify audit log message.
  @NotNull private final LDIFModifyChangeRecord modifyChangeRecord;



  /**
   * Creates a new modify audit log message from the provided set of lines.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty, and it must not
   *                          contain any blank lines, although it may contain
   *                          comments.  In fact, it must contain at least one
   *                          comment line that appears before any non-comment
   *                          lines (but possibly after other comment line) that
   *                          serves as the message header.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  public ModifyAuditLogMessage(@NotNull final String... logMessageLines)
         throws AuditLogException
  {
    this(StaticUtils.toList(logMessageLines), logMessageLines);
  }



  /**
   * Creates a new modify audit log message from the provided set of lines.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty, and it must not
   *                          contain any blank lines, although it may contain
   *                          comments.  In fact, it must contain at least one
   *                          comment line that appears before any non-comment
   *                          lines (but possibly after other comment line) that
   *                          serves as the message header.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  public ModifyAuditLogMessage(@NotNull final List<String> logMessageLines)
         throws AuditLogException
  {
    this(logMessageLines, StaticUtils.toArray(logMessageLines, String.class));
  }



  /**
   * Creates a new modify audit log message from the provided information.
   *
   * @param  logMessageLineList   The lines that comprise the log message as a
   *                              list.
   * @param  logMessageLineArray  The lines that comprise the log message as an
   *                              array.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  private ModifyAuditLogMessage(@NotNull final List<String> logMessageLineList,
                                @NotNull final String[] logMessageLineArray)
          throws AuditLogException
  {
    super(logMessageLineList);

    try
    {
      final LDIFChangeRecord changeRecord =
           LDIFReader.decodeChangeRecord(logMessageLineArray);
      if (! (changeRecord instanceof LDIFModifyChangeRecord))
      {
        throw new AuditLogException(logMessageLineList,
             ERR_MODIFY_AUDIT_LOG_MESSAGE_CHANGE_TYPE_NOT_MODIFY.get(
                  changeRecord.getChangeType().getName(),
                  ChangeType.MODIFY.getName()));
      }

      modifyChangeRecord = (LDIFModifyChangeRecord) changeRecord;
    }
    catch (final LDIFException e)
    {
      Debug.debugException(e);
      throw new AuditLogException(logMessageLineList,
           ERR_MODIFY_AUDIT_LOG_MESSAGE_LINES_NOT_CHANGE_RECORD.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    isSoftDeletedEntry =
         getNamedValueAsBoolean("isSoftDeletedEntry", getHeaderNamedValues());
  }



  /**
   * Creates a new modify audit log message from the provided set of lines.
   *
   * @param  logMessageLines     The lines that comprise the log message.  It
   *                             must not be {@code null} or empty, and it must
   *                             not contain any blank lines, although it may
   *                             contain comments.  In fact, it must contain at
   *                             least one comment line that appears before any
   *                             non-comment lines (but possibly after other
   *                             comment line) that serves as the message
   *                             header.
   * @param  modifyChangeRecord  The LDIF modify change record that is described
   *                             by the provided log message lines.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  ModifyAuditLogMessage(@NotNull final List<String> logMessageLines,
       @NotNull final LDIFModifyChangeRecord modifyChangeRecord)
       throws AuditLogException
  {
    super(logMessageLines);

    this.modifyChangeRecord = modifyChangeRecord;

    isSoftDeletedEntry =
         getNamedValueAsBoolean("isSoftDeletedEntry", getHeaderNamedValues());
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDN()
  {
    return modifyChangeRecord.getDN();
  }



  /**
   * Retrieves a list of the modifications included in the associated modify
   * operation.
   *
   * @return  A list of the modifications included in the associated modify
   *          operation.
   */
  @NotNull()
  public List<Modification> getModifications()
  {
    return Collections.unmodifiableList(
         Arrays.asList(modifyChangeRecord.getModifications()));
  }



  /**
   * Retrieves the value of the flag that indicates whether this modify
   * operation targeted an entry that had previously been soft deleted, if
   * available.
   *
   * @return  {@code Boolean.TRUE} if it is known that the operation targeted a
   *          soft-deleted entry, {@code Boolean.FALSE} if it is known that the
   *          operation did not target a soft-deleted entry, or {@code null} if
   *          this is not available.
   */
@Nullable   public Boolean getIsSoftDeletedEntry()
  {
    return isSoftDeletedEntry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFModifyChangeRecord getChangeRecord()
  {
    return modifyChangeRecord;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean isRevertible()
  {
    // Modify audit log messages are revertible as long as both of the following
    // are true:
    // - It must not contain any REPLACE modifications, with or without values.
    // - It must not contain any DELETE modifications without values.  DELETE
    //   modifications with values are fine.
    for (final Modification m : modifyChangeRecord.getModifications())
    {
      if (! modificationIsRevertible(m))
      {
        return false;
      }
    }

    // If we've gotten here, then it must be acceptable.
    return true;
  }



  /**
   * Indicates whether the provided modification is revertible.
   *
   * @param  m  The modification for which to make the determination.  It must
   *            not be {@code null}.
   *
   * @return  {@code true} if the modification is revertible, or {@code false}
   *          if not.
   */
  static boolean modificationIsRevertible(@NotNull final Modification m)
  {
    switch (m.getModificationType().intValue())
    {
      case ModificationType.ADD_INT_VALUE:
      case ModificationType.INCREMENT_INT_VALUE:
        // This is always revertible.
        return true;

      case ModificationType.DELETE_INT_VALUE:
        // This is revertible as long as it has one or more values.
        return m.hasValue();

      case ModificationType.REPLACE_INT_VALUE:
      default:
        // This is never revertible.
        return false;
    }
  }



  /**
   * Retrieves a modification that can be used to revert the provided
   * modification.
   *
   * @param  m  The modification for which to retrieve the revert modification.
   *            It must not be {@code null}.
   *
   * @return  A modification that can be used to revert the provided
   *          modification, or {@code null} if the provided modification cannot
   *          be reverted.
   */
  @Nullable()
  static Modification getRevertModification(@NotNull final Modification m)
  {
    switch (m.getModificationType().intValue())
    {
      case ModificationType.ADD_INT_VALUE:
        return new Modification(ModificationType.DELETE, m.getAttributeName(),
             m.getRawValues());

      case ModificationType.INCREMENT_INT_VALUE:
        final String firstValue = m.getValues()[0];
        if (firstValue.startsWith("-"))
        {
          return new Modification(ModificationType.INCREMENT,
               m.getAttributeName(), firstValue.substring(1));
        }
        else
        {
          return new Modification(ModificationType.INCREMENT,
               m.getAttributeName(), '-' + firstValue);
        }

      case ModificationType.DELETE_INT_VALUE:
        if (m.hasValue())
        {
          return new Modification(ModificationType.ADD, m.getAttributeName(),
               m.getRawValues());
        }
        else
        {
          return null;
        }

      case ModificationType.REPLACE_INT_VALUE:
      default:
        return null;
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<LDIFChangeRecord> getRevertChangeRecords()
         throws AuditLogException
  {
    // Iterate through the modifications backwards and construct the
    // appropriate set of modifications to revert each of them.
    final Modification[] mods = modifyChangeRecord.getModifications();
    final Modification[] revertMods = new Modification[mods.length];
    for (int i=mods.length - 1, j = 0; i >= 0; i--, j++)
    {
      revertMods[j] = getRevertModification(mods[i]);
      if (revertMods[j] == null)
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_MODIFY_AUDIT_LOG_MESSAGE_MOD_NOT_REVERTIBLE.get(
                  modifyChangeRecord.getDN(), String.valueOf(mods[i])));
      }
    }

    return Collections.<LDIFChangeRecord>singletonList(
         new LDIFModifyChangeRecord(modifyChangeRecord.getDN(), revertMods));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(getUncommentedHeaderLine());
    buffer.append("; changeType=modify; dn=\"");
    buffer.append(modifyChangeRecord.getDN());
    buffer.append('\"');
  }
}
