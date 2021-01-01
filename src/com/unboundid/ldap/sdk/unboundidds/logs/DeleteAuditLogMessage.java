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



import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.UndeleteRequestControl;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
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
 * log message that represents a delete operation.
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
public final class DeleteAuditLogMessage
       extends AuditLogMessage
{
  /**
   * Retrieves the serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 2082830761413726711L;



  // Indicates whether the entry was deleted as part of a subtree delete.
  @Nullable private final Boolean deletedAsPartOfSubtreeDelete;

  // Indicates whether the delete operation represents a subtree delete.
  @Nullable private final Boolean isSubtreeDelete;

  // Indicates whether the delete operation represents a soft delete.
  @Nullable private final Boolean isSoftDelete;

  // Indicates whether the delete operation targets a soft-deleted entry.
  @Nullable private final Boolean isSoftDeletedEntry;

  // An LDIF change record that encapsulates the change represented by this
  // delete audit log message.
  @NotNull private final LDIFDeleteChangeRecord deleteChangeRecord;

  // A list of the virtual attributes from the entry that was deleted.
  @Nullable private final List<Attribute> deletedEntryVirtualAttributes;

  // A read-only copy of the entry that was deleted.
  @Nullable private final ReadOnlyEntry deletedEntry;

  // The resulting DN of the soft-deleted entry.
  @Nullable private final String softDeletedEntryDN;



  /**
   * Creates a new delete audit log message from the provided set of lines.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty, and it must not
   *                          contain any blank lines, although it may contain
   *                          comments.  In fact, it must contain at least one
   *                          comment line that appears before any non-comment
   *                          lines (but possibly after other comment lines)
   *                          that serves as the message header.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  public DeleteAuditLogMessage(@NotNull final String... logMessageLines)
         throws AuditLogException
  {
    this(StaticUtils.toList(logMessageLines), logMessageLines);
  }



  /**
   * Creates a new delete audit log message from the provided set of lines.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty, and it must not
   *                          contain any blank lines, although it may contain
   *                          comments.  In fact, it must contain at least one
   *                          comment line that appears before any non-comment
   *                          lines (but possibly after other comment lines)
   *                          that serves as the message header.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  public DeleteAuditLogMessage(@NotNull final List<String> logMessageLines)
         throws AuditLogException
  {
    this(logMessageLines, StaticUtils.toArray(logMessageLines, String.class));
  }



  /**
   * Creates a new delete audit log message from the provided information.
   *
   * @param  logMessageLineList   The lines that comprise the log message as a
   *                              list.
   * @param  logMessageLineArray  The lines that comprise the log message as an
   *                              array.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  private DeleteAuditLogMessage(@NotNull final List<String> logMessageLineList,
                                @NotNull final String[] logMessageLineArray)
          throws AuditLogException
  {
    super(logMessageLineList);

    try
    {
      final LDIFChangeRecord changeRecord =
           LDIFReader.decodeChangeRecord(logMessageLineArray);
      if (! (changeRecord instanceof LDIFDeleteChangeRecord))
      {
        throw new AuditLogException(logMessageLineList,
             ERR_DELETE_AUDIT_LOG_MESSAGE_CHANGE_TYPE_NOT_DELETE.get(
                  changeRecord.getChangeType().getName(),
                  ChangeType.DELETE.getName()));
      }

      deleteChangeRecord = (LDIFDeleteChangeRecord) changeRecord;
    }
    catch (final LDIFException e)
    {
      Debug.debugException(e);
      throw new AuditLogException(logMessageLineList,
           ERR_DELETE_AUDIT_LOG_MESSAGE_LINES_NOT_CHANGE_RECORD.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    deletedAsPartOfSubtreeDelete = getNamedValueAsBoolean(
         "deletedAsPartOfSubtreeDelete", getHeaderNamedValues());
    isSubtreeDelete =
         getNamedValueAsBoolean("isSubtreeDelete", getHeaderNamedValues());
    isSoftDelete =
         getNamedValueAsBoolean("isSoftDelete", getHeaderNamedValues());
    isSoftDeletedEntry =
         getNamedValueAsBoolean("isSoftDeletedEntry", getHeaderNamedValues());
    softDeletedEntryDN = getHeaderNamedValues().get("softDeletedEntryDN");
    deletedEntry = decodeCommentedEntry("Deleted entry real attributes",
         logMessageLineList, deleteChangeRecord.getDN());

    final ReadOnlyEntry virtualAttributeEntry = decodeCommentedEntry(
         "Deleted entry virtual attributes", logMessageLineList,
         deleteChangeRecord.getDN());
    if (virtualAttributeEntry == null)
    {
      deletedEntryVirtualAttributes = null;
    }
    else
    {
      deletedEntryVirtualAttributes = Collections.unmodifiableList(
           new ArrayList<>(virtualAttributeEntry.getAttributes()));
    }
  }



  /**
   * Creates a new delete audit log message from the provided set of lines.
   *
   * @param  logMessageLines     The lines that comprise the log message.  It
   *                             must not be {@code null} or empty, and it must
   *                             not contain any blank lines, although it may
   *                             contain comments.  In fact, it must contain at
   *                             least one comment line that appears before any
   *                             non-comment lines (but possibly after other
   *                             comment lines) that serves as the message
   *                             header.
   * @param  deleteChangeRecord  The LDIF delete change record that is described
   *                             by the provided log message lines.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  DeleteAuditLogMessage(@NotNull final List<String> logMessageLines,
       @NotNull final LDIFDeleteChangeRecord deleteChangeRecord)
       throws AuditLogException
  {
    super(logMessageLines);

    this.deleteChangeRecord = deleteChangeRecord;

    deletedAsPartOfSubtreeDelete = getNamedValueAsBoolean(
         "deletedAsPartOfSubtreeDelete", getHeaderNamedValues());
    isSubtreeDelete =
         getNamedValueAsBoolean("isSubtreeDelete", getHeaderNamedValues());
    isSoftDelete =
         getNamedValueAsBoolean("isSoftDelete", getHeaderNamedValues());
    isSoftDeletedEntry =
         getNamedValueAsBoolean("isSoftDeletedEntry", getHeaderNamedValues());
    softDeletedEntryDN = getHeaderNamedValues().get("softDeletedEntryDN");
    deletedEntry = decodeCommentedEntry("Deleted entry real attributes",
         logMessageLines, deleteChangeRecord.getDN());

    final ReadOnlyEntry virtualAttributeEntry = decodeCommentedEntry(
         "Deleted entry virtual attributes", logMessageLines,
         deleteChangeRecord.getDN());
    if (virtualAttributeEntry == null)
    {
      deletedEntryVirtualAttributes = null;
    }
    else
    {
      deletedEntryVirtualAttributes = Collections.unmodifiableList(
           new ArrayList<>(virtualAttributeEntry.getAttributes()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDN()
  {
    return deleteChangeRecord.getDN();
  }



  /**
   * Retrieves the value of the flag that indicates whether this delete audit
   * log message represents the delete of the base entry of a subtree delete
   * operation, if available.
   *
   * @return  {@code Boolean.TRUE} if it is known that the operation was a
   *          subtree delete, {@code Boolean.FALSE} if it is known that the
   *          operation was not a subtree delete, or {@code null} if this is not
   *          available.
   */
  @Nullable()
  public Boolean getIsSubtreeDelete()
  {
    return isSubtreeDelete;
  }



  /**
   * Retrieves the value of the flag that indicates whether this delete audit
   * log record represents an entry that was deleted as part of a subtree
   * delete (and is not the base entry for that subtree delete), if available.
   *
   * @return  {@code Boolean.TRUE} if it is known that the entry was deleted as
   *          part of a subtree delete, {@code Boolean.FALSE} if it is known
   *          that the entry was not deleted as part of a subtree delete, or
   *          {@code null} if this is not available.
   */
  @Nullable()
  public Boolean getDeletedAsPartOfSubtreeDelete()
  {
    return deletedAsPartOfSubtreeDelete;
  }



  /**
   * Retrieves the value of the flag that indicates whether this delete
   * operation was a soft delete, if available.
   *
   * @return  {@code Boolean.TRUE} if it is known that the operation was a soft
   *          delete, {@code Boolean.FALSE} if it is known that the operation
   *          was not a soft delete, or {@code null} if this is not available.
   */
  @Nullable()
  public Boolean getIsSoftDelete()
  {
    return isSoftDelete;
  }



  /**
   * Retrieves the DN of the entry after it was been soft deleted, if available.
   *
   * @return  The DN of the entry after it was soft deleted, or {@code null} if
   *          this is not available.
   */
  @Nullable()
  public String getSoftDeletedEntryDN()
  {
    return softDeletedEntryDN;
  }



  /**
   * Retrieves the value of the flag that indicates whether this delete
   * operation targeted an entry that had previously been soft deleted, if
   * available.
   *
   * @return  {@code Boolean.TRUE} if it is known that the operation targeted a
   *          soft-deleted entry, {@code Boolean.FALSE} if it is known that the
   *          operation did not target a soft-deleted entry, or {@code null} if
   *          this is not available.
   */
  @Nullable()
  public Boolean getIsSoftDeletedEntry()
  {
    return isSoftDeletedEntry;
  }



  /**
   * Retrieves a read-only copy of the entry that was deleted, if available.
   *
   * @return  A read-only copy of the entry that was deleted, or {@code null} if
   *          it is not available.
   */
  @Nullable()
  public ReadOnlyEntry getDeletedEntry()
  {
    return deletedEntry;
  }



  /**
   * Retrieves a list of the virtual attributes from the entry that was deleted,
   * if available.
   *
   * @return  A list of the virtual attributes from the entry that was deleted,
   *          or {@code null} if it is not available.
   */
  @Nullable()
  public List<Attribute> getDeletedEntryVirtualAttributes()
  {
    return deletedEntryVirtualAttributes;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ChangeType getChangeType()
  {
    return ChangeType.DELETE;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFDeleteChangeRecord getChangeRecord()
  {
    return deleteChangeRecord;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean isRevertible()
  {
    // Subtree delete operations are not inherently revertible.  The audit log
    // should actually record a separate delete log message for each entry that
    // was deleted as part of the subtree delete, and therefore it is possible
    // to reverse an audit log that includes those additional delete records,
    // but it is not possible to revert a subtree delete from a single delete
    // audit log message.
    //
    // However, if this audit log message is for the base entry of a subtree
    // delete, and if getDeletedEntry returns a non-null value, then the add
    // change record needed to revert the delete of just that base entry can be
    // obtained by simply creating an add change record using the entry returned
    // by getDeletedEntry.
    if ((isSubtreeDelete != null) && isSubtreeDelete)
    {
      return false;
    }

    // Non-subtree delete audit log messages are revertible under conditions:
    // - It was a soft delete and we have the soft-deleted entry DN.
    // - It was a hard delete and we have a copy of the entry that was deleted.
    if ((isSoftDelete != null) && isSoftDelete)
    {
      return (softDeletedEntryDN != null);
    }
    else
    {
      return (deletedEntry != null);
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
    if ((isSubtreeDelete != null) && isSubtreeDelete)
    {
      if (deletedEntry == null)
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_DELETE_AUDIT_LOG_MESSAGE_SUBTREE_DELETE_WITHOUT_ENTRY.get(
                  deleteChangeRecord.getDN()));
      }
      else
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_DELETE_AUDIT_LOG_MESSAGE_SUBTREE_DELETE_WITH_ENTRY.get(
                  deleteChangeRecord.getDN()));
      }
    }

    if ((isSoftDelete != null) && isSoftDelete)
    {
      if (softDeletedEntryDN != null)
      {
        return Collections.<LDIFChangeRecord>singletonList(
             new LDIFAddChangeRecord(
                  UndeleteRequestControl.createUndeleteRequest(
                       deleteChangeRecord.getDN(), softDeletedEntryDN)));
      }
      else
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_DELETE_AUDIT_LOG_MESSAGE_NO_SOFT_DELETED_ENTRY_DN.get(
                  deleteChangeRecord.getDN()));
      }
    }
    else
    {
      if (deletedEntry != null)
      {
        return Collections.<LDIFChangeRecord>singletonList(
             new LDIFAddChangeRecord(deletedEntry));
      }
      else
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_DELETE_AUDIT_LOG_MESSAGE_DELETED_ENTRY.get(
                  deleteChangeRecord.getDN()));
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(getUncommentedHeaderLine());
    buffer.append("; changeType=delete; dn=\"");
    buffer.append(deleteChangeRecord.getDN());
    buffer.append('\"');
  }
}
