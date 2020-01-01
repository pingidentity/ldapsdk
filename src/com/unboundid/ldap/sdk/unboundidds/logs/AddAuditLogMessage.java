/*
 * Copyright 2018-2020 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2018-2020 Ping Identity Corporation
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



import java.util.Collections;
import java.util.List;

import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.ldap.sdk.unboundidds.controls.SoftDeleteRequestControl;
import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.LogMessages.*;



/**
 * This class provides a data structure that holds information about an audit
 * log message that represents an add operation.
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
public final class AddAuditLogMessage
       extends AuditLogMessage
{
  /**
   * Retrieves the serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4103749134439291911L;



  // Indicates whether the add operation represents an undelete of a
  // soft-deleted entry.
  private final Boolean isUndelete;

  // An LDIF change record that encapsulates the change represented by this add
  // audit log message.
  private final LDIFAddChangeRecord addChangeRecord;

  // The entry included in the undelete request.
  private final ReadOnlyEntry undeleteRequestEntry;



  /**
   * Creates a new add audit log message from the provided set of lines.
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
  public AddAuditLogMessage(final String... logMessageLines)
         throws AuditLogException
  {
    this(StaticUtils.toList(logMessageLines), logMessageLines);
  }



  /**
   * Creates a new add audit log message from the provided set of lines.
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
  public AddAuditLogMessage(final List<String> logMessageLines)
         throws AuditLogException
  {
    this(logMessageLines, StaticUtils.toArray(logMessageLines, String.class));
  }



  /**
   * Creates a new add audit log message from the provided information.
   *
   * @param  logMessageLineList   The lines that comprise the log message as a
   *                              list.
   * @param  logMessageLineArray  The lines that comprise the log message as an
   *                              array.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  private AddAuditLogMessage(final List<String> logMessageLineList,
                             final String[] logMessageLineArray)
          throws AuditLogException
  {
    super(logMessageLineList);

    try
    {
      final LDIFChangeRecord changeRecord =
           LDIFReader.decodeChangeRecord(logMessageLineArray);
      if (!(changeRecord instanceof LDIFAddChangeRecord))
      {
        throw new AuditLogException(logMessageLineList,
             ERR_ADD_AUDIT_LOG_MESSAGE_CHANGE_TYPE_NOT_ADD.get(
                  changeRecord.getChangeType().getName(),
                  ChangeType.ADD.getName()));
      }

      addChangeRecord = (LDIFAddChangeRecord) changeRecord;
    }
    catch (final LDIFException e)
    {
      Debug.debugException(e);
      throw new AuditLogException(logMessageLineList,
           ERR_ADD_AUDIT_LOG_MESSAGE_LINES_NOT_CHANGE_RECORD.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    isUndelete = getNamedValueAsBoolean("isUndelete", getHeaderNamedValues());
    undeleteRequestEntry = decodeCommentedEntry("Undelete request entry",
         logMessageLineList, null);
  }



  /**
   * Creates a new add audit log message from the provided set of lines.
   *
   * @param  logMessageLines  The lines that comprise the log message.  It must
   *                          not be {@code null} or empty, and it must not
   *                          contain any blank lines, although it may contain
   *                          comments.  In fact, it must contain at least one
   *                          comment line that appears before any non-comment
   *                          lines (but possibly after other comment lines)
   *                          that serves as the message header.
   * @param  addChangeRecord  The LDIF add change record that is described by
   *                          the provided log message lines.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  AddAuditLogMessage(final List<String> logMessageLines,
                     final LDIFAddChangeRecord addChangeRecord)
       throws AuditLogException
  {
    super(logMessageLines);

    this.addChangeRecord = addChangeRecord;

    isUndelete = getNamedValueAsBoolean("isUndelete", getHeaderNamedValues());
    undeleteRequestEntry = decodeCommentedEntry("Undelete request entry",
         logMessageLines, null);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getDN()
  {
    return addChangeRecord.getDN();
  }



  /**
   * Retrieves a read-only representation of the entry that was added.
   *
   * @return  A read-only representation of the entry that was added.
   */
  public ReadOnlyEntry getEntry()
  {
    return new ReadOnlyEntry(addChangeRecord.getEntryToAdd());
  }



  /**
   * Retrieves the value of the "isUndelete" flag from this log message, which
   * indicates whether the add operation attempted to undelete a previously
   * soft-deleted entry, if available.
   *
   * @return  The value of the "isUndelete" flag from this log message, or
   *          {@code null} if it is not available.
   */
  public Boolean getIsUndelete()
  {
    return isUndelete;
  }



  /**
   * Retrieves the entry that comprised the undelete request, available.
   *
   * @return  The entry that comprised the undelete request, or {@code null} if
   *          it is not available.
   */
  public ReadOnlyEntry getUndeleteRequestEntry()
  {
    return undeleteRequestEntry;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public ChangeType getChangeType()
  {
    return ChangeType.ADD;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public LDIFAddChangeRecord getChangeRecord()
  {
    return addChangeRecord;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean isRevertible()
  {
    // Add audit log messages are always reversible.
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<LDIFChangeRecord> getRevertChangeRecords()
  {
    if ((isUndelete != null) && isUndelete)
    {
      return Collections.<LDIFChangeRecord>singletonList(
           new LDIFDeleteChangeRecord(
                SoftDeleteRequestControl.createSoftDeleteRequest(
                     addChangeRecord.getDN(), false, true)));
    }
    else
    {
      return Collections.<LDIFChangeRecord>singletonList(
           new LDIFDeleteChangeRecord(addChangeRecord.getDN()));
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(final StringBuilder buffer)
  {
    buffer.append(getUncommentedHeaderLine());
    buffer.append("; changeType=add; dn=\"");
    buffer.append(addChangeRecord.getDN());
    buffer.append('\"');
  }
}
