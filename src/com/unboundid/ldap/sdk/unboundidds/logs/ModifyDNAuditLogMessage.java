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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.logs.LogMessages.*;



/**
 * This class provides a data structure that holds information about an audit
 * log message that represents a modify DN operation.
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
public final class ModifyDNAuditLogMessage
       extends AuditLogMessage
{
  /**
   * Retrieves the serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 3954476664207635518L;



  // An LDIF change record that encapsulates the change represented by this
  // modify DN audit log message.
  @NotNull private final LDIFModifyDNChangeRecord modifyDNChangeRecord;

  // The attribute modifications associated with this modify DN operation.
  @Nullable private final List<Modification> attributeModifications;



  /**
   * Creates a new modify DN audit log message from the provided set of lines.
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
  public ModifyDNAuditLogMessage(@NotNull final String... logMessageLines)
         throws AuditLogException
  {
    this(StaticUtils.toList(logMessageLines), logMessageLines);
  }



  /**
   * Creates a new modify DN audit log message from the provided set of lines.
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
   *                             audit provided list of log message lines.
   */
  public ModifyDNAuditLogMessage(@NotNull final List<String> logMessageLines)
         throws AuditLogException
  {
    this(logMessageLines, StaticUtils.toArray(logMessageLines, String.class));
  }



  /**
   * Creates a new modify DN audit log message from the provided information.
   *
   * @param  logMessageLineList   The lines that comprise the log message as a
   *                              list.
   * @param  logMessageLineArray  The lines that comprise the log message as an
   *                              array.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  private ModifyDNAuditLogMessage(
               @NotNull final List<String> logMessageLineList,
               @NotNull final String[] logMessageLineArray)
          throws AuditLogException
  {
    super(logMessageLineList);

    try
    {
      final LDIFChangeRecord changeRecord =
           LDIFReader.decodeChangeRecord(logMessageLineArray);
      if (! (changeRecord instanceof LDIFModifyDNChangeRecord))
      {
        throw new AuditLogException(logMessageLineList,
             ERR_MODIFY_DN_AUDIT_LOG_MESSAGE_CHANGE_TYPE_NOT_MODIFY_DN.get(
                  changeRecord.getChangeType().getName(),
                  ChangeType.MODIFY_DN.getName()));
      }

      modifyDNChangeRecord = (LDIFModifyDNChangeRecord) changeRecord;
    }
    catch (final LDIFException e)
    {
      Debug.debugException(e);
      throw new AuditLogException(logMessageLineList,
           ERR_MODIFY_DN_AUDIT_LOG_MESSAGE_LINES_NOT_CHANGE_RECORD.get(
                StaticUtils.getExceptionMessage(e)),
           e);
    }

    attributeModifications =
         decodeAttributeModifications(logMessageLineList, modifyDNChangeRecord);
  }



  /**
   * Creates a new modify DN audit log message from the provided set of lines.
   *
   * @param  logMessageLines       The lines that comprise the log message.  It
   *                               must not be {@code null} or empty, and it
   *                               must not contain any blank lines, although it
   *                               may contain comments.  In fact, it must
   *                               contain at least one comment line that
   *                               appears before any non-comment lines (but
   *                               possibly after other comment lines) that
   *                               serves as the message header.
   * @param  modifyDNChangeRecord  The LDIF modify DN change record that is
   *                               described by the provided log message lines.
   *
   * @throws  AuditLogException  If a problem is encountered while processing
   *                             the provided list of log message lines.
   */
  ModifyDNAuditLogMessage(@NotNull final List<String> logMessageLines,
       @NotNull final LDIFModifyDNChangeRecord modifyDNChangeRecord)
       throws AuditLogException
  {
    super(logMessageLines);

    this.modifyDNChangeRecord = modifyDNChangeRecord;

    attributeModifications =
         decodeAttributeModifications(logMessageLines, modifyDNChangeRecord);
  }



  /**
   * Decodes the list of attribute modifications from the audit log message, if
   * available.
   *
   * @param  logMessageLines       The lines that comprise the log message.  It
   *                               must not be {@code null} or empty, and it
   *                               must not contain any blank lines, although it
   *                               may contain comments.  In fact, it must
   *                               contain at least one comment line that
   *                               appears before any non-comment lines (but
   *                               possibly after other comment lines) that
   *                               serves as the message header.
   * @param  modifyDNChangeRecord  The LDIF modify DN change record that is
   *                               described by the provided log message lines.
   *
   * @return  The list of attribute modifications from the audit log message, or
   *          {@code null} if there were no modifications.
   */
  @Nullable()
  private static List<Modification> decodeAttributeModifications(
               @NotNull final List<String> logMessageLines,
               @NotNull final LDIFModifyDNChangeRecord modifyDNChangeRecord)
  {
    List<String> ldifLines = null;
    for (final String line : logMessageLines)
    {
      final String uncommentedLine;
      if (line.startsWith("# "))
      {
        uncommentedLine = line.substring(2);
      }
      else
      {
        break;
      }

      if (ldifLines == null)
      {
        final String lowerLine = StaticUtils.toLowerCase(uncommentedLine);
        if (lowerLine.startsWith("modifydn attribute modifications"))
        {
          ldifLines = new ArrayList<>(logMessageLines.size());
        }
      }
      else
      {
        if (ldifLines.isEmpty())
        {
          ldifLines.add("dn: " + modifyDNChangeRecord.getDN());
          ldifLines.add("changetype: modify");
        }

        ldifLines.add(uncommentedLine);
      }
    }

    if (ldifLines == null)
    {
      return null;
    }
    else if (ldifLines.isEmpty())
    {
      return Collections.emptyList();
    }
    else
    {
      try
      {
        final String[] ldifLineArray =
             ldifLines.toArray(StaticUtils.NO_STRINGS);
        final LDIFModifyChangeRecord changeRecord =
             (LDIFModifyChangeRecord)
             LDIFReader.decodeChangeRecord(ldifLineArray);
        return Collections.unmodifiableList(
             Arrays.asList(changeRecord.getModifications()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        return null;
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getDN()
  {
    return modifyDNChangeRecord.getDN();
  }



  /**
   * Retrieves the new RDN for the associated modify DN operation.
   *
   * @return  The new RDN for the associated modify DN operation.
   */
  @NotNull()
  public String getNewRDN()
  {
    return modifyDNChangeRecord.getNewRDN();
  }



  /**
   * Indicates whether the old RDN attribute values were removed from the entry.
   *
   * @return  {@code true} if the old RDN attribute values were removed from the
   *          entry, or {@code false} if not.
   */
  public boolean deleteOldRDN()
  {
    return modifyDNChangeRecord.deleteOldRDN();
  }



  /**
   * Retrieves the new superior DN for the associated modify DN operation, if
   * available.
   *
   * @return  The new superior DN for the associated modify DN operation, or
   *          {@code null} if there was no new superior DN.
   */
  @Nullable()
  public String getNewSuperiorDN()
  {
    return modifyDNChangeRecord.getNewSuperiorDN();
  }



  /**
   * Retrieves the list of attribute modifications for the associated modify DN
   * operation, if available.
   *
   * @return  The list of attribute modifications for the associated modify DN
   *          operation, or {@code null} if it is not available.  If it is
   *          known that there were no attribute modifications, then an empty
   *          list will be returned.
   */
  @Nullable()
  public List<Modification> getAttributeModifications()
  {
    return attributeModifications;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ChangeType getChangeType()
  {
    return ChangeType.MODIFY_DN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LDIFModifyDNChangeRecord getChangeRecord()
  {
    return modifyDNChangeRecord;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean isRevertible()
  {
    // We can't revert a change record if the original DN was that of the root
    // DSE.
    final DN parsedDN;
    final RDN oldRDN;
    try
    {
      parsedDN = modifyDNChangeRecord.getParsedDN();
      oldRDN = parsedDN.getRDN();
      if (oldRDN == null)
      {
        return false;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }


    // We can't create a revert change record if we can't construct the new DN
    // for the entry.
    final DN newDN;
    final RDN newRDN;
    try
    {
      newDN = modifyDNChangeRecord.getNewDN();
      newRDN = modifyDNChangeRecord.getParsedNewRDN();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      return false;
    }


    // Modify DN change records will only be revertible if we have a set of
    // attribute modifications.  If we don't have a set of attribute
    // modifications, we can't know what value to use for the deleteOldRDN flag.
    if (attributeModifications == null)
    {
      return false;
    }


    // If the set of attribute modifications is empty, then deleteOldRDN must
    // be false or the new RDN must equal the old RDN.
    if (attributeModifications.isEmpty())
    {
      if (modifyDNChangeRecord.deleteOldRDN() && (! newRDN.equals(oldRDN)))
      {
        return false;
      }
    }


    // If any of the included modifications has a modification type that is
    // anything other than add, delete, or increment, then it's not revertible.
    // And if any of the delete modifications don't have values, then it's not
    // revertible.
    for (final Modification m : attributeModifications)
    {
      if (!ModifyAuditLogMessage.modificationIsRevertible(m))
      {
        return false;
      }
    }


    // If we've gotten here, then we can change
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public List<LDIFChangeRecord> getRevertChangeRecords()
         throws AuditLogException
  {
    // We can't create a set of revertible changes if we don't have access to
    // attribute modifications.
    if (attributeModifications == null)
    {
      throw new AuditLogException(getLogMessageLines(),
           ERR_MODIFY_DN_NOT_REVERTIBLE.get(modifyDNChangeRecord.getDN()));
    }


    // Get the DN of the entry after the modify DN operation was processed,
    // along with parsed versions of the original DN, new RDN, and new superior
    // DN.
    final DN newDN;
    final DN newSuperiorDN;
    final DN originalDN;
    final RDN newRDN;
    try
    {
      newDN = modifyDNChangeRecord.getNewDN();
      originalDN = modifyDNChangeRecord.getParsedDN();
      newSuperiorDN = modifyDNChangeRecord.getParsedNewSuperiorDN();
      newRDN = modifyDNChangeRecord.getParsedNewRDN();
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      if (modifyDNChangeRecord.getNewSuperiorDN() == null)
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_MODIFY_DN_CANNOT_GET_NEW_DN_WITHOUT_NEW_SUPERIOR.get(
                  modifyDNChangeRecord.getDN(),
                  modifyDNChangeRecord.getNewRDN()),
             e);
      }
      else
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_MODIFY_DN_CANNOT_GET_NEW_DN_WITH_NEW_SUPERIOR.get(
                  modifyDNChangeRecord.getDN(),
                  modifyDNChangeRecord.getNewRDN(),
                  modifyDNChangeRecord.getNewSuperiorDN()),
             e);
      }
    }


    // If the original DN is the null DN, then fail.
    if (originalDN.isNullDN())
    {
      throw new AuditLogException(getLogMessageLines(),
           ERR_MODIFY_DN_CANNOT_REVERT_NULL_DN.get());
    }


    // If the set of attribute modifications is empty, then deleteOldRDN must
    // be false or the new RDN must equal the old RDN.
    if (attributeModifications.isEmpty())
    {
      if (modifyDNChangeRecord.deleteOldRDN() &&
           (! newRDN.equals(originalDN.getRDN())))
      {
        throw new AuditLogException(getLogMessageLines(),
             ERR_MODIFY_DN_CANNOT_REVERT_WITHOUT_NECESSARY_MODS.get(
                  modifyDNChangeRecord.getDN()));
      }
    }


    // Construct the DN, new RDN, and new superior DN values for the change
    // needed to revert the modify DN operation.
    final String revertedDN = newDN.toString();
    final String revertedNewRDN = originalDN.getRDNString();

    final String revertedNewSuperiorDN;
    if (newSuperiorDN == null)
    {
      revertedNewSuperiorDN = null;
    }
    else
    {
      revertedNewSuperiorDN = originalDN.getParentString();
    }


    // If the set of attribute modifications is empty, then deleteOldRDN must
    // have been false and the new RDN attribute value(s) must have already been
    // in the entry.
    if (attributeModifications.isEmpty())
    {
      return Collections.<LDIFChangeRecord>singletonList(
           new LDIFModifyDNChangeRecord(revertedDN, revertedNewRDN, false,
                revertedNewSuperiorDN));
    }


    // Iterate through the modifications to see which new RDN attributes were
    // added to the entry.  If they were all added, then we need to use a
    // deleteOldRDN value of true.  If none of them were added, then we need to
    // use a deleteOldRDN value of false.  If some of them were added but some
    // were not, then we need to use a deleteOldRDN value o false and have a
    // second modification to delete those values that were added.
    //
    // Also, collect any additional modifications that don't involve new RDN
    // attribute values.
    final int numNewRDNs = newRDN.getAttributeNames().length;
    final Set<ObjectPair<String,byte[]>> addedNewRDNValues =
         new HashSet<>(StaticUtils.computeMapCapacity(numNewRDNs));
    final RDN originalRDN = originalDN.getRDN();
    final List<Modification> additionalModifications =
         new ArrayList<>(attributeModifications.size());
    final int numModifications = attributeModifications.size();
    for (int i=numModifications - 1; i >= 0; i--)
    {
      final Modification m = attributeModifications.get(i);
      if (m.getModificationType() == ModificationType.ADD)
      {
        final Attribute a = m.getAttribute();
        final ArrayList<byte[]> retainedValues = new ArrayList<>(a.size());
        for (final ASN1OctetString value : a.getRawValues())
        {
          final byte[] valueBytes = value.getValue();
          if (newRDN.hasAttributeValue(a.getName(), valueBytes))
          {
            addedNewRDNValues.add(new ObjectPair<>(a.getName(), valueBytes));
          }
          else
          {
            retainedValues.add(valueBytes);
          }
        }

        if (retainedValues.size() == a.size())
        {
          additionalModifications.add(new Modification(
               ModificationType.DELETE, a.getName(), a.getRawValues()));
        }
        else if (! retainedValues.isEmpty())
        {
          additionalModifications.add(new Modification(
               ModificationType.DELETE, a.getName(),
               StaticUtils.toArray(retainedValues, byte[].class)));
        }
      }
      else if (m.getModificationType() == ModificationType.DELETE)
      {
        final Attribute a = m.getAttribute();
        final ArrayList<byte[]> retainedValues = new ArrayList<>(a.size());
        for (final ASN1OctetString value : a.getRawValues())
        {
          final byte[] valueBytes = value.getValue();
          if (! originalRDN.hasAttributeValue(a.getName(), valueBytes))
          {
            retainedValues.add(valueBytes);
          }
        }

        if (retainedValues.size() == a.size())
        {
          additionalModifications.add(new Modification(
               ModificationType.ADD, a.getName(), a.getRawValues()));
        }
        else if (! retainedValues.isEmpty())
        {
          additionalModifications.add(new Modification(
               ModificationType.ADD, a.getName(),
               StaticUtils.toArray(retainedValues, byte[].class)));
        }
      }
      else
      {
        final Modification revertModification =
             ModifyAuditLogMessage.getRevertModification(m);
        if (revertModification == null)
        {
          throw new AuditLogException(getLogMessageLines(),
               ERR_MODIFY_DN_MOD_NOT_REVERTIBLE.get(
                    modifyDNChangeRecord.getDN(),
                    m.getModificationType().getName(), m.getAttributeName()));
        }
        else
        {
          additionalModifications.add(revertModification);
        }
      }
    }

    final boolean revertedDeleteOldRDN;
    if (addedNewRDNValues.size() == numNewRDNs)
    {
      revertedDeleteOldRDN = true;
    }
    else
    {
      revertedDeleteOldRDN = false;
      if (! addedNewRDNValues.isEmpty())
      {
        for (final ObjectPair<String,byte[]> p : addedNewRDNValues)
        {
          additionalModifications.add(0,
               new Modification(ModificationType.DELETE, p.getFirst(),
                    p.getSecond()));
        }
      }
    }


    final List<LDIFChangeRecord> changeRecords = new ArrayList<>(2);
    changeRecords.add(new LDIFModifyDNChangeRecord(revertedDN, revertedNewRDN,
         revertedDeleteOldRDN, revertedNewSuperiorDN));
    if (! additionalModifications.isEmpty())
    {
      changeRecords.add(new LDIFModifyChangeRecord(originalDN.toString(),
           additionalModifications));
    }

    return Collections.unmodifiableList(changeRecords);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append(getUncommentedHeaderLine());
    buffer.append("; changeType=modify-dn; dn=\"");
    buffer.append(modifyDNChangeRecord.getDN());
    buffer.append("\", newRDN=\"");
    buffer.append(modifyDNChangeRecord.getNewRDN());
    buffer.append("\", deleteOldRDN=");
    buffer.append(modifyDNChangeRecord.deleteOldRDN());

    final String newSuperiorDN = modifyDNChangeRecord.getNewSuperiorDN();
    if (newSuperiorDN != null)
    {
      buffer.append(", newSuperiorDN=\"");
      buffer.append(newSuperiorDN);
      buffer.append('"');
    }
  }
}
