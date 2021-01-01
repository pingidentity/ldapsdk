/*
 * Copyright 2007-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2007-2021 Ping Identity Corporation
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
 * Copyright (C) 2007-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.ldif.LDIFAddChangeRecord;
import com.unboundid.ldif.LDIFChangeRecord;
import com.unboundid.ldif.LDIFDeleteChangeRecord;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFModifyChangeRecord;
import com.unboundid.ldif.LDIFModifyDNChangeRecord;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.ldif.TrailingSpaceBehavior;
import com.unboundid.ldap.matchingrules.BooleanMatchingRule;
import com.unboundid.ldap.matchingrules.DistinguishedNameMatchingRule;
import com.unboundid.ldap.matchingrules.IntegerMatchingRule;
import com.unboundid.ldap.matchingrules.OctetStringMatchingRule;
import com.unboundid.util.Debug;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for representing a changelog entry as
 * described in draft-good-ldap-changelog.  Changelog entries provide
 * information about a change (add, delete, modify, or modify DN) operation
 * that was processed in the directory server.  Changelog entries may be
 * parsed from entries, and they may be converted to LDIF change records or
 * processed as LDAP operations.
 */
@NotExtensible()
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public class ChangeLogEntry
       extends ReadOnlyEntry
{
  /**
   * The name of the attribute that contains the change number that identifies
   * the change and the order it was processed in the server.
   */
  @NotNull public static final String ATTR_CHANGE_NUMBER = "changeNumber";



  /**
   * The name of the attribute that contains the DN of the entry targeted by
   * the change.
   */
  @NotNull public static final String ATTR_TARGET_DN = "targetDN";



  /**
   * The name of the attribute that contains the type of change made to the
   * target entry.
   */
  @NotNull public static final String ATTR_CHANGE_TYPE = "changeType";



  /**
   * The name of the attribute used to hold a list of changes.  For an add
   * operation, this will be an LDIF representation of the attributes that make
   * up the entry.  For a modify operation, this will be an LDIF representation
   * of the changes to the target entry.
   */
  @NotNull public static final String ATTR_CHANGES = "changes";



  /**
   * The name of the attribute used to hold the new RDN for a modify DN
   * operation.
   */
  @NotNull public static final String ATTR_NEW_RDN = "newRDN";



  /**
   * The name of the attribute used to hold the flag indicating whether the old
   * RDN value(s) should be removed from the target entry for a modify DN
   * operation.
   */
  @NotNull public static final String ATTR_DELETE_OLD_RDN = "deleteOldRDN";



  /**
   * The name of the attribute used to hold the new superior DN for a modify DN
   * operation.
   */
  @NotNull public static final String ATTR_NEW_SUPERIOR = "newSuperior";



  /**
   * The name of the attribute used to hold information about attributes from a
   * deleted entry, if available.
   */
  @NotNull public static final String ATTR_DELETED_ENTRY_ATTRS =
       "deletedEntryAttrs";



  /**
   * The name of an alternative attribute that may be used to obtain information
   * about attributes from a deleted entry if the deletedEntryAttrs attribute
   * is not present.
   */
  @NotNull public static final String
       ATTR_ALTERNATIVE_DELETED_ENTRY_ATTRS_INCLUDED_ATTRIBUTES =
            "includedAttributes";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -4018129098468341663L;



  // Indicates whether to delete the old RDN value(s) in a modify DN operation.
  private final boolean deleteOldRDN;

  // The change type for this changelog entry.
  @NotNull private final ChangeType changeType;

  // A list of the attributes for an add, or the deleted entry attributes for a
  // delete operation.
  @Nullable private final List<Attribute> attributes;

  // A list of the modifications for a modify operation.
  @Nullable private final List<Modification> modifications;

  // The change number for the changelog entry.
  private final long changeNumber;

  // The new RDN for a modify DN operation.
  @Nullable private final String newRDN;

  // The new superior DN for a modify DN operation.
  @Nullable private final String newSuperior;

  // The DN of the target entry.
  @NotNull private final String targetDN;



  /**
   * Creates a new changelog entry from the provided entry.
   *
   * @param  entry  The entry from which to create this changelog entry.
   *
   * @throws  LDAPException  If the provided entry cannot be parsed as a
   *                         changelog entry.
   */
  public ChangeLogEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry);


    final Attribute changeNumberAttr = entry.getAttribute(ATTR_CHANGE_NUMBER);
    if ((changeNumberAttr == null) || (! changeNumberAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_NO_CHANGE_NUMBER.get());
    }

    try
    {
      changeNumber = Long.parseLong(changeNumberAttr.getValue());
    }
    catch (final NumberFormatException nfe)
    {
      Debug.debugException(nfe);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_INVALID_CHANGE_NUMBER.get(changeNumberAttr.getValue()),
           nfe);
    }


    final Attribute targetDNAttr = entry.getAttribute(ATTR_TARGET_DN);
    if ((targetDNAttr == null) || (! targetDNAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_NO_TARGET_DN.get());
    }
    targetDN = targetDNAttr.getValue();


    final Attribute changeTypeAttr = entry.getAttribute(ATTR_CHANGE_TYPE);
    if ((changeTypeAttr == null) || (! changeTypeAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_NO_CHANGE_TYPE.get());
    }
    changeType = ChangeType.forName(changeTypeAttr.getValue());
    if (changeType == null)
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_INVALID_CHANGE_TYPE.get(changeTypeAttr.getValue()));
    }


    switch (changeType)
    {
      case ADD:
        attributes    = parseAddAttributeList(entry, ATTR_CHANGES, targetDN);
        modifications = null;
        newRDN        = null;
        deleteOldRDN  = false;
        newSuperior   = null;
        break;

      case DELETE:
        attributes    = parseDeletedAttributeList(entry, targetDN);
        modifications = null;
        newRDN        = null;
        deleteOldRDN  = false;
        newSuperior   = null;
        break;

      case MODIFY:
        attributes    = null;
        modifications = parseModificationList(entry, targetDN);
        newRDN        = null;
        deleteOldRDN  = false;
        newSuperior   = null;
        break;

      case MODIFY_DN:
        attributes    = null;
        modifications = parseModificationList(entry, targetDN);
        newSuperior   = getAttributeValue(ATTR_NEW_SUPERIOR);

        final Attribute newRDNAttr = getAttribute(ATTR_NEW_RDN);
        if ((newRDNAttr == null) || (! newRDNAttr.hasValue()))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_CHANGELOG_MISSING_NEW_RDN.get());
        }
        newRDN = newRDNAttr.getValue();

        final Attribute deleteOldRDNAttr = getAttribute(ATTR_DELETE_OLD_RDN);
        if ((deleteOldRDNAttr == null) || (! deleteOldRDNAttr.hasValue()))
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
                                  ERR_CHANGELOG_MISSING_DELETE_OLD_RDN.get());
        }
        final String delOldRDNStr =
             StaticUtils.toLowerCase(deleteOldRDNAttr.getValue());
        if (delOldRDNStr.equals("true"))
        {
          deleteOldRDN = true;
        }
        else if (delOldRDNStr.equals("false"))
        {
          deleteOldRDN = false;
        }
        else
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_CHANGELOG_MISSING_DELETE_OLD_RDN.get(delOldRDNStr));
        }
        break;

      default:
        // This should never happen.
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CHANGELOG_INVALID_CHANGE_TYPE.get(changeTypeAttr.getValue()));
    }
  }



  /**
   * Constructs a changelog entry from information contained in the provided
   * LDIF change record.
   *
   * @param  changeNumber  The change number to use for the constructed
   *                       changelog entry.
   * @param  changeRecord  The LDIF change record with the information to
   *                       include in the generated changelog entry.
   *
   * @return  The changelog entry constructed from the provided change record.
   *
   * @throws  LDAPException  If a problem is encountered while constructing the
   *                         changelog entry.
   */
  @NotNull()
  public static ChangeLogEntry constructChangeLogEntry(final long changeNumber,
                     @NotNull final LDIFChangeRecord changeRecord)
         throws LDAPException
  {
    final Entry e =
         new Entry(ATTR_CHANGE_NUMBER + '=' + changeNumber + ",cn=changelog");
    e.addAttribute("objectClass", "top", "changeLogEntry");
    e.addAttribute(new Attribute(ATTR_CHANGE_NUMBER,
         IntegerMatchingRule.getInstance(), String.valueOf(changeNumber)));
    e.addAttribute(new Attribute(ATTR_TARGET_DN,
         DistinguishedNameMatchingRule.getInstance(), changeRecord.getDN()));
    e.addAttribute(ATTR_CHANGE_TYPE, changeRecord.getChangeType().getName());

    switch (changeRecord.getChangeType())
    {
      case ADD:
        // The changes attribute should be an LDIF-encoded representation of the
        // attributes from the entry, which is the LDIF representation of the
        // entry without the first line (which contains the DN).
        final LDIFAddChangeRecord addRecord =
             (LDIFAddChangeRecord) changeRecord;
        final Entry addEntry = new Entry(addRecord.getDN(),
             addRecord.getAttributes());
        final String[] entryLdifLines = addEntry.toLDIF(0);
        final StringBuilder entryLDIFBuffer = new StringBuilder();
        for (int i=1; i < entryLdifLines.length; i++)
        {
          entryLDIFBuffer.append(entryLdifLines[i]);
          entryLDIFBuffer.append(StaticUtils.EOL);
        }
        e.addAttribute(new Attribute(ATTR_CHANGES,
             OctetStringMatchingRule.getInstance(),
             entryLDIFBuffer.toString()));
        break;

      case DELETE:
        // No additional information is needed.
        break;

      case MODIFY:
        // The changes attribute should be an LDIF-encoded representation of the
        // modification, with the first two lines (the DN and changetype)
        // removed.
        final String[] modLdifLines = changeRecord.toLDIF(0);
        final StringBuilder modLDIFBuffer = new StringBuilder();
        for (int i=2; i < modLdifLines.length; i++)
        {
          modLDIFBuffer.append(modLdifLines[i]);
          modLDIFBuffer.append(StaticUtils.EOL);
        }
        e.addAttribute(new Attribute(ATTR_CHANGES,
             OctetStringMatchingRule.getInstance(), modLDIFBuffer.toString()));
        break;

      case MODIFY_DN:
        final LDIFModifyDNChangeRecord modDNRecord =
             (LDIFModifyDNChangeRecord) changeRecord;
        e.addAttribute(new Attribute(ATTR_NEW_RDN,
             DistinguishedNameMatchingRule.getInstance(),
             modDNRecord.getNewRDN()));
        e.addAttribute(new Attribute(ATTR_DELETE_OLD_RDN,
             BooleanMatchingRule.getInstance(),
             (modDNRecord.deleteOldRDN() ? "TRUE" : "FALSE")));
        if (modDNRecord.getNewSuperiorDN() != null)
        {
          e.addAttribute(new Attribute(ATTR_NEW_SUPERIOR,
               DistinguishedNameMatchingRule.getInstance(),
               modDNRecord.getNewSuperiorDN()));
        }
        break;
    }

    return new ChangeLogEntry(e);
  }



  /**
   * Parses the attribute list from the specified attribute in a changelog
   * entry.
   *
   * @param  entry     The entry containing the data to parse.
   * @param  attrName  The name of the attribute from which to parse the
   *                   attribute list.
   * @param  targetDN  The DN of the target entry.
   *
   * @return  The parsed attribute list.
   *
   * @throws  LDAPException  If an error occurs while parsing the attribute
   *                         list.
   */
  @NotNull()
  protected static List<Attribute> parseAddAttributeList(
                                        @NotNull final Entry entry,
                                        @NotNull final String attrName,
                                        @NotNull final String targetDN)
            throws LDAPException
  {
    final Attribute changesAttr = entry.getAttribute(attrName);
    if ((changesAttr == null) || (! changesAttr.hasValue()))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
                              ERR_CHANGELOG_MISSING_CHANGES.get());
    }

    final ArrayList<String> ldifLines = new ArrayList<>(20);
    ldifLines.add("dn: " + targetDN);

    final StringTokenizer tokenizer =
         new StringTokenizer(changesAttr.getValue(), "\r\n");
    while (tokenizer.hasMoreTokens())
    {
      ldifLines.add(tokenizer.nextToken());
    }

    final String[] lineArray = new String[ldifLines.size()];
    ldifLines.toArray(lineArray);

    try
    {
      final Entry e = LDIFReader.decodeEntry(true, TrailingSpaceBehavior.RETAIN,
           null, lineArray);
      return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
    }
    catch (final LDIFException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_CANNOT_PARSE_ATTR_LIST.get(attrName,
                StaticUtils.getExceptionMessage(le)),
           le);
    }
  }



  /**
   * Parses the list of deleted attributes from a changelog entry representing a
   * delete operation.  The attribute is optional, so it may not be present at
   * all, and there are two different encodings that we need to handle.  One
   * encoding is the same as is used for the add attribute list, and the second
   * is similar to the encoding used for the list of changes, except that it
   * ends with a NULL byte (0x00).
   *
   * @param  entry     The entry containing the data to parse.
   * @param  targetDN  The DN of the target entry.
   *
   * @return  The parsed deleted attribute list, or {@code null} if the
   *          changelog entry does not include a deleted attribute list.
   *
   * @throws  LDAPException  If an error occurs while parsing the deleted
   *                         attribute list.
   */
  @Nullable()
  private static List<Attribute> parseDeletedAttributeList(
                                      @NotNull final Entry entry,
                                      @NotNull final String targetDN)
          throws LDAPException
  {
    Attribute deletedEntryAttrs =
         entry.getAttribute(ATTR_DELETED_ENTRY_ATTRS);
    if ((deletedEntryAttrs == null) || (! deletedEntryAttrs.hasValue()))
    {
      deletedEntryAttrs = entry.getAttribute(
           ATTR_ALTERNATIVE_DELETED_ENTRY_ATTRS_INCLUDED_ATTRIBUTES);
      if ((deletedEntryAttrs == null) || (! deletedEntryAttrs.hasValue()))
      {
        return null;
      }
    }

    final byte[] valueBytes = deletedEntryAttrs.getValueByteArray();
    if ((valueBytes.length > 0) && (valueBytes[valueBytes.length-1] == 0x00))
    {
      final String valueStr = new String(valueBytes, 0, valueBytes.length-2,
           StandardCharsets.UTF_8);

      final ArrayList<String> ldifLines = new ArrayList<>(20);
      ldifLines.add("dn: " + targetDN);
      ldifLines.add("changetype: modify");

      final StringTokenizer tokenizer = new StringTokenizer(valueStr, "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        ldifLines.add(tokenizer.nextToken());
      }

      final String[] lineArray = new String[ldifLines.size()];
      ldifLines.toArray(lineArray);

      try
      {

        final LDIFModifyChangeRecord changeRecord =
             (LDIFModifyChangeRecord) LDIFReader.decodeChangeRecord(lineArray);
        final Modification[] mods = changeRecord.getModifications();
        final ArrayList<Attribute> attrs = new ArrayList<>(mods.length);
        for (final Modification m : mods)
        {
          if (! m.getModificationType().equals(ModificationType.DELETE))
          {
            throw new LDAPException(ResultCode.DECODING_ERROR,
                 ERR_CHANGELOG_INVALID_DELENTRYATTRS_MOD_TYPE.get(
                      ATTR_DELETED_ENTRY_ATTRS));
          }

          attrs.add(m.getAttribute());
        }

        return Collections.unmodifiableList(attrs);
      }
      catch (final LDIFException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CHANGELOG_INVALID_DELENTRYATTRS_MODS.get(
                  ATTR_DELETED_ENTRY_ATTRS,
                  StaticUtils.getExceptionMessage(le)),
             le);
      }
    }
    else
    {
      final ArrayList<String> ldifLines = new ArrayList<>(20);
      ldifLines.add("dn: " + targetDN);

      final StringTokenizer tokenizer =
           new StringTokenizer(deletedEntryAttrs.getValue(), "\r\n");
      while (tokenizer.hasMoreTokens())
      {
        ldifLines.add(tokenizer.nextToken());
      }

      final String[] lineArray = new String[ldifLines.size()];
      ldifLines.toArray(lineArray);

      try
      {
        final Entry e = LDIFReader.decodeEntry(true,
             TrailingSpaceBehavior.RETAIN, null, lineArray);
        return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
      }
      catch (final LDIFException le)
      {
        Debug.debugException(le);
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_CHANGELOG_CANNOT_PARSE_DELENTRYATTRS.get(
                  ATTR_DELETED_ENTRY_ATTRS,
                  StaticUtils.getExceptionMessage(le)),
             le);
      }
    }
  }



  /**
   * Parses the modification list from a changelog entry representing a modify
   * operation.
   *
   * @param  entry     The entry containing the data to parse.
   * @param  targetDN  The DN of the target entry.
   *
   * @return  The parsed modification list, or {@code null} if the changelog
   *          entry does not include any modifications.
   *
   * @throws  LDAPException  If an error occurs while parsing the modification
   *                         list.
   */
  @Nullable()
  private static List<Modification> parseModificationList(
                                         @NotNull final Entry entry,
                                         @NotNull final String targetDN)
          throws LDAPException
  {
    final Attribute changesAttr = entry.getAttribute(ATTR_CHANGES);
    if ((changesAttr == null) || (! changesAttr.hasValue()))
    {
      return null;
    }

    final byte[] valueBytes = changesAttr.getValueByteArray();
    if (valueBytes.length == 0)
    {
      return null;
    }


    final ArrayList<String> ldifLines = new ArrayList<>(20);
    ldifLines.add("dn: " + targetDN);
    ldifLines.add("changetype: modify");

    // Even though it's a violation of the specification in
    // draft-good-ldap-changelog, it appears that some servers (e.g., Sun DSEE)
    // may terminate the changes value with a null character (\u0000).  If that
    // is the case, then we'll need to strip it off before trying to parse it.
    final StringTokenizer tokenizer;
    if ((valueBytes.length > 0) && (valueBytes[valueBytes.length-1] == 0x00))
    {
      final String fullValue = changesAttr.getValue();
      final String realValue = fullValue.substring(0, fullValue.length()-2);
      tokenizer = new StringTokenizer(realValue, "\r\n");
    }
    else
    {
      tokenizer = new StringTokenizer(changesAttr.getValue(), "\r\n");
    }

    while (tokenizer.hasMoreTokens())
    {
      ldifLines.add(tokenizer.nextToken());
    }

    final String[] lineArray = new String[ldifLines.size()];
    ldifLines.toArray(lineArray);

    try
    {
      final LDIFModifyChangeRecord changeRecord =
           (LDIFModifyChangeRecord) LDIFReader.decodeChangeRecord(lineArray);
      return Collections.unmodifiableList(
                  Arrays.asList(changeRecord.getModifications()));
    }
    catch (final LDIFException le)
    {
      Debug.debugException(le);
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_CHANGELOG_CANNOT_PARSE_MOD_LIST.get(ATTR_CHANGES,
                StaticUtils.getExceptionMessage(le)),
           le);
    }
  }



  /**
   * Retrieves the change number for this changelog entry.
   *
   * @return  The change number for this changelog entry.
   */
  public final long getChangeNumber()
  {
    return changeNumber;
  }



  /**
   * Retrieves the target DN for this changelog entry.
   *
   * @return  The target DN for this changelog entry.
   */
  @NotNull()
  public final String getTargetDN()
  {
    return targetDN;
  }



  /**
   * Retrieves the change type for this changelog entry.
   *
   * @return  The change type for this changelog entry.
   */
  @NotNull()
  public final ChangeType getChangeType()
  {
    return changeType;
  }



  /**
   * Retrieves the attribute list for an add changelog entry.
   *
   * @return  The attribute list for an add changelog entry, or {@code null} if
   *          this changelog entry does not represent an add operation.
   */
  @Nullable()
  public final List<Attribute> getAddAttributes()
  {
    if (changeType == ChangeType.ADD)
    {
      return attributes;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the list of deleted entry attributes for a delete changelog
   * entry.  Note that this is a non-standard extension implemented by some
   * types of servers and is not defined in draft-good-ldap-changelog and may
   * not be provided by some servers.
   *
   * @return  The delete entry attribute list for a delete changelog entry, or
   *          {@code null} if this changelog entry does not represent a delete
   *          operation or no deleted entry attributes were included in the
   *          changelog entry.
   */
  @Nullable()
  public final List<Attribute> getDeletedEntryAttributes()
  {
    if (changeType == ChangeType.DELETE)
    {
      return attributes;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the list of modifications for a modify changelog entry.  Note
   * some directory servers may also include changes for modify DN change
   * records if there were updates to operational attributes (e.g.,
   * modifiersName and modifyTimestamp).
   *
   * @return  The list of modifications for a modify (or possibly modify DN)
   *          changelog entry, or {@code null} if this changelog entry does
   *          not represent a modify operation or a modify DN operation with
   *          additional changes.
   */
  @Nullable
  public final List<Modification> getModifications()
  {
    return modifications;
  }



  /**
   * Retrieves the new RDN for a modify DN changelog entry.
   *
   * @return  The new RDN for a modify DN changelog entry, or {@code null} if
   *          this changelog entry does not represent a modify DN operation.
   */
  @Nullable()
  public final String getNewRDN()
  {
    return newRDN;
  }



  /**
   * Indicates whether the old RDN value(s) should be removed from the entry
   * targeted by this modify DN changelog entry.
   *
   * @return  {@code true} if the old RDN value(s) should be removed from the
   *          entry, or {@code false} if not or if this changelog entry does not
   *          represent a modify DN operation.
   */
  public final boolean deleteOldRDN()
  {
    return deleteOldRDN;
  }



  /**
   * Retrieves the new superior DN for a modify DN changelog entry.
   *
   * @return  The new superior DN for a modify DN changelog entry, or
   *          {@code null} if there is no new superior DN, or if this changelog
   *          entry does not represent a modify DN operation.
   */
  @Nullable()
  public final String getNewSuperior()
  {
    return newSuperior;
  }



  /**
   * Retrieves the DN of the entry after the change has been processed.  For an
   * add or modify operation, the new DN will be the same as the target DN.  For
   * a modify DN operation, the new DN will be constructed from the original DN,
   * the new RDN, and the new superior DN.  For a delete operation, it will be
   * {@code null} because the entry will no longer exist.
   *
   * @return  The DN of the entry after the change has been processed, or
   *          {@code null} if the entry no longer exists.
   */
  @Nullable()
  public final String getNewDN()
  {
    switch (changeType)
    {
      case ADD:
      case MODIFY:
        return targetDN;

      case MODIFY_DN:
        // This will be handled below.
        break;

      case DELETE:
      default:
        return null;
    }

    try
    {
      final RDN parsedNewRDN = new RDN(newRDN);

      if (newSuperior == null)
      {
        final DN parsedTargetDN = new DN(targetDN);
        final DN parentDN = parsedTargetDN.getParent();
        if (parentDN == null)
        {
          return new DN(parsedNewRDN).toString();
        }
        else
        {
          return new DN(parsedNewRDN, parentDN).toString();
        }
      }
      else
      {
        final DN parsedNewSuperior = new DN(newSuperior);
        return new DN(parsedNewRDN, parsedNewSuperior).toString();
      }
    }
    catch (final Exception e)
    {
      // This should never happen.
      Debug.debugException(e);
      return null;
    }
  }



  /**
   * Retrieves an LDIF change record that is analogous to the operation
   * represented by this changelog entry.
   *
   * @return  An LDIF change record that is analogous to the operation
   *          represented by this changelog entry.
   */
  @NotNull()
  public final LDIFChangeRecord toLDIFChangeRecord()
  {
    switch (changeType)
    {
      case ADD:
        return new LDIFAddChangeRecord(targetDN, attributes);

      case DELETE:
        return new LDIFDeleteChangeRecord(targetDN);

      case MODIFY:
        return new LDIFModifyChangeRecord(targetDN, modifications);

      case MODIFY_DN:
        return new LDIFModifyDNChangeRecord(targetDN, newRDN, deleteOldRDN,
                                            newSuperior);

      default:
        // This should never happen.
        return null;
    }
  }



  /**
   * Processes the operation represented by this changelog entry using the
   * provided LDAP connection.
   *
   * @param  connection  The connection (or connection pool) to use to process
   *                     the operation.
   *
   * @return  The result of processing the operation.
   *
   * @throws  LDAPException  If the operation could not be processed
   *                         successfully.
   */
  @NotNull()
  public final LDAPResult processChange(@NotNull final LDAPInterface connection)
         throws LDAPException
  {
    switch (changeType)
    {
      case ADD:
        return connection.add(targetDN, attributes);

      case DELETE:
        return connection.delete(targetDN);

      case MODIFY:
        return connection.modify(targetDN, modifications);

      case MODIFY_DN:
        return connection.modifyDN(targetDN, newRDN, deleteOldRDN, newSuperior);

      default:
        // This should never happen.
        return null;
    }
  }
}
