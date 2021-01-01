/*
 * Copyright 2011-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2011-2021 Ping Identity Corporation
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
 * Copyright (C) 2011-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ChangeLogEntry;
import com.unboundid.ldap.sdk.ChangeType;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.UnboundIDDSMessages.*;



/**
 * This class provides an implementation of a changelog entry which provides
 * support for all standard changelog entry attributes as well as those unique
 * to the Ping Identity, UnboundID, and Nokia/Alcatel-Lucent 8661 Directory
 * Server.
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
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class UnboundIDChangeLogEntry
       extends ChangeLogEntry
{
  /**
   * The name of the attribute used to hold the previous values for all
   * attributes affected by the change.
   */
  @NotNull public static final String ATTR_BEFORE_VALUES =
       "ds-changelog-before-values";



  /**
   * The name of the attribute used to hold the resulting values for all
   * attributes affected by the change.
   */
  @NotNull public static final String ATTR_AFTER_VALUES =
       "ds-changelog-after-values";



  /**
   * The name of the attribute used to indicate whether the operation represents
   * a change to a soft-deleted entry.
   */
  @NotNull public static final String ATTR_CHANGE_TO_SOFT_DELETED_ENTRY =
       "ds-change-to-soft-deleted-entry";



  /**
   * The name of the attribute used to hold the values of key attributes from
   * the entry after the change was applied.
   */
  @NotNull public static final String ATTR_KEY_VALUES =
       "ds-changelog-entry-key-attr-values";



  /**
   * The name of the attribute used to hold information about updated attributes
   * which had more values (whether before the change, after the change, or
   * both) than allowed to be shown in the before/after values attributes.
   */
  @NotNull public static final String ATTR_EXCEEDED_MAX_VALUES =
       "ds-changelog-attr-exceeded-max-values-count";



  /**
   * The name of the attribute used to hold information about the number of
   * user attributes that may have been excluded by access control and/or
   * sensitive attribute processing.
   */
  @NotNull public static final String ATTR_EXCLUDED_USER_ATTR_COUNT =
       "ds-changelog-num-excluded-user-attributes";



  /**
   * The name of the attribute used to hold information about the number of
   * operational attributes that may have been excluded by access control and/or
   * sensitive attribute processing.
   */
  @NotNull public static final String ATTR_EXCLUDED_OPERATIONAL_ATTR_COUNT =
       "ds-changelog-num-excluded-operational-attributes";



  /**
   * The name of the attribute used to hold information about the names of the
   * user attributes that may have been excluded by access control and/or
   * sensitive attribute processing.
   */
  @NotNull public static final String ATTR_EXCLUDED_USER_ATTR_NAME =
       "ds-changelog-excluded-user-attribute";



  /**
   * The name of the attribute used to hold information about the names of the
   * operational attributes that may have been excluded by access control and/or
   * sensitive attribute processing.
   */
  @NotNull public static final String ATTR_EXCLUDED_OPERATIONAL_ATTR_NAME =
       "ds-changelog-excluded-operational-attribute";



  /**
   * The name of the attribute used to hold the entryUUID value for the entry
   * that was targeted by the change.
   */
  @NotNull public static final String ATTR_TARGET_UNIQUE_ID = "targetUniqueID";



  /**
   * The name of the attribute used to hold a timestamp of the time the change
   * was processed.
   */
  @NotNull public static final String ATTR_CHANGE_TIME = "changeTime";



  /**
   * The name of the attribute used to hold the local change sequence number
   * assigned to the change.
   */
  @NotNull public static final String ATTR_LOCAL_CSN = "localCSN";



  /**
   * The name of the attribute used to hold the DN of the soft-deleted entry
   * resulting from a soft delete operation.
   */
  @NotNull public static final String ATTR_SOFT_DELETE_TO_DN =
       "ds-soft-delete-entry-dn";



  /**
   * The name of the attribute used to hold the names of the attributes targeted
   * by the change.
   */
  @NotNull public static final String ATTR_TARGET_ATTRIBUTE =
       "ds-changelog-target-attribute";



  /**
   * The name of the attribute used to hold the DN of the soft-deleted entry
   * from which the content of an undelete was obtained.
   */
  @NotNull public static final String ATTR_UNDELETE_FROM_DN =
       "ds-undelete-from-dn";



  /**
   * The name of the attribute used to hold information about virtual values
   * for an add or delete operation.
   */
  @NotNull public static final String ATTR_VIRTUAL_ATTRS =
       "ds-changelog-virtual-attributes";



  /**
   * The name of the attribute used to hold information about virtual values
   * for modified attributes before the change.
   */
  @NotNull public static final String ATTR_BEFORE_VIRTUAL_VALUES =
       "ds-changelog-before-virtual-values";



  /**
   * The name of the attribute used to hold information about virtual values
   * for modified attributes after the change.
   */
  @NotNull public static final String ATTR_AFTER_VIRTUAL_VALUES =
       "ds-changelog-after-virtual-values";



  /**
   * The name of the attribute used to hold information about virtual values
   * for key attributes after the change.
   */
  @NotNull public static final String ATTR_KEY_VIRTUAL_VALUES =
       "ds-changelog-entry-key-virtual-values";



  /**
   * The name of the attribute used to hold information about updated attributes
   * which had more virtual values (whether before the change, after the change,
   * or both) than allowed to be shown in the before/after values attributes.
   */
  @NotNull public static final String ATTR_VIRTUAL_EXCEEDED_MAX_VALUES =
       "ds-changelog-virtual-attr-exceeded-max-values-count";



  /**
   * The name of the attribute used to hold the entryUUID values for the
   * notification destinations matched by the change.
   */
  @NotNull public static final String ATTR_NOTIFICATION_DESTINATION_ENTRY_UUID =
       "ds-notification-destination-entry-uuid";



  /**
   * The name of the attribute used to hold a number of properties related to
   * the notification matched by the change.
   */
  @NotNull public static final String ATTR_NOTIFICATION_PROPERTIES =
       "ds-changelog-notification-properties";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -6127912254495185946L;



  // Indicates whether the changelog record represents a change to a
  // soft-deleted entry.
  @Nullable private final Boolean changeToSoftDeletedEntry;

  // The time that the change was processed.
  @Nullable private final Date changeTime;

  // The number of user attributes excluded by access control and/or sensitive
  // attribute processing.
  @Nullable private final Integer numExcludedUserAttributes;

  // The number of operational attributes excluded by access control and/or
  // sensitive attribute processing.
  @Nullable private final Integer numExcludedOperationalAttributes;

  // The names of virtual attributes as they appeared in the entry after an add
  // or before a delete operation.
  @NotNull private final List<Attribute> entryVirtualAttributes;

  // The values of key attributes as they appeared in the entry after the change
  // was applied (or before the delete if the entry was removed).
  @NotNull private final List<Attribute> keyEntryAttributes;

  // The virtual values of key attributes as they appeared in the entry after
  // the change was applied (or before the delete if the entry was removed).
  @NotNull private final List<Attribute> keyEntryVirtualAttributes;

  // The updated attributes as they appeared in the entry after the change was
  // applied.
  @NotNull private final List<Attribute> updatedAttributesAfterChange;

  // The updated attributes as they appeared in the entry before the change was
  // applied.
  @NotNull private final List<Attribute> updatedAttributesBeforeChange;

  // The virtual values of updated attributes as they appeared in the entry
  // after the change was applied.
  @NotNull private final List<Attribute> updatedVirtualAttributesAfterChange;

  // The virtual values of updated attributes as they appeared in the entry
  // before the change was applied.
  @NotNull private final List<Attribute> updatedVirtualAttributesBeforeChange;

  // Information about updated attributes that had more values than are allowed
  // to be included in the ds-changelog-before-values or
  // ds-changelog-after-values attributes.
  @NotNull private final List<ChangeLogEntryAttributeExceededMaxValuesCount>
       attributesThatExceededMaxValuesCount;

  // Information about updated attributes that had more virtual values than are
  // allowed to be included in the ds-changelog-before-virtual-values or
  // ds-changelog-after-virtual-values attributes.
  @NotNull private final List<ChangeLogEntryAttributeExceededMaxValuesCount>
       virtualAttributesThatExceededMaxValuesCount;

  // The names of user attributes excluded by access control and/or sensitive
  // attribute processing.
  @NotNull private final List<String> excludedUserAttributeNames;

  // The names of operational attributes excluded by access control and/or
  // sensitive attribute processing.
  @NotNull private final List<String> excludedOperationalAttributeNames;

  // The entryUUID values for the notification destinations matched by the
  // change.
  @NotNull private final List<String> notificationDestinationEntryUUIDs;

  // The values of any notification properties for the change.
  @NotNull private final List<String> notificationProperties;

  // The names of the attributes targeted by the change.
  @NotNull private final List<String> targetAttributeNames;

  // The local change sequence number for the change.
  @Nullable private final String localCSN;

  // The DN of the soft-deleted entry resulting from a soft delete operation.
  @Nullable private final String softDeleteToDN;

  // The entryUUID value for the target entry.
  @Nullable private final String targetUniqueID;

  // The DN of the soft-deleted entry from which the content of an undelete
  // operation was created.
  @Nullable private final String undeleteFromDN;



  /**
   * Creates a new UnboundID changelog entry object from the provided entry.
   *
   * @param  entry  The entry from which to create this changelog entry.
   *
   * @throws  LDAPException  If the provided entry cannot be parsed as a
   *                         changelog entry.
   */
  public UnboundIDChangeLogEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry);

    final String targetDN = entry.getAttributeValue(ATTR_TARGET_DN);

    targetUniqueID = entry.getAttributeValue(ATTR_TARGET_UNIQUE_ID);
    localCSN       = entry.getAttributeValue(ATTR_LOCAL_CSN);
    changeTime     = entry.getAttributeValueAsDate(ATTR_CHANGE_TIME);
    softDeleteToDN = entry.getAttributeValue(ATTR_SOFT_DELETE_TO_DN);
    undeleteFromDN = entry.getAttributeValue(ATTR_UNDELETE_FROM_DN);

    changeToSoftDeletedEntry =
         entry.getAttributeValueAsBoolean(ATTR_CHANGE_TO_SOFT_DELETED_ENTRY);

    if (entry.hasAttribute(ATTR_VIRTUAL_ATTRS))
    {
      entryVirtualAttributes = parseAddAttributeList(entry, ATTR_VIRTUAL_ATTRS,
           targetDN);
    }
    else
    {
      entryVirtualAttributes = Collections.emptyList();
    }

    if (entry.hasAttribute(ATTR_BEFORE_VALUES))
    {
      updatedAttributesBeforeChange = parseAddAttributeList(entry,
           ATTR_BEFORE_VALUES, targetDN);
    }
    else
    {
      updatedAttributesBeforeChange = Collections.emptyList();
    }

    if (entry.hasAttribute(ATTR_BEFORE_VIRTUAL_VALUES))
    {
      updatedVirtualAttributesBeforeChange = parseAddAttributeList(entry,
           ATTR_BEFORE_VIRTUAL_VALUES, targetDN);
    }
    else
    {
      updatedVirtualAttributesBeforeChange = Collections.emptyList();
    }

    if (entry.hasAttribute(ATTR_AFTER_VALUES))
    {
      updatedAttributesAfterChange = parseAddAttributeList(entry,
           ATTR_AFTER_VALUES, targetDN);
    }
    else
    {
      updatedAttributesAfterChange = Collections.emptyList();
    }

    if (entry.hasAttribute(ATTR_AFTER_VIRTUAL_VALUES))
    {
      updatedVirtualAttributesAfterChange = parseAddAttributeList(entry,
           ATTR_AFTER_VIRTUAL_VALUES, targetDN);
    }
    else
    {
      updatedVirtualAttributesAfterChange = Collections.emptyList();
    }

    if (entry.hasAttribute(ATTR_KEY_VALUES))
    {
      keyEntryAttributes =
           parseAddAttributeList(entry, ATTR_KEY_VALUES, targetDN);
    }
    else
    {
      keyEntryAttributes = Collections.emptyList();
    }

    if (entry.hasAttribute(ATTR_KEY_VIRTUAL_VALUES))
    {
      keyEntryVirtualAttributes =
           parseAddAttributeList(entry, ATTR_KEY_VIRTUAL_VALUES, targetDN);
    }
    else
    {
      keyEntryVirtualAttributes = Collections.emptyList();
    }

    final Attribute exceededMaxValues =
         entry.getAttribute(ATTR_EXCEEDED_MAX_VALUES);
    if (exceededMaxValues == null)
    {
      attributesThatExceededMaxValuesCount = Collections.emptyList();
    }
    else
    {
      final String[] values = exceededMaxValues.getValues();
      final ArrayList<ChangeLogEntryAttributeExceededMaxValuesCount> l =
           new ArrayList<>(values.length);
      for (final String value : values)
      {
        l.add(new ChangeLogEntryAttributeExceededMaxValuesCount(value));
      }
      attributesThatExceededMaxValuesCount = Collections.unmodifiableList(l);
    }

    final Attribute virtualExceededMaxValues =
         entry.getAttribute(ATTR_VIRTUAL_EXCEEDED_MAX_VALUES);
    if (virtualExceededMaxValues == null)
    {
      virtualAttributesThatExceededMaxValuesCount = Collections.emptyList();
    }
    else
    {
      final String[] values = virtualExceededMaxValues.getValues();
      final ArrayList<ChangeLogEntryAttributeExceededMaxValuesCount> l =
           new ArrayList<>(values.length);
      for (final String value : values)
      {
        l.add(new ChangeLogEntryAttributeExceededMaxValuesCount(value));
      }
      virtualAttributesThatExceededMaxValuesCount =
           Collections.unmodifiableList(l);
    }

    numExcludedUserAttributes =
         entry.getAttributeValueAsInteger(ATTR_EXCLUDED_USER_ATTR_COUNT);
    numExcludedOperationalAttributes =
         entry.getAttributeValueAsInteger(ATTR_EXCLUDED_OPERATIONAL_ATTR_COUNT);

    final String[] excludedUserAttrNames =
         entry.getAttributeValues(ATTR_EXCLUDED_USER_ATTR_NAME);
    if (excludedUserAttrNames == null)
    {
      excludedUserAttributeNames = Collections.emptyList();
    }
    else
    {
      excludedUserAttributeNames = Collections.unmodifiableList(
           new ArrayList<>(Arrays.asList(excludedUserAttrNames)));
    }

    final String[] excludedOpAttrNames =
         entry.getAttributeValues(ATTR_EXCLUDED_OPERATIONAL_ATTR_NAME);
    if (excludedOpAttrNames == null)
    {
      excludedOperationalAttributeNames = Collections.emptyList();
    }
    else
    {
      excludedOperationalAttributeNames = Collections.unmodifiableList(
           new ArrayList<>(Arrays.asList(excludedOpAttrNames)));
    }

    final String[] targetAttrNames =
         entry.getAttributeValues(ATTR_TARGET_ATTRIBUTE);
    if (targetAttrNames == null)
    {
      targetAttributeNames = Collections.emptyList();
    }
    else
    {
      targetAttributeNames = Collections.unmodifiableList(
           new ArrayList<>(Arrays.asList(targetAttrNames)));
    }

    final String[] notificationUUIDValues =
         entry.getAttributeValues(ATTR_NOTIFICATION_DESTINATION_ENTRY_UUID);
    if (notificationUUIDValues == null)
    {
      notificationDestinationEntryUUIDs = Collections.emptyList();
    }
    else
    {
      notificationDestinationEntryUUIDs = Collections.unmodifiableList(
           new ArrayList<>(Arrays.asList(notificationUUIDValues)));
    }

    final String[] notificationPropertyValues =
         entry.getAttributeValues(ATTR_NOTIFICATION_PROPERTIES);
    if (notificationPropertyValues == null)
    {
      notificationProperties = Collections.emptyList();
    }
    else
    {
      notificationProperties = Collections.unmodifiableList(
           new ArrayList<>(Arrays.asList(notificationPropertyValues)));
    }
  }



  /**
   * Retrieves the entryUUID value of the entry targeted by the change, if
   * available.
   *
   * @return  The entryUUID value of the entry targeted by the change, or
   *          {@code null} if it was not included in the changelog entry.
   */
  @Nullable()
  public String getTargetUniqueID()
  {
    return targetUniqueID;
  }



  /**
   * Retrieves the local change sequence number (CSN) for the change, if
   * available.
   *
   * @return  The local CSN for the change, or {@code null} if it was not
   *          included in the changelog entry.
   */
  @Nullable()
  public String getLocalCSN()
  {
    return localCSN;
  }



  /**
   * Retrieves the time that the change was processed, if available.
   *
   * @return  The time that the change was processed, or {@code null} if it was
   *           not included in the changelog entry.
   */
  @Nullable()
  public Date getChangeTime()
  {
    return changeTime;
  }



  /**
   * Retrieves the attribute list for an add changelog entry, optionally
   * including information about virtual attributes.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  The attribute list for an add changelog entry, optionally
   *          including virtual attributes, or {@code null} if this changelog
   *          entry does not represent an add operation.
   */
  @Nullable()
  public List<Attribute> getAddAttributes(final boolean includeVirtual)
  {
    if (includeVirtual && (getChangeType() == ChangeType.ADD) &&
         (! entryVirtualAttributes.isEmpty()))
    {
      final Entry e = new Entry(getTargetDN(), getAddAttributes());
      for (final Attribute a : entryVirtualAttributes)
      {
        e.addAttribute(a);
      }

      return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
    }
    else
    {
      return getAddAttributes();
    }
  }



  /**
   * Retrieves the virtual attribute list for an add changelog entry, if
   * available.
   *
   * @return  The virtual attribute list for an add changelog entry, or
   *           {@code null} if the changelog entry does not represent an add
   *           operation, or an empty list if it does represent an add operation
   *           but no virtual attribute information is available in the
   *           changelog entry.
   */
  @Nullable()
  public List<Attribute> getAddVirtualAttributes()
  {
    if (getChangeType() == ChangeType.ADD)
    {
      return entryVirtualAttributes;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves the list of attributes contained in the target entry at the time
   * that it was deleted, optionally including information about virtual
   * attributes.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  The list of attributes contained in the target entry at the time
   *           that it was deleted, optionally including virtual attributes, or
   *           {@code null} if this changelog entry does not represent a delete
   *           operation or no deleted attribute information is available.
   */
  @Nullable()
  public List<Attribute> getDeletedEntryAttributes(
       final boolean includeVirtual)
  {
    if (includeVirtual && (getChangeType() == ChangeType.DELETE) &&
         (! entryVirtualAttributes.isEmpty()))
    {
      final Entry e;
      final List<Attribute> realAttrs = getDeletedEntryAttributes();
      if (realAttrs != null)
      {
        e = new Entry(getTargetDN(), realAttrs);
        for (final Attribute a : entryVirtualAttributes)
        {
          e.addAttribute(a);
        }
      }
      else
      {
        e = new Entry(getTargetDN(), entryVirtualAttributes);
      }

      return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
    }
    else
    {
      return getDeletedEntryAttributes();
    }
  }



  /**
   * Retrieves the virtual attribute list for a delete changelog entry, if
   * available.
   *
   * @return  The virtual attribute list for a delete changelog entry, or
   *          {@code null} if the changelog entry does not represent a delete
   *          operation, or an empty list if it does represent a delete
   *          operation but no virtual attribute information is available in the
   *          changelog entry.
   */
  @Nullable()
  public List<Attribute> getDeletedEntryVirtualAttributes()
  {
    if (getChangeType() == ChangeType.DELETE)
    {
      return entryVirtualAttributes;
    }
    else
    {
      return null;
    }
  }



  /**
   * Retrieves a list containing the set of attributes that were updated in the
   * associated modify or modify DN operation as they appeared before the change
   * was processed.  Virtual attribute information will not be included.
   *
   * @return  A list containing the set of updated attributes as they appeared
   *          in the entry before the associated modify or modify DN was
   *          processed, or an empty list if the change was not a modify or
   *          modify DN operation, none of the updated attributes previously
   *          existed in the target entry, the previous versions of the updated
   *          attributes had too many values to include, or the server is not
   *          configured to provide (or does not support providing) previous
   *          versions of updated attributes.
   */
  @NotNull()
  public List<Attribute> getUpdatedAttributesBeforeChange()
  {
    return updatedAttributesBeforeChange;
  }



  /**
   * Retrieves a list containing the set of attributes (optionally including
   * both real and virtual values) that were updated in the associated modify or
   * modify DN operation as they appeared before the change was processed.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  A list containing the set of updated attributes as they appeared
   *          in the entry before the associated modify or modify DN was
   *          processed, or an empty list if the change was not a modify or
   *          modify DN operation, none of the updated attributes previously
   *          existed in the target entry, the previous versions of the updated
   *          attributes had too many values to include, or the server is not
   *          configured to provide (or does not support providing) previous
   *          versions of updated attributes.
   */
  @NotNull()
  public List<Attribute> getUpdatedAttributesBeforeChange(
                              final boolean includeVirtual)
  {
    if (includeVirtual && (! updatedVirtualAttributesBeforeChange.isEmpty()))
    {
      final Entry e = new Entry(getTargetDN(), updatedAttributesBeforeChange);
      for (final Attribute a : updatedVirtualAttributesBeforeChange)
      {
        e.addAttribute(a);
      }

      return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
    }
    else
    {
      return updatedAttributesBeforeChange;
    }
  }



  /**
   * Retrieves a list containing information about virtual values for attributes
   * that were updated in the associated modify or modify DN operation, as they
   * appeared in the entry before the change was processed.
   *
   * @return  A list containing information about virtual values for attributes
   *          that were updated in the associated modify or modify DN operation,
   *          as they appeared in the entry before the change was processed.  It
   *          may be empty if the change was not a modify or modify DN
   *          operation, or if the changelog entry did not include any
   *          information about virtual attributes as they appeared before the
   *          change.
   */
  @NotNull()
  public List<Attribute> getUpdatedVirtualAttributesBeforeChange()
  {
    return updatedVirtualAttributesBeforeChange;
  }



  /**
   * Retrieves a list containing the set of attributes that were updated in the
   * associated modify or modify DN operation as they appeared after the change
   * was processed.  Virtual attribute information will not be included.
   *
   * @return  A list containing the set of updated attributes as they appeared
   *          in the entry after the associated modify or modify DN was
   *          processed, or an empty list if the change was not a modify or
   *          modify DN operation, none of the updated attributes existed in the
   *          entry after the change was processed, the resulting versions of
   *          the updated attributes had too many values to include, or the
   *          server is not configured to provide (or does not support
   *          providing) resulting versions of updated attributes.
   */
  @NotNull()
  public List<Attribute> getUpdatedAttributesAfterChange()
  {
    return updatedAttributesAfterChange;
  }



  /**
   * Retrieves a list containing the set of attributes (optionally including
   * both real and virtual values) that were updated in the associated modify or
   * modify DN operation as they appeared after the change was processed.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  A list containing the set of updated attributes as they appeared
   *          in the entry after the associated modify or modify DN was
   *          processed, or an empty list if the change was not a modify or
   *          modify DN operation, none of the updated attributes previously
   *          existed in the target entry, the previous versions of the updated
   *          attributes had too many values to include, or the server is not
   *          configured to provide (or does not support providing) previous
   *          versions of updated attributes.
   */
  @NotNull()
  public List<Attribute> getUpdatedAttributesAfterChange(
                              final boolean includeVirtual)
  {
    if (includeVirtual && (! updatedVirtualAttributesAfterChange.isEmpty()))
    {
      final Entry e = new Entry(getTargetDN(), updatedAttributesAfterChange);
      for (final Attribute a : updatedVirtualAttributesAfterChange)
      {
        e.addAttribute(a);
      }

      return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
    }
    else
    {
      return updatedAttributesAfterChange;
    }
  }



  /**
   * Retrieves a list containing information about virtual values for attributes
   * that were updated in the associated modify or modify DN operation, as they
   * appeared in the entry after the change was processed.
   *
   * @return  A list containing information about virtual values for attributes
   *          that were updated in the associated modify or modify DN operation,
   *          as they appeared in the entry after the change was processed.  It
   *          may be empty if the change was not a modify or modify DN
   *          operation, or if the changelog entry did not include any
   *          information about virtual attributes as they appeared after the
   *          change.
   */
  @NotNull()
  public List<Attribute> getUpdatedVirtualAttributesAfterChange()
  {
    return updatedVirtualAttributesAfterChange;
  }



  /**
   * Retrieves information about any attributes updated in the associated modify
   * or modify DN operation that had too many values to include in the changelog
   * entry's set of before and/or after values.
   *
   * @return  Information about attributes updated in the associated modify or
   *          modify DN operation that had too many values to include in the
   *          changelog entry's set of before and/or after values, or an empty
   *          list if none of the updated attributes had too many values, the
   *          server is not configured to provide (or does not support
   *          providing) previous and resulting versions of updated attributes,
   *          or the change was not the result of a modify or modify DN
   *          operation.
   */
  @NotNull()
  public List<ChangeLogEntryAttributeExceededMaxValuesCount>
              getAttributesThatExceededMaxValuesCount()
  {
    return attributesThatExceededMaxValuesCount;
  }



  /**
   * Retrieves information about any attributes updated in the associated modify
   * or modify DN operation that had too many virtual values to include in the
   * changelog entry's set of before and/or after virtual values.
   *
   * @return  Information about attributes updated in the associated modify or
   *          modify DN operation that had too many virtual values to include in
   *          the changelog entry's set of before and/or after virtual values,
   *          or an empty list if none of the updated attributes had too many
   *          virtual values, the server is not configured to provide (or does
   *          not support providing) previous and resulting versions of updated
   *          attributes, or the change was not the result of a modify or modify
   *          DN operation.
   */
  @NotNull()
  public List<ChangeLogEntryAttributeExceededMaxValuesCount>
              getVirtualAttributesThatExceededMaxValuesCount()
  {
    return virtualAttributesThatExceededMaxValuesCount;
  }



  /**
   * Retrieves a list containing key attributes from the target entry, as
   * defined in the server configuration.  For add, modify, and modify DN
   * operations, this will include the key attributes as they appeared in the
   * entry after the change had been processed.  For delete operations, this
   * will include the key attributes as they appeared in the entry just before
   * it was removed.
   *
   * @return  A list containing key attributes from the target entry, or an
   *          empty list if the associated entry did not have any key attributes
   *          or there are no key attribute types defined in the server
   *          configuration.
   */
  @NotNull()
  public List<Attribute> getKeyEntryAttributes()
  {
    return keyEntryAttributes;
  }



  /**
   * Retrieves a list containing key attributes from the target entry, as
   * defined in the server configuration.  For add, modify, and modify DN
   * operations, this will include the key attributes as they appeared in the
   * entry after the change had been processed.  For delete operations, this
   * will include the key attributes as they appeared in the entry just before
   * it was removed.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  A list containing key attributes from the target entry, or an
   *          empty list if the associated entry did not have any key attributes
   *          or there are no key attribute types defined in the server
   *          configuration.
   */
  @NotNull()
  public List<Attribute> getKeyEntryAttributes(final boolean includeVirtual)
  {
    if (includeVirtual && (! keyEntryVirtualAttributes.isEmpty()))
    {
      final Entry e = new Entry(getTargetDN(), keyEntryAttributes);
      for (final Attribute a : keyEntryVirtualAttributes)
      {
        e.addAttribute(a);
      }

      return Collections.unmodifiableList(new ArrayList<>(e.getAttributes()));
    }
    else
    {
      return keyEntryAttributes;
    }
  }



  /**
   * Retrieves a list containing virtual values for key attributes from the
   * target entry, as defined in the server configuration.  For add, modify, and
   * modify DN operations, this will include the virtual values for key
   * attributes as they appeared in the entry after the change had been
   * processed.  For delete operations, this will include the virtual values for
   * key attributes as they appeared in the entry just before it was removed.
   *
   * @return  A list containing virtual values for key attributes from the
   *          target entry, or an empty list if the associated entry did not
   *          have any virtual values for key attributes or there are no key
   *          attribute types defined in the server configuration.
   */
  @NotNull()
  public List<Attribute> getKeyEntryVirtualAttributes()
  {
    return keyEntryVirtualAttributes;
  }



  /**
   * Retrieves the number of user attributes for which information was excluded
   * from the changelog entry by access control and/or sensitive attribute
   * processing, if available.
   *
   * @return  The number of user attributes for which information was excluded
   *          from the changelog entry by access control and/or sensitive
   *          attribute processing, or -1 if that information was not included
   *          in the changelog entry.
   */
  public int getNumExcludedUserAttributes()
  {
    if (numExcludedUserAttributes == null)
    {
      return -1;
    }
    else
    {
      return numExcludedUserAttributes;
    }
  }



  /**
   * Retrieves the number of operational attributes for which information was
   * excluded from the changelog entry by access control and/or sensitive
   * attribute processing, if available.
   *
   * @return  The number of operational attributes for which information was
   *          excluded from the changelog entry by access control and/or
   *          sensitive attribute processing, or -1 if that information was not
   *          included in the changelog entry.
   */
  public int getNumExcludedOperationalAttributes()
  {
    if (numExcludedOperationalAttributes == null)
    {
      return -1;
    }
    else
    {
      return numExcludedOperationalAttributes;
    }
  }



  /**
   * Retrieves the names of any user attributes for which information was
   * excluded from the changelog entry by access control and/or sensitive
   * attribute processing, if available.
   *
   * @return  The names of any user attributes for which information was
   *          excluded from the changelog entry by access control and/or
   *          sensitive attribute processing, or an empty list if that
   *          information was not included in the changelog entry.
   */
  @NotNull()
  public List<String> getExcludedUserAttributeNames()
  {
    return excludedUserAttributeNames;
  }



  /**
   * Retrieves the names of any operational attributes for which information was
   * excluded from the changelog entry by access control and/or sensitive
   * attribute processing, if available.
   *
   * @return  The names of any operational attributes for which information was
   *          excluded from the changelog entry by access control and/or
   *          sensitive processing, or an empty list if that information was not
   *          included in the changelog entry.
   */
  @NotNull()
  public List<String> getExcludedOperationalAttributeNames()
  {
    return excludedOperationalAttributeNames;
  }



  /**
   * Indicates whether the associated modify or delete operation targeted a
   * soft-deleted entry.
   *
   * @return  {@code true} if the modify or delete operation targeted a
   *          soft-deleted entry, {@code false} if not, or {@code null} if that
   *          information was not included in the changelog entry (which likely
   *          indicates that the operation did not target a soft-deleted
   *          entry).
   */
  @Nullable()
  public Boolean getChangeToSoftDeletedEntry()
  {
    return changeToSoftDeletedEntry;
  }



  /**
   * Retrieves the DN of the soft-deleted entry that resulted from the
   * associated soft delete operation.
   *
   * @return  The DN of the soft-deleted entry that resulted from the associated
   *          soft delete operation, or {@code null} if that information was not
   *          included in the changelog entry (e.g., because it does not
   *          represent a soft delete operation).
   */
  @Nullable()
  public String getSoftDeleteToDN()
  {
    return softDeleteToDN;
  }



  /**
   * Retrieves the DN of the soft-deleted entry from which the content of an add
   * operation was obtained, if that operation represents an undelete rather
   * than a normal add.
   *
   * @return  The DN of the soft-deleted entry from which the content of an add
   *          operation was obtained, or {@code null} if that information was
   *          not included in the changelog entry (e.g., because it does not
   *          represent an undelete operation).
   */
  @Nullable()
  public String getUndeleteFromDN()
  {
    return undeleteFromDN;
  }



  /**
   * Retrieves the names of any attributes targeted by the change, if available.
   * For an add operation, this may include the attributes in the entry that
   * was added.  For a delete operation, this may include the attributes in the
   * entry that was deleted.  For a modify operation, this may include the
   * attributes targeted by modifications.  For a modify DN operation, this may
   * include attributes used in the new RDN and potentially any other attributes
   * altered during the change.
   * <BR><BR>
   * Note that this information may not be available in all changelog entries or
   * Directory Server versions, and complete information about some changes may
   * only be available in some changelog configurations (e.g., information about
   * attributes included in delete operations may only be available if
   * changelog-deleted-entry-include-attribute is configured, and information
   * about changes to non-RDN attributes for modify DN operations may only be
   * available if changelog-max-before-after-values is configured).
   *
   * @return  The names of any attributes targeted by the change, or an empty
   *          list if that information was not included in the changelog entry.
   */
  @NotNull()
  public List<String> getTargetAttributeNames()
  {
    return targetAttributeNames;
  }



  /**
   * Retrieves a list of the entryUUID values for any notification destinations
   * for which the change matches one or more subscriptions.
   *
   * @return  A list of the entryUUID values for any notification destinations
   *          for which the change matches one or more subscriptions, or an
   *          empty list if that information was not included in the changelog
   *          entry.
   */
  @NotNull()
  public List<String> getNotificationDestinationEntryUUIDs()
  {
    return notificationDestinationEntryUUIDs;
  }



  /**
   * Retrieves a list of any notification properties included in the changelog
   * entry.
   *
   * @return  A list of any notification properties included in the changelog
   *          entry, or an empty list if that information was not included in
   *          the changelog entry.
   */
  @NotNull()
  public List<String> getNotificationProperties()
  {
    return notificationProperties;
  }



  /**
   * Retrieves the specified attribute as it appeared in the target entry before
   * the change was processed, if available.  It will not include any virtual
   * values.
   *
   * @param  name  The name of the attribute to retrieve as it appeared before
   *               the change.
   *
   * @return  The requested attribute as it appeared in the target entry before
   *          the change was processed, or {@code null} if it was not available
   *          in the changelog entry.
   *
   * @throws  ChangeLogEntryAttributeExceededMaxValuesException  If the
   *               specified attribute had more values before the change than
   *               may be included in a changelog entry.
   */
  @Nullable()
  public Attribute getAttributeBeforeChange(@NotNull final String name)
         throws ChangeLogEntryAttributeExceededMaxValuesException
  {
    return getAttributeBeforeChange(name, false);
  }



  /**
   * Retrieves the specified attribute as it appeared in the target entry before
   * the change was processed, if available.  It may optionally include virtual
   * values.
   *
   * @param  name            The name of the attribute to retrieve as it
   *                         appeared before the change.
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attribute to be returned.
   *
   * @return  The requested attribute as it appeared in the target entry before
   *          the change was processed, or {@code null} if it was not available
   *          in the changelog entry.
   *
   * @throws  ChangeLogEntryAttributeExceededMaxValuesException  If the
   *               specified attribute had more values before the change than
   *               may be included in a changelog entry.
   */
  @Nullable()
  public Attribute getAttributeBeforeChange(@NotNull final String name,
                                            final boolean includeVirtual)
         throws ChangeLogEntryAttributeExceededMaxValuesException
  {
    if (getChangeType() == ChangeType.ADD)
    {
      return null;
    }

    for (final Attribute a : getUpdatedAttributesBeforeChange(includeVirtual))
    {
      if (a.getName().equalsIgnoreCase(name))
      {
        return a;
      }
    }

    for (final ChangeLogEntryAttributeExceededMaxValuesCount a :
         attributesThatExceededMaxValuesCount)
    {
      if (a.getAttributeName().equalsIgnoreCase(name))
      {
        // TODO:  In the event that the before count was exceeded but the after
        // count was not, then we may be able to reconstruct the before values
        // if the changes included deleting specific values for the attribute.
        throw new ChangeLogEntryAttributeExceededMaxValuesException(
             ERR_CHANGELOG_EXCEEDED_BEFORE_VALUE_COUNT.get(name, getTargetDN(),
                  a.getBeforeCount()),
             a);
      }
    }

    if (includeVirtual)
    {
      for (final ChangeLogEntryAttributeExceededMaxValuesCount a :
           virtualAttributesThatExceededMaxValuesCount)
      {
        if (a.getAttributeName().equalsIgnoreCase(name))
        {
          // TODO:  In the event that the before count was exceeded but the
          // after count was not, then we may be able to reconstruct the before
          // values if the changes included deleting specific values for the
          // attribute.
          throw new ChangeLogEntryAttributeExceededMaxValuesException(
               ERR_CHANGELOG_EXCEEDED_VIRTUAL_BEFORE_VALUE_COUNT.get(name,
                    getTargetDN(), a.getBeforeCount()),
               a);
        }
      }
    }

    for (final Attribute a : getKeyEntryAttributes(includeVirtual))
    {
      if (a.getName().equalsIgnoreCase(name))
      {
        return a;
      }
    }

    final List<Attribute> deletedAttrs =
         getDeletedEntryAttributes(includeVirtual);
    if (deletedAttrs != null)
    {
      for (final Attribute a : deletedAttrs)
      {
        if (a.getName().equalsIgnoreCase(name))
        {
          return a;
        }
      }
    }

    return null;
  }



  /**
   * Retrieves the specified attribute as it appeared in the target entry after
   * the change was processed, if available.    It will not include any virtual
   * values.
   *
   * @param  name  The name of the attribute to retrieve as it appeared after
   *               the change.
   *
   * @return  The requested attribute as it appeared in the target entry after
   *          the change was processed, or {@code null} if it was not available
   *          in the changelog entry.
   *
   * @throws  ChangeLogEntryAttributeExceededMaxValuesException  If the
   *               specified attribute had more values before the change than
   *               may be included in a changelog entry.
   */
  @Nullable()
  public Attribute getAttributeAfterChange(@NotNull final String name)
         throws ChangeLogEntryAttributeExceededMaxValuesException
  {
    return getAttributeAfterChange(name, false);
  }



  /**
   * Retrieves the specified attribute as it appeared in the target entry after
   * the change was processed, if available.  It may optionally include virtual
   * values.
   *
   * @param  name            The name of the attribute to retrieve as it
   *                         appeared after the change.
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  The requested attribute as it appeared in the target entry after
   *          the change was processed, or {@code null} if it was not available
   *          in the changelog entry.
   *
   * @throws  ChangeLogEntryAttributeExceededMaxValuesException  If the
   *               specified attribute had more values before the change than
   *               may be included in a changelog entry.
   */
  @Nullable()
  public Attribute getAttributeAfterChange(@NotNull final String name,
                                           final boolean includeVirtual)
         throws ChangeLogEntryAttributeExceededMaxValuesException
  {
    if (getChangeType() == ChangeType.DELETE)
    {
      return null;
    }

    for (final Attribute a : getUpdatedAttributesAfterChange(includeVirtual))
    {
      if (a.getName().equalsIgnoreCase(name))
      {
        return a;
      }
    }

    for (final Attribute a : getKeyEntryAttributes(includeVirtual))
    {
      if (a.getName().equalsIgnoreCase(name))
      {
        return a;
      }
    }

    for (final ChangeLogEntryAttributeExceededMaxValuesCount a :
         attributesThatExceededMaxValuesCount)
    {
      if (a.getAttributeName().equalsIgnoreCase(name))
      {
        // TODO:  In the event that the after count was exceeded but the before
        // count was not, then we may be able to reconstruct the after values
        // if the changes included adding specific values for the attribute.
        throw new ChangeLogEntryAttributeExceededMaxValuesException(
             ERR_CHANGELOG_EXCEEDED_AFTER_VALUE_COUNT.get(name, getTargetDN(),
                  a.getAfterCount()),
             a);
      }
    }

    if (includeVirtual)
    {
      for (final ChangeLogEntryAttributeExceededMaxValuesCount a :
           virtualAttributesThatExceededMaxValuesCount)
      {
        if (a.getAttributeName().equalsIgnoreCase(name))
        {
          // TODO:  In the event that the after count was exceeded but the
          // before count was not, then we may be able to reconstruct the after
          // values if the changes included adding specific values for the
          // attribute.
          throw new ChangeLogEntryAttributeExceededMaxValuesException(
               ERR_CHANGELOG_EXCEEDED_VIRTUAL_AFTER_VALUE_COUNT.get(name,
                    getTargetDN(), a.getAfterCount()),
               a);
        }
      }
    }

    final List<Attribute> addAttrs = getAddAttributes(includeVirtual);
    if (addAttrs != null)
    {
      for (final Attribute a : addAttrs)
      {
        if (a.getName().equalsIgnoreCase(name))
        {
          return a;
        }
      }
    }

    final List<Modification> mods = getModifications();
    if (mods != null)
    {
      for (final Modification m : mods)
      {
        if (m.getAttributeName().equalsIgnoreCase(name))
        {
          final byte[][] values = m.getValueByteArrays();
          if ((m.getModificationType() == ModificationType.REPLACE) &&
              (values.length > 0))
          {
            return new Attribute(name, values);
          }
        }
      }
    }

    return null;
  }



  /**
   * Attempts to construct a partial representation of the target entry as it
   * appeared before the change was processed.  The information contained in the
   * constructed entry will be based solely on information contained in the
   * changelog entry, including information provided in the deletedEntryAttrs,
   * ds-changelog-before-values, ds-changelog-after-values,
   * ds-changelog-entry-key-attr-values, and
   * ds-changelog-attr-exceeded-max-values-count attributes.  It will not
   * include any virtual attribute information.
   *
   * @return  A partial representation of the target entry as it appeared before
   *          the change was processed, or {@code null} if the change was an
   *          add operation and therefore the entry did not exist before the
   *          change.
   */
  @Nullable()
  public ReadOnlyEntry constructPartialEntryBeforeChange()
  {
    return constructPartialEntryBeforeChange(false);
  }



  /**
   * Attempts to construct a partial representation of the target entry as it
   * appeared before the change was processed.  The information contained in the
   * constructed entry will be based solely on information contained in the
   * changelog entry, including information provided in the deletedEntryAttrs,
   * ds-changelog-before-values, ds-changelog-after-values,
   * ds-changelog-entry-key-attr-values, and
   * ds-changelog-attr-exceeded-max-values-count attributes, and optionally
   * virtual versions of all of those elements.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  A partial representation of the target entry as it appeared before
   *          the change was processed, or {@code null} if the change was an
   *          add operation and therefore the entry did not exist before the
   *          change.
   */
  @Nullable()
  public ReadOnlyEntry constructPartialEntryBeforeChange(
                            final boolean includeVirtual)
  {
    if (getChangeType() == ChangeType.ADD)
    {
      return null;
    }

    final Entry e = new Entry(getTargetDN());

    // If there is a set of deleted entry attributes available, then use them.
    final List<Attribute> deletedEntryAttrs =
         getDeletedEntryAttributes(includeVirtual);
    if (deletedEntryAttrs != null)
    {
      for (final Attribute a : deletedEntryAttrs)
      {
        e.addAttribute(a);
      }
    }

    // If there is a set of before attributes, then use them.
    for (final Attribute a : getUpdatedAttributesBeforeChange(includeVirtual))
    {
      e.addAttribute(a);
    }

    // If there is a set of key attributes, then only use them if the
    // associated attributes aren't already in the entry and aren't in either
    // the after values and exceeded max values count.
    for (final Attribute a : getKeyEntryAttributes(includeVirtual))
    {
      boolean shouldExclude = e.hasAttribute(a.getName());

      for (final Attribute ba : getUpdatedAttributesAfterChange(includeVirtual))
      {
        if (ba.getName().equalsIgnoreCase(a.getName()))
        {
          shouldExclude = true;
        }
      }

      for (final ChangeLogEntryAttributeExceededMaxValuesCount ea :
           attributesThatExceededMaxValuesCount)
      {
        if (ea.getAttributeName().equalsIgnoreCase(a.getName()))
        {
          // TODO:  In the event that the before count was exceeded but the
          // after count was not, then we may be able to reconstruct the before
          // values if the changes included deleting specific values for the
          // attribute.
          shouldExclude = true;
        }
      }

      if (includeVirtual)
      {
        for (final ChangeLogEntryAttributeExceededMaxValuesCount ea :
             virtualAttributesThatExceededMaxValuesCount)
        {
          if (ea.getAttributeName().equalsIgnoreCase(a.getName()))
          {
            // TODO:  In the event that the before count was exceeded but the
            // after count was not, then we may be able to reconstruct the
            // before values if the changes included deleting specific values
            // for the attribute.
            shouldExclude = true;
          }
        }
      }

      if (! shouldExclude)
      {
        e.addAttribute(a);
      }
    }

    // NOTE:  Although we could possibly get additional attribute values from
    // the entry's RDN, that can't be considered authoritative because those
    // same attributes may have additional values that aren't in the RDN, and we
    // don't want to include an attribute without the entire set of values.

    return new ReadOnlyEntry(e);
  }



  /**
   * Attempts to construct a partial representation of the target entry as it
   * appeared after the change was processed.  The information contained in the
   * constructed entry will be based solely on information contained in the
   * changelog entry, including information provided in the changes,
   * ds-changelog-after-values, and ds-changelog-entry-key-attr-values
   * attributes.  It will not include any virtual attribute information.
   *
   * @return  A partial representation of the target entry as it appeared after
   *          the change was processed, or {@code null} if the change was a
   *          delete operation and therefore did not exist after the change.
   */
  @Nullable()
  public ReadOnlyEntry constructPartialEntryAfterChange()
  {
    return constructPartialEntryAfterChange(false);
  }



  /**
   * Attempts to construct a partial representation of the target entry as it
   * appeared after the change was processed.  The information contained in the
   * constructed entry will be based solely on information contained in the
   * changelog entry, including information provided in the changes,
   * ds-changelog-after-values, and ds-changelog-entry-key-attr-values
   * attributes, and optionally virtual versions of all of those elements.
   *
   * @param  includeVirtual  Indicates whether to include both real and virtual
   *                         values (if {@code true}, or only real values (if
   *                         {@code false}), for the attributes to be returned.
   *
   * @return  A partial representation of the target entry as it appeared after
   *          the change was processed, or {@code null} if the change was a
   *          delete operation and therefore did not exist after the change.
   */
  @Nullable()
  public ReadOnlyEntry constructPartialEntryAfterChange(
                            final boolean includeVirtual)
  {
    final Entry e;
    switch (getChangeType())
    {
      case ADD:
      case MODIFY:
        e = new Entry(getTargetDN());
        break;

      case MODIFY_DN:
        e = new Entry(getNewDN());
        break;

      case DELETE:
      default:
        return null;
    }


    // If there is a set of add attributes, then use them.
    final List<Attribute> addAttrs = getAddAttributes(includeVirtual);
    if (addAttrs != null)
    {
      for (final Attribute a : addAttrs)
      {
        e.addAttribute(a);
      }
    }

    // If there is a set of modifications and any of them are replace
    // modifications with a set of values, then we can use them to determine
    // the new values of those attributes.
    final List<Modification> mods = getModifications();
    if (mods != null)
    {
      for (final Modification m : mods)
      {
        final byte[][] values = m.getValueByteArrays();
        if ((m.getModificationType() == ModificationType.REPLACE) &&
            (values.length > 0))
        {
          e.addAttribute(m.getAttributeName(), values);
        }
      }
    }

    // If there is a set of after attributes, then use them.
    for (final Attribute a : getUpdatedAttributesAfterChange(includeVirtual))
    {
      e.addAttribute(a);
    }

    // If there is a set of key attributes, then use them.
    for (final Attribute a : getKeyEntryAttributes(includeVirtual))
    {
      e.addAttribute(a);
    }

    // TODO:  In the event that the after count was exceeded but the before
    // count was not, then we may be able to reconstruct the after values if the
    // changes included adding specific values for the attribute.

    // NOTE:  Although we could possibly get additional attribute values from
    // the entry's RDN, that can't be considered authoritative because those
    // same attributes may have additional values that aren't in the RDN, and we
    // don't want to include an attribute without the entire set of values.

    return new ReadOnlyEntry(e);
  }
}
