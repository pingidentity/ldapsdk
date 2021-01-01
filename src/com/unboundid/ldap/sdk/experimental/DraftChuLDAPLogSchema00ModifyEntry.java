/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.experimental;



import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.ModifyRequest;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import com.unboundid.ldap.sdk.OperationType;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.experimental.ExperimentalMessages.*;



/**
 * This class represents an entry that holds information about a modify
 * operation processed by an LDAP server, as per the specification described in
 * draft-chu-ldap-logschema-00.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class DraftChuLDAPLogSchema00ModifyEntry
       extends DraftChuLDAPLogSchema00Entry
{
  /**
   * The name of the attribute used to hold the attribute changes contained in
   * the modify operation.
   */
  @NotNull public static final String ATTR_ATTRIBUTE_CHANGES = "reqMod";



  /**
   * The name of the attribute used to hold the former values of entries changed
   * by the modify operation.
   */
  @NotNull public static final String ATTR_FORMER_ATTRIBUTE = "reqOld";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 5787071409404025072L;



  // A list of the former versions of modified attributes.
  @NotNull private final List<Attribute> formerAttributes;

  // A list of the modifications contained in the request.
  @NotNull private final List<Modification> modifications;



  /**
   * Creates a new instance of this modify access log entry from the provided
   * entry.
   *
   * @param  entry  The entry used to create this modify access log entry.
   *
   * @throws  LDAPException  If the provided entry cannot be decoded as a valid
   *                         modify access log entry as per the specification
   *                         contained in draft-chu-ldap-logschema-00.
   */
  public DraftChuLDAPLogSchema00ModifyEntry(@NotNull final Entry entry)
         throws LDAPException
  {
    super(entry, OperationType.MODIFY);


    // Process the set of modifications.
    final byte[][] changes =
         entry.getAttributeValueByteArrays(ATTR_ATTRIBUTE_CHANGES);
    if ((changes == null) || (changes.length == 0))
    {
      throw new LDAPException(ResultCode.DECODING_ERROR,
           ERR_LOGSCHEMA_DECODE_MISSING_REQUIRED_ATTR.get(entry.getDN(),
                ATTR_ATTRIBUTE_CHANGES));
    }

    final ArrayList<Modification> mods = new ArrayList<>(changes.length);
    for (final byte[] changeBytes : changes)
    {
      int colonPos = -1;
      for (int i=0; i < changeBytes.length; i++)
      {
        if (changeBytes[i] == ':')
        {
          colonPos = i;
          break;
        }
      }

      if (colonPos < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_CHANGE_MISSING_COLON.get(entry.getDN(),
                  ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }
      else if (colonPos == 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_CHANGE_MISSING_ATTR.get(entry.getDN(),
                  ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }

      final String attrName =
           StaticUtils.toUTF8String(changeBytes, 0, colonPos);

      if (colonPos == (changeBytes.length - 1))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_CHANGE_MISSING_CHANGE_TYPE.get(
                  entry.getDN(), ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes)));
      }

      final boolean needValue;
      final ModificationType modType;
      switch (changeBytes[colonPos+1])
      {
        case '+':
          modType = ModificationType.ADD;
          needValue = true;
          break;
        case '-':
          modType = ModificationType.DELETE;
          needValue = false;
          break;
        case '=':
          modType = ModificationType.REPLACE;
          needValue = false;
          break;
        case '#':
          modType = ModificationType.INCREMENT;
          needValue = true;
          break;
        default:
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_LOGSCHEMA_DECODE_MODIFY_CHANGE_INVALID_CHANGE_TYPE.get(
                    entry.getDN(), ATTR_ATTRIBUTE_CHANGES,
                    StaticUtils.toUTF8String(changeBytes)));
      }

      if (changeBytes.length == (colonPos+2))
      {
        if (needValue)
        {
          throw new LDAPException(ResultCode.DECODING_ERROR,
               ERR_LOGSCHEMA_DECODE_MODIFY_CHANGE_MISSING_VALUE.get(
                    entry.getDN(), ATTR_ATTRIBUTE_CHANGES,
                    StaticUtils.toUTF8String(changeBytes),
                    modType.getName()));
        }
        else
        {
          mods.add(new Modification(modType, attrName));
          continue;
        }
      }

      if ((changeBytes.length == (colonPos+3)) ||
          (changeBytes[colonPos+2] != ' '))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_CHANGE_MISSING_SPACE.get(
                  entry.getDN(), ATTR_ATTRIBUTE_CHANGES,
                  StaticUtils.toUTF8String(changeBytes),
                  modType.getName()));
      }

      final byte[] attrValue = new byte[changeBytes.length - colonPos - 3];
      if (attrValue.length > 0)
      {
        System.arraycopy(changeBytes, (colonPos+3), attrValue, 0,
             attrValue.length);
      }

      if (mods.isEmpty())
      {
        mods.add(new Modification(modType, attrName, attrValue));
        continue;
      }

      final Modification lastMod = mods.get(mods.size() - 1);
      if ((lastMod.getModificationType() == modType) &&
          (lastMod.getAttributeName().equalsIgnoreCase(attrName)))
      {
        final byte[][] lastModValues = lastMod.getValueByteArrays();
        final byte[][] newValues = new byte[lastModValues.length+1][];
        System.arraycopy(lastModValues, 0, newValues, 0, lastModValues.length);
        newValues[lastModValues.length] = attrValue;
        mods.set((mods.size()-1),
             new Modification(modType, lastMod.getAttributeName(), newValues));
      }
      else
      {
        mods.add(new Modification(modType, attrName, attrValue));
      }
    }

    modifications = Collections.unmodifiableList(mods);


    // Get the former attribute values, if present.
    final byte[][] formerAttrBytes =
         entry.getAttributeValueByteArrays(ATTR_FORMER_ATTRIBUTE);
    if ((formerAttrBytes == null) || (formerAttrBytes.length == 0))
    {
      formerAttributes = Collections.emptyList();
      return;
    }

    final LinkedHashMap<String,List<Attribute>> attrMap = new LinkedHashMap<>(
         StaticUtils.computeMapCapacity(formerAttrBytes.length));
    for (final byte[] attrBytes : formerAttrBytes)
    {
      int colonPos = -1;
      for (int i=0; i < attrBytes.length; i++)
      {
        if (attrBytes[i] == ':')
        {
          colonPos = i;
          break;
        }
      }

      if (colonPos < 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_OLD_ATTR_MISSING_COLON.get(
                  entry.getDN(), ATTR_FORMER_ATTRIBUTE,
                  StaticUtils.toUTF8String(attrBytes)));
      }
      else if (colonPos == 0)
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_OLD_ATTR_MISSING_ATTR.get(
                  entry.getDN(), ATTR_FORMER_ATTRIBUTE,
                  StaticUtils.toUTF8String(attrBytes)));
      }

      if ((colonPos == (attrBytes.length - 1)) ||
          (attrBytes[colonPos+1] != ' '))
      {
        throw new LDAPException(ResultCode.DECODING_ERROR,
             ERR_LOGSCHEMA_DECODE_MODIFY_OLD_ATTR_MISSING_SPACE.get(
                  entry.getDN(), ATTR_FORMER_ATTRIBUTE,
                  StaticUtils.toUTF8String(attrBytes)));
      }

      final String attrName =
           StaticUtils.toUTF8String(attrBytes, 0, colonPos);
      final String lowerName = StaticUtils.toLowerCase(attrName);

      List<Attribute> attrList = attrMap.get(lowerName);
      if (attrList == null)
      {
        attrList = new ArrayList<>(10);
        attrMap.put(lowerName, attrList);
      }

      final byte[] attrValue = new byte[attrBytes.length - colonPos - 2];
      if (attrValue.length > 0)
      {
        System.arraycopy(attrBytes, colonPos + 2, attrValue, 0,
             attrValue.length);
      }

      attrList.add(new Attribute(attrName, attrValue));
    }

    final ArrayList<Attribute> oldAttributes = new ArrayList<>(attrMap.size());
    for (final List<Attribute> attrList : attrMap.values())
    {
      if (attrList.size() == 1)
      {
        oldAttributes.addAll(attrList);
      }
      else
      {
        final byte[][] valueArray = new byte[attrList.size()][];
        for (int i=0; i < attrList.size(); i++)
        {
          valueArray[i] = attrList.get(i).getValueByteArray();
        }
        oldAttributes.add(new Attribute(attrList.get(0).getName(), valueArray));
      }
    }

    formerAttributes = Collections.unmodifiableList(oldAttributes);
  }



  /**
   * Retrieves the modifications for the modify request described by this modify
   * access log entry.
   *
   * @return  The modifications for the modify request described by this modify
   *          access log entry.
   */
  @NotNull()
   public List<Modification> getModifications()
   {
     return modifications;
   }



  /**
   * Retrieves a list of former versions of modified attributes described by
   * this modify access log entry, if available.
   *
   * @return  A list of former versions of modified attributes, or an empty list
   *          if no former attribute information was included in the access log
   *          entry.
   */
  @NotNull()
  public List<Attribute> getFormerAttributes()
  {
    return formerAttributes;
  }



  /**
   * Retrieves a {@code ModifyRequest} created from this modify access log
   * entry.
   *
   * @return  The {@code ModifyRequest} created from this modify access log
   *          entry.
   */
  @NotNull()
  public ModifyRequest toModifyRequest()
  {
    return new ModifyRequest(getTargetEntryDN(), modifications,
         getRequestControlArray());
  }
}
