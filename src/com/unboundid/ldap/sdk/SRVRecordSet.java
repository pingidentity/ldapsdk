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
package com.unboundid.ldap.sdk;



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import com.unboundid.util.Debug;
import com.unboundid.util.DebugType;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding information about a set of
 * DNS SRV records, and a method for ordering them for ordering them based on
 * their priorities and weights.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SRVRecordSet
      implements Serializable
{
  /**
   * The attribute name that will be used to retrieve the SRV record.
   */
  @NotNull private static final String DNS_ATTR_SRV = "SRV";



  /**
   * The names of the DNS attributes that should be retrieved.
   */
  @NotNull private static final String[] ATTRIBUTE_IDS = { DNS_ATTR_SRV };



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7075112952759306499L;



  // The total number of records to be processed.
  private final int totalRecords;

  // A list of all records associated with this set.  There is no defined order
  // to the list of records.
  @NotNull private final List<SRVRecord> allRecords;

  // A list of record sets ordered by ascending priority.
  @NotNull private final List<SRVRecordPrioritySet> recordSets;

  // The expiration time for this set.
  private final long expirationTime;



  /**
   * Creates a new SRV record set with the provided information.
   *
   * @param  expirationTime  The time that this information should be considered
   *                         expired.
   * @param  records         The set of all records to be processed.  It must
   *                         not be {@code null} or empty.
   */
  SRVRecordSet(final long expirationTime,
               @NotNull final List<SRVRecord> records)
  {
    this.expirationTime = expirationTime;

    allRecords = Collections.unmodifiableList(records);
    totalRecords = records.size();

    final TreeMap<Long,List<SRVRecord>> m = new TreeMap<>();
    for (final SRVRecord r : records)
    {
      final Long priority = r.getPriority();
      List<SRVRecord> l = m.get(priority);
      if (l == null)
      {
        l = new ArrayList<>(records.size());
        m.put(priority, l);
      }

      l.add(r);
    }

    final ArrayList<SRVRecordPrioritySet> l = new ArrayList<>(m.size());
    for (final Map.Entry<Long,List<SRVRecord>> e : m.entrySet())
    {
      l.add(new SRVRecordPrioritySet(e.getKey(), e.getValue()));
    }

    recordSets = Collections.unmodifiableList(l);
  }



  /**
   * Retrieves the expiration time for this set.
   *
   * @return  The expiration time for this set.
   */
  long getExpirationTime()
  {
    return expirationTime;
  }



  /**
   * Indicates whether the information in this record set is expired.
   *
   * @return  {@code true} if the expiration time has passed, or {@code false}
   *          if not.
   */
  boolean isExpired()
  {
    return (System.currentTimeMillis() >= expirationTime);
  }



  /**
   * Retrieves a list of all SRV records ordered by priority and weight.
   *
   * @return  A list of all SRV records ordered by priority and weight.
   */
  @NotNull()
  List<SRVRecord> getOrderedRecords()
  {
    final ArrayList<SRVRecord> l = new ArrayList<>(totalRecords);

    for (final SRVRecordPrioritySet s : recordSets)
    {
      l.addAll(s.getOrderedRecords());
    }

    return l;
  }



  /**
   * Attempts to communicate with DNS in order to retrieve a record set.
   *
   * @param  name            The name of the SRV record to retrieve.
   * @param  jndiProperties  The properties to use to initialize the JNDI
   *                         context.
   * @param  ttlMillis       Specifies the maximum length of time in
   *                         milliseconds that DNS information should be cached
   *                         before it needs to be retrieved again.
   *
   * @return  The record set retrieved from DNS.
   *
   * @throws  LDAPException  If an error occurs while querying DNS or while
   *                         parsing the results.
   */
  @NotNull()
  static SRVRecordSet getRecordSet(@NotNull final String name,
              @NotNull final Hashtable<String,String> jndiProperties,
              final long ttlMillis)
         throws LDAPException
  {
    final ArrayList<String> recordStrings = new ArrayList<>(10);
    DirContext context = null;

    try
    {
      if (Debug.debugEnabled(DebugType.CONNECT))
      {
        Debug.debug(Level.INFO, DebugType.CONNECT,
             "Issuing JNDI query to retrieve DNS SRV record '" + name +
                  "' using properties '" + jndiProperties + "'.");
      }

      context = new InitialDirContext(jndiProperties);
      final Attributes recordAttributes =
           context.getAttributes(name, ATTRIBUTE_IDS);
      context.close();

      final Attribute srvAttr = recordAttributes.get(DNS_ATTR_SRV);
      if (srvAttr == null)
      {
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_SRV_RECORD_SET_NO_RECORDS.get(name));
      }

      final NamingEnumeration<?> values = srvAttr.getAll();
      while (values.hasMore())
      {
        final Object value = values.next();
        recordStrings.add(String.valueOf(value));
      }
      values.close();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      throw le;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SRV_RECORD_SET_ERROR_QUERYING_DNS.get(name,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
    finally
    {
      if (context != null)
      {
        try
        {
          context.close();
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }

    if (recordStrings.isEmpty())
    {
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SRV_RECORD_SET_NO_RECORDS.get(name));
    }

    final List<SRVRecord> recordList = new ArrayList<>(recordStrings.size());
    for (final String s : recordStrings)
    {
      final SRVRecord r = new SRVRecord(s);
      recordList.add(r);
      if (Debug.debugEnabled(DebugType.CONNECT))
      {
        Debug.debug(Level.INFO, DebugType.CONNECT,
             "Decoded DNS SRV record " + r.toString());
      }
    }

    return new SRVRecordSet(System.currentTimeMillis() + ttlMillis, recordList);
  }



  /**
   * Retrieves a string representation of this priority server set.
   *
   * @return  A string representation of this priority server set.
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
   * Appends a string representation of this priority buffer set to the provided
   * buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  private void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("SRVRecordSet(records={");

    final Iterator<SRVRecord> iterator = allRecords.iterator();
    while (iterator.hasNext())
    {
      buffer.append(iterator.next().toString());
      if (iterator.hasNext())
      {
        buffer.append(", ");
      }
    }

    buffer.append("})");
  }
}
