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
import java.util.StringTokenizer;

import com.unboundid.util.Debug;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides a data structure for holding information about a single
 * DNS SRV record.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
final class SRVRecord
      implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -5505867807717870889L;



  // The port for this record.
  private final int port;

  // The priority for this record.
  private final long priority;

  // The weight for this record.
  private final long weight;

  // The address for this record.
  @NotNull private final String address;

  // The string representation of this record.
  @NotNull private final String recordString;



  /**
   * Decodes the provided string to obtain information about a DNS SRV record.
   * The string should contain four space-delimited values in the following
   * order:  priority weight port address.
   *
   * @param  recordString  The string representation of the record to be parsed.
   *
   * @throws  LDAPException  If a problem is encountered while parsing the
   *                         record.
   */
  SRVRecord(@NotNull final String recordString)
       throws LDAPException
  {
    this.recordString = recordString;

    try
    {
      final StringTokenizer tokenizer = new StringTokenizer(recordString, " ");
      priority = Long.parseLong(tokenizer.nextToken());
      weight   = Long.parseLong(tokenizer.nextToken());
      port     = Integer.parseInt(tokenizer.nextToken());

      final String addrString = tokenizer.nextToken();
      if (addrString.endsWith("."))
      {
        address = addrString.substring(0, addrString.length() - 1);
      }
      else
      {
        address = addrString;
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);

      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_SRV_RECORD_MALFORMED_STRING.get(recordString,
                StaticUtils.getExceptionMessage(e)),
           e);
    }
  }



  /**
   * Retrieves the address of the server described by this DNS SRV record.
   *
   * @return  The address of the server described by this DNS SRV record.
   */
  @NotNull()
  public String getAddress()
  {
    return address;
  }



  /**
   * Retrieves the port of the server described by this DNS SRV record.
   *
   * @return  The port of the server described by this DNS SRV record.
   */
  public int getPort()
  {
    return port;
  }



  /**
   * Retrieves the priority of the server described by this DNS SRV record.
   *
   * @return  The priority of the server described by this DNS SRV record.
   */
  public long getPriority()
  {
    return priority;
  }



  /**
   * Retrieves the weight of the server described by this DNS SRV record.
   *
   * @return  The weight of the server described by this DNS SRV record.
   */
  public long getWeight()
  {
    return weight;
  }



  /**
   * Retrieves a string representation of this DNS SRV record.
   *
   * @return  A string representation of this DNS SRV record.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return recordString;
  }
}
