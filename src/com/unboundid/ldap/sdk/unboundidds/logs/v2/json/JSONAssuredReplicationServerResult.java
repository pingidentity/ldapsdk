/*
 * Copyright 2022-2025 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022-2025 Ping Identity Corporation
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
 * Copyright (C) 2022-2025 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.json;



import java.io.Serializable;

import com.unboundid.ldap.sdk.unboundidds.controls.
            AssuredReplicationServerResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;



/**
 * This class provides a data structure that contains information about a
 * server result from an assurance completed access log message.
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
public final class JSONAssuredReplicationServerResult
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7810704048456207340L;



  // The result code for this result.
  @Nullable private final AssuredReplicationServerResultCode resultCode;

  // The JSON object containing an encoded representation of this server result.
  @NotNull private final JSONObject serverResultObject;

  // The replica ID for this result.
  @Nullable private final Long replicaID;

  // The replication server ID for this result.
  @Nullable private final Long replicationServerID;



  /**
   * Creates a new JSON assured replication server result that is decoded from
   * the provided JSON object.
   *
   * @param  serverResultObject  The JSON object containing an encoded
   *                             representation of this server result.
   */
  public JSONAssuredReplicationServerResult(
              @NotNull final JSONObject serverResultObject)
  {
    this.serverResultObject = serverResultObject;

    replicaID = serverResultObject.getFieldAsLong(JSONFormattedAccessLogFields.
         SERVER_ASSURANCE_RESULTS_REPLICA_ID.getFieldName());
    replicationServerID = serverResultObject.getFieldAsLong(
         JSONFormattedAccessLogFields.
              SERVER_ASSURANCE_RESULTS_REPLICATION_SERVER_ID.getFieldName());

    final String resultCodeName = serverResultObject.getFieldAsString(
         JSONFormattedAccessLogFields.SERVER_ASSURANCE_RESULTS_RESULT_CODE.
              getFieldName());
    if (resultCodeName == null)
    {
      resultCode = null;
    }
    else
    {
      resultCode = AssuredReplicationServerResultCode.forName(resultCodeName);
    }
  }



  /**
   * Retrieves the JSON object containing an encoded representation of this
   * assured replication server result.
   *
   * @return  The JSON object containing an encoded representation of this
   *          certificate.
   */
  @NotNull()
  public JSONObject getServerResultObject()
  {
    return serverResultObject;
  }



  /**
   * Retrieves the result code for this server result.
   *
   * @return  The result code for this server result.
   */
  @Nullable()
  public AssuredReplicationServerResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the replication server ID for this server result.
   *
   * @return  The replication server ID for this server result.
   */
  @Nullable()
  public Long getReplicationServerID()
  {
    return replicationServerID;
  }



  /**
   * Retrieves the replica ID for this server result.
   *
   * @return  The replica ID for this server result.
   */
  @Nullable()
  public Long getReplicaID()
  {
    return replicaID;
  }



  /**
   * Retrieves a string representation of this JSON assured replication server
   * result.
   *
   * @return  A string representation of this JSON assured replication server
   *          result.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    return serverResultObject.toSingleLineString();
  }
}
