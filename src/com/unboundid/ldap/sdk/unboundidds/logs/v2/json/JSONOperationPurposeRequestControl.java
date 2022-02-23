/*
 * Copyright 2022 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2022 Ping Identity Corporation
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
 * Copyright (C) 2022 Ping Identity Corporation
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

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.json.JSONObject;

import static com.unboundid.ldap.sdk.unboundidds.logs.v2.json.
                   JSONFormattedAccessLogFields.*;



/**
 * This class provides a data structure that contains information about an
 * JSON-formatted operation purpose request control.
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
public final class JSONOperationPurposeRequestControl
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7062571568593641747L;



  // The JSON object with an encoded representation of this control.
  @NotNull private final JSONObject controlObject;

  // The application name from the control.
  @Nullable private final String applicationName;

  // The application version from the control.
  @Nullable private final String applicationVersion;

  // The code location from the control.
  @Nullable private final String codeLocation;

  // The request purpose from the control.
  @Nullable private final String requestPurpose;



  /**
   * Creates a new JSON operation purpose request control that is decoded from
   * the provided JSON object.
   *
   * @param  controlObject  The JSON object containing an encoded representation
   *                        of this operation purpose request control.
   */
  public JSONOperationPurposeRequestControl(
              @NotNull final JSONObject controlObject)
  {
    this.controlObject = controlObject;

    applicationName = controlObject.getFieldAsString(
         OPERATION_PURPOSE_APPLICATION_NAME.getFieldName());
    applicationVersion = controlObject.getFieldAsString(
         OPERATION_PURPOSE_APPLICATION_VERSION.getFieldName());
    codeLocation = controlObject.getFieldAsString(
         OPERATION_PURPOSE_CODE_LOCATION.getFieldName());
    requestPurpose = controlObject.getFieldAsString(
         OPERATION_PURPOSE_REQUEST_PURPOSE.getFieldName());
  }



  /**
   * Retrieves a JSON object containing an encoded representation of this
   * operation purpose request control.
   *
   * @return  A JSON object containing an encoded representation of this
   *          operation purpose request control.
   */
  @NotNull()
  public JSONObject getControlObject()
  {
    return controlObject;
  }



  /**
   * Retrieves the name of the application that generated this control.
   *
   * @return  The name of the application that generated this control, or
   *          {@code null} if it was not included in the log message.
   */
  @Nullable()
  public String getApplicationName()
  {
    return applicationName;
  }



  /**
   * Retrieves the version of the application that generated this control.
   *
   * @return  The version of the application that generated this control, or
   *          {@code null} if it was not included in the log message.
   */
  @Nullable()
  public String getApplicationVersion()
  {
    return applicationVersion;
  }



  /**
   * Retrieves a description of the location in the application code where the
   * control was generated.
   *
   * @return  A description of the location in the application code where the
   *          control was generated, or {@code null} if it was not included in
   *          the log message.
   */
  @Nullable()
  public String getCodeLocation()
  {
    return codeLocation;
  }



  /**
   * Retrieves the request purpose from the control.
   *
   * @return  The request purpose from the control, or {@code null} if it was
   *          not included in the log message.
   */
  @Nullable()
  public String getRequestPurpose()
  {
    return requestPurpose;
  }



  /**
   * Retrieves a string representation of this operation purpose request
   * control.
   *
   * @return  A string representation of this operation purpose request control.
   */
  @NotNull()
  public String toString()
  {
    return controlObject.toSingleLineString();
  }
}
