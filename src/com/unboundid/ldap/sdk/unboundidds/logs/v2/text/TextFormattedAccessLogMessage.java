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
package com.unboundid.ldap.sdk.unboundidds.logs.v2.text;



import com.unboundid.ldap.sdk.unboundidds.logs.v2.AccessLogMessage;
import com.unboundid.util.NotExtensible;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a
 * text-formatted access log message.
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
@NotExtensible()
@ThreadSafety(level=ThreadSafetyLevel.INTERFACE_THREADSAFE)
public abstract class TextFormattedAccessLogMessage
       extends TextFormattedLogMessage
       implements AccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 458413508863077700L;



  // The connection ID value from the log message.
  @Nullable private final Long connectionID;

  // The thread ID value from the log message.
  @Nullable private final Long threadID;

  // The instance name value from the log message.
  @Nullable private final String instanceName;

  // The product name value from the log message.
  @Nullable private final String productName;

  // The startup ID value from the log message.
  @Nullable private final String startupID;



  /**
   * Creates a new text-formatted access log message from the provided message.
   *
   * @param  logMessage  The log message to use to create this access log
   *                     message.  It must not be {@code null}.
   */
  protected TextFormattedAccessLogMessage(
                 @NotNull final TextFormattedLogMessage logMessage)
  {
    super(logMessage);

    instanceName = getString(TextFormattedAccessLogFields.INSTANCE_NAME);
    productName = getString(TextFormattedAccessLogFields.PRODUCT_NAME);
    startupID = getString(TextFormattedAccessLogFields.STARTUP_ID);
    threadID = getLongNoThrow(TextFormattedAccessLogFields.THREAD_ID);
    connectionID =
         getLongNoThrow(TextFormattedAccessLogFields.CONNECTION_ID);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getProductName()
  {
    return productName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getInstanceName()
  {
    return instanceName;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final String getStartupID()
  {
    return startupID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable()
  public final Long getThreadID()
  {
    return threadID;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @Nullable
  public final Long getConnectionID()
  {
    return connectionID;
  }
}
