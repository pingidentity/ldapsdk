/*
 * Copyright 2008-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2008-2021 Ping Identity Corporation
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
 * Copyright (C) 2008-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.io.Serializable;

import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that may be used to hold information
 * about disk space information for a Directory Server component.
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
public final class DiskSpaceInfo
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -7798824641501237274L;



  // The number of total bytes at the specified path.
  @Nullable private final Long totalBytes;

  // The number of usable bytes at the specified path.
  @Nullable private final Long usableBytes;

  // The percentage of the total space that is usable.
  @Nullable private final Long usablePercent;

  // The name of the associated disk space consumer.
  @Nullable private final String consumerName;

  // The path in which the disk space is being consumed.
  @Nullable private final String path;



  /**
   * Creates a new disk space info object with the provided information.
   *
   * @param  consumerName   The name of the server component which may consume
   *                        disk space.
   * @param  path           The path in which the server component may consume
   *                        disk space.
   * @param  totalBytes     The total amount of space in bytes on the volume
   *                        that holds the specified path.
   * @param  usableBytes    The amount of usable space in bytes on the volume
   *                        that holds the specified path.
   * @param  usablePercent  The percentage of the total space that is usable on
   *                        the volume that holds the specified path.
   *
   * @deprecated  Use the constructor that takes a {@code Long} object for the
   *              {@code usableBytes} parameter.
   */
  @Deprecated()
  public DiskSpaceInfo(@Nullable final String consumerName,
                       @Nullable final String path,
                       @Nullable final Long totalBytes,
                       @Nullable final Long usableBytes,
                       final long usablePercent)
  {
    this(consumerName, path, totalBytes, usableBytes,
         Long.valueOf(usablePercent));
  }



  /**
   * Creates a new disk space info object with the provided information.
   *
   * @param  consumerName   The name of the server component which may consume
   *                        disk space.
   * @param  path           The path in which the server component may consume
   *                        disk space.
   * @param  totalBytes     The total amount of space in bytes on the volume
   *                        that holds the specified path.
   * @param  usableBytes    The amount of usable space in bytes on the volume
   *                        that holds the specified path.
   * @param  usablePercent  The percentage of the total space that is usable on
   *                        the volume that holds the specified path.
   */
  public DiskSpaceInfo(@Nullable final String consumerName,
                       @Nullable final String path,
                       @Nullable final Long totalBytes,
                       @Nullable final Long usableBytes,
                       @Nullable final Long usablePercent)
  {
    this.consumerName  = consumerName;
    this.path          = path;
    this.totalBytes    = totalBytes;
    this.usableBytes   = usableBytes;
    this.usablePercent = usablePercent;
  }



  /**
   * The name of the server component which may consume disk space.
   *
   * @return  The name of the server component which may consume disk space, or
   *          {@code null} if that is not available.
   */
  @Nullable()
  public String getConsumerName()
  {
    return consumerName;
  }



  /**
   * Retrieves the path in which the server component may consume disk space.
   *
   * @return  The path in which the server component may consume disk space, or
   *          {@code null} if that is not available.
   */
  @Nullable()
  public String getPath()
  {
    return path;
  }



  /**
   * Retrieves the total amount of space in bytes on the volume that holds the
   * specified path.
   *
   * @return  The total amount of space in bytes on the volume that holds the
   *          specified path, or {@code null} if that is not available.
   */
  @Nullable()
  public Long getTotalBytes()
  {
    return totalBytes;
  }



  /**
   * Retrieves the amount of usable free space in bytes on the volume that holds
   * the specified path.
   *
   * @return  The total amount of usable free space in bytes on the volume that
   *          holds the specified path, or {@code null} if that is not
   *          available.
   */
  @Nullable()
  public Long getUsableBytes()
  {
    return usableBytes;
  }



  /**
   * Retrieves the percentage of the total space on the volume that holds the
   * specified path which is free and usable by the Directory Server.
   *
   * @return  The percentage of the total space on the volume that holds the
   *          specified path which is free and usable by the Directory Server.
   */
  @Nullable()
  public Long getUsablePercent()
  {
    return usablePercent;
  }



  /**
   * Retrieves a string representation of this disk space info object.
   *
   * @return  A string representation of this disk space info object.
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
   * Appends a string representation of this disk space info object to the
   * provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("DiskSpaceInfo(consumerName='");
    buffer.append(consumerName);
    buffer.append("', path='");
    buffer.append(path);
    buffer.append("', totalBytes=");
    buffer.append(totalBytes);
    buffer.append(", usableBytes=");
    buffer.append(usableBytes);
    buffer.append(", usablePercent=");
    buffer.append(usablePercent);
    buffer.append(')');
  }
}
