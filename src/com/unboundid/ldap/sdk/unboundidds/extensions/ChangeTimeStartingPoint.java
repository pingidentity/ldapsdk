/*
 * Copyright 2010-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2010-2021 Ping Identity Corporation
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
 * Copyright (C) 2010-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.extensions;



import java.util.Date;

import com.unboundid.asn1.ASN1Element;
import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.StaticUtils;



/**
 * This class provides an implementation of a changelog batch starting point
 * which may be used to start a batch of changes at a specified time.  The first
 * change of the batch will be the first change on any server with a change time
 * greater than or equal to the specified time.
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
public final class ChangeTimeStartingPoint
       extends ChangelogBatchStartingPoint
{
  /**
   * The BER type to use for the ASN.1 element used to encode this starting
   * point.
   */
  static final byte TYPE = (byte) 0x84;



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 920153185766534528L;



  // The time that defines the starting point for the changelog batch request.
  private final long changeTime;

  // The string representation of the start time, using the generalized time
  // syntax.
  @NotNull private final String changeTimeString;



  /**
   * Creates a new instance of this changelog starting point using the provided
   * start time.
   *
   * @param  changeTime  The time of the oldest change which may be used as the
   *                     starting point for the batch of changes.
   */
  public ChangeTimeStartingPoint(final long changeTime)
  {
    this.changeTime = changeTime;

    changeTimeString = StaticUtils.encodeGeneralizedTime(new Date(changeTime));
  }



  /**
   * Retrieves the time of the oldest change which may be used as the starting
   * point for the batch of changes.
   *
   * @return  The time of the oldest change which may be used as the starting
   *          point for the batch of changes.
   */
  public long getChangeTime()
  {
    return changeTime;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ASN1Element encode()
  {
    return new ASN1OctetString(TYPE, changeTimeString);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("ChangeTimeStartingPoint(time='");
    buffer.append(changeTimeString);
    buffer.append("')");
  }
}
