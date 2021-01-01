/*
 * Copyright 2014-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2014-2021 Ping Identity Corporation
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
 * Copyright (C) 2014-2021 Ping Identity Corporation
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



import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import com.unboundid.asn1.ASN1OctetString;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class represents a data structure with information about a notification
 * subscription defined in a Ping Identity, UnboundID, or Nokia/Alcatel-Lucent
 * 8661 server instance.
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
public final class NotificationSubscriptionDetails
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7883889980556267057L;



  // The encoded details for this notification subscription.
  @NotNull private final List<ASN1OctetString> details;

  // The unique ID for this notification subscription.
  @NotNull private final String id;



  /**
   * Creates a new notification subscription details object with the provided
   * information.
   *
   * @param  id       The unique ID for this notification subscription.  It
   *                  must not be {@code null}.
   * @param  details  The encoded details for this notification subscription.
   *                  It must not be {@code null} or empty.
   */
  public NotificationSubscriptionDetails(@NotNull final String id,
              @NotNull final Collection<ASN1OctetString> details)
  {
    Validator.ensureNotNull(id);
    Validator.ensureNotNull(details);
    Validator.ensureFalse(details.isEmpty());

    this.id = id;
    this.details =
         Collections.unmodifiableList(new ArrayList<>(details));
  }



  /**
   * Retrieves the unique ID for this subscription details object.
   *
   * @return The unique ID for this subscription details object.
   */
  @NotNull()
  public String getID()
  {
    return id;
  }



  /**
   * Retrieves the encoded details for this subscription details object.
   *
   * @return  The encoded details for this subscription details object.
   */
  @NotNull()
  public List<ASN1OctetString> getDetails()
  {
    return details;
  }



  /**
   * Retrieves a string representation of this notification subscription details
   * object.
   *
   * @return  A string representation of this notification subscription details
   *          object.
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
   * Appends a string representation of this notification subscription details
   * object to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("NotificationSubscription(id='");
    buffer.append(id);
    buffer.append("')");
  }
}
