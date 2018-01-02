/*
 * Copyright 2014-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2015-2018 Ping Identity Corporation
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
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class represents a data structure with information about a notification
 * subscription defined in a Ping Identity, UnboundID, or Alcatel-Lucent 8661
 * server instance.
 * <BR>
 * <BLOCKQUOTE>
 *   <B>NOTE:</B>  This class, and other classes within the
 *   {@code com.unboundid.ldap.sdk.unboundidds} package structure, are only
 *   supported for use against Ping Identity, UnboundID, and Alcatel-Lucent 8661
 *   server products.  These classes provide support for proprietary
 *   functionality or for external specifications that are not considered stable
 *   or mature enough to be guaranteed to work in an interoperable way with
 *   other types of LDAP servers.
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
  private final List<ASN1OctetString> details;

  // The unique ID for this notification subscription.
  private final String id;



  /**
   * Creates a new notification subscription details object with the provided
   * information.
   *
   * @param  id       The unique ID for this notification subscription.  It
   *                  must not be {@code null}.
   * @param  details  The encoded details for this notification subscription.
   *                  It must not be {@code null} or empty.
   */
  public NotificationSubscriptionDetails(final String id,
              final Collection<ASN1OctetString> details)
  {
    Validator.ensureNotNull(id);
    Validator.ensureNotNull(details);
    Validator.ensureFalse(details.isEmpty());

    this.id = id;
    this.details =
         Collections.unmodifiableList(new ArrayList<ASN1OctetString>(details));
  }



  /**
   * Retrieves the unique ID for this subscription details object.
   *
   * @return The unique ID for this subscription details object.
   */
  public String getID()
  {
    return id;
  }



  /**
   * Retrieves the encoded details for this subscription details object.
   *
   * @return  The encoded details for this subscription details object.
   */
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
  public void toString(final StringBuilder buffer)
  {
    buffer.append("NotificationSubscription(id='");
    buffer.append(id);
    buffer.append("')");
  }
}
