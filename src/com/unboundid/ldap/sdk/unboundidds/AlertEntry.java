/*
 * Copyright 2009-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2009-2021 Ping Identity Corporation
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
 * Copyright (C) 2009-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds;



import java.util.Date;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ReadOnlyEntry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure for representing an administrative entry
 * as exposed by the alerts backend in the Directory Server.  Alert entries
 * provide information about warnings, errors, or other significant events that
 * could impact the availability or function of the Directory Server.
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
public final class AlertEntry
       extends ReadOnlyEntry
{
  /**
   * The name of the structural object class that will be used for entries
   * containing information about administrative alerts.
   */
  @NotNull public static final String OC_ALERT = "ds-admin-alert";



  /**
   * The name of the attribute that contains the fully-qualified name of the
   * server class that generated the alert notification.
   */
  @NotNull public static final String ATTR_ALERT_GENERATOR =
       "ds-alert-generator";



  /**
   * The name of the attribute that contains the unique ID assigned to the alert
   * notification.
   */
  @NotNull public static final String ATTR_ALERT_ID = "ds-alert-id";



  /**
   * The name of the attribute that contains a message with additional
   * information about the alert notification.
   */
  @NotNull public static final String ATTR_ALERT_MESSAGE = "ds-alert-message";



  /**
   * The name of the attribute that contains the severity of the alert
   * notification.
   */
  @NotNull public static final String ATTR_ALERT_SEVERITY = "ds-alert-severity";



  /**
   * The name of the attribute that contains the time that the alert
   * notification was generated.
   */
  @NotNull public static final String ATTR_ALERT_TIME = "ds-alert-time";



  /**
   * The name of the attribute that contains the name of the alert type.
   */
  @NotNull public static final String ATTR_ALERT_TYPE = "ds-alert-type";



  /**
   * The name of the attribute that contains the OID assigned to the alert type.
   */
  @NotNull public static final String ATTR_ALERT_TYPE_OID = "ds-alert-type-oid";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -2912778595612338699L;



  // The severity for this alert entry.
  @Nullable private final AlertSeverity alertSeverity;

  // The time that the alert notification was generated.
  @Nullable private final Date alertTime;

  // The fully-qualified name of the alert generator class.
  @Nullable private final String alertGeneratorClass;

  // The unique identifier assigned to the alert notification.
  @Nullable private final String alertID;

  // The message for the alert notification.
  @Nullable private final String alertMessage;

  // The name of the alert type for the alert notification.
  @Nullable private final String alertType;

  // The OID for the alert type.
  @Nullable private final String alertTypeOID;



  /**
   * Creates a new alert entry from the provided entry.
   *
   * @param  entry  The entry from which to create this alert entry.
   */
  public AlertEntry(@NotNull final Entry entry)
  {
    super(entry);

    alertGeneratorClass = entry.getAttributeValue(ATTR_ALERT_GENERATOR);
    alertID             = entry.getAttributeValue(ATTR_ALERT_ID);
    alertMessage        = entry.getAttributeValue(ATTR_ALERT_MESSAGE);
    alertType           = entry.getAttributeValue(ATTR_ALERT_TYPE);
    alertTypeOID        = entry.getAttributeValue(ATTR_ALERT_TYPE_OID);

    alertTime = entry.getAttributeValueAsDate(ATTR_ALERT_TIME);

    final String severityStr = entry.getAttributeValue(ATTR_ALERT_SEVERITY);
    if (severityStr == null)
    {
      alertSeverity = null;
    }
    else
    {
      alertSeverity = AlertSeverity.forName(severityStr);
    }
  }



  /**
   * Retrieves the fully-qualified name of the class that generated the alert
   * notification.
   *
   * @return  The fully-qualified name of the class that generated the alert
   *          notification, or {@code null} if it was not included in the alert
   *          entry.
   */
  @Nullable()
  public String getAlertGeneratorClass()
  {
    return alertGeneratorClass;
  }



  /**
   * Retrieves the unique identifier for the alert notification.
   *
   * @return  The unique identifier for the alert notification, or {@code null}
   *          if it was not included in the alert entry.
   */
  @Nullable()
  public String getAlertID()
  {
    return alertID;
  }



  /**
   * Retrieves the message for the alert notification.
   *
   * @return  The message for the alert notification, or {@code null} if it was
   *          not included in the alert entry.
   */
  @Nullable()
  public String getAlertMessage()
  {
    return alertMessage;
  }



  /**
   * Retrieves the severity for the alert notification.
   *
   * @return  The severity for the alert notification, or {@code null} if it was
   *          not included in the alert entry, or if it included an unknown
   *          severity.
   */
  @Nullable()
  public AlertSeverity getAlertSeverity()
  {
    return alertSeverity;
  }



  /**
   * Retrieves the time that the alert notification was generated.
   *
   * @return  The time that the alert notification was generated, or
   *          {@code null} if it was not included in the alert entry or if the
   *          alert time value could not be parsed.
   */
  @Nullable()
  public Date getAlertTime()
  {
    return alertTime;
  }



  /**
   * Retrieves the name of the alert type for the alert notification.
   *
   * @return  The name of the alert type for the alert notification, or
   *          {@code null} if it was not included in the alert entry.
   */
  @Nullable()
  public String getAlertType()
  {
    return alertType;
  }



  /**
   * Retrieves the OID of the alert type for the alert notification.
   *
   * @return  The OID of the alert type for the alert notification, or
   *          {@code null} if it was not included in the alert entry.
   */
  @Nullable()
  public String getAlertTypeOID()
  {
    return alertTypeOID;
  }
}
