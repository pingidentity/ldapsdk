/*
 * Copyright 2008-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.monitors;



import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;



/**
 * This class defines a monitor entry that provides information about the types
 * of LDAP operations processed through an LDAP connection handler.
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
 * <BR>
 * Information available through this monitor entry includes:
 * <UL>
 *   <LI>The total number of requests for each type of operation received by the
 *       connection handler.</LI>
 *   <LI>The total number of responses of each type of operation returned by the
 *       connection handler.</LI>
 *   <LI>The total number of search result entries returned by the connection
 *       handler.</LI>
 *   <LI>The total number of search result references returned by the connection
 *       handler.</LI>
 *   <LI>The total number of LDAP messages read from clients.</LI>
 *   <LI>The total number of LDAP messages written to clients.</LI>
 *   <LI>The total number of request bytes read from clients.</LI>
 *   <LI>The total number of response bytes written to clients.</LI>
 *   <LI>The number of connections accepted by the connection handler.</LI>
 *   <LI>The number of connections closed by the connection handler.</LI>
 *   <LI>The number of operations initiated by the connection handler.</LI>
 *   <LI>The number of operations completed by the connection handler.</LI>
 *   <LI>The number of operations abandoned by the connection handler.</LI>
 * </UL>
 * The LDAP statistics monitor entries provided by the server can be retrieved
 * using the {@link MonitorManager#getLDAPStatisticsMonitorEntries} method.
 * These entries provide specific methods for accessing information about the
 * LDAP connection handler (e.g., the
 * {@link LDAPStatisticsMonitorEntry#getAbandonRequests} method can be used to
 * retrieve the number of abandon requests received).  Alternately, this
 * information may be accessed using the generic API.  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class LDAPStatisticsMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in LDAP statistics monitor entries.
   */
  static final String LDAP_STATISTICS_MONITOR_OC =
       "ds-ldap-statistics-monitor-entry";



  /**
   * The name of the attribute that contains the number of abandon requests.
   */
  private static final String ATTR_ABANDON_REQUESTS = "abandonRequests";



  /**
   * The name of the attribute that contains the number of add requests.
   */
  private static final String ATTR_ADD_REQUESTS = "addRequests";



  /**
   * The name of the attribute that contains the number of add responses.
   */
  private static final String ATTR_ADD_RESPONSES = "addResponses";



  /**
   * The name of the attribute that contains the number of bind requests.
   */
  private static final String ATTR_BIND_REQUESTS = "bindRequests";



  /**
   * The name of the attribute that contains the number of bind responses.
   */
  private static final String ATTR_BIND_RESPONSES = "bindResponses";



  /**
   * The name of the attribute that contains the number of bytes read.
   */
  private static final String ATTR_BYTES_READ = "bytesRead";



  /**
   * The name of the attribute that contains the number of bytes written.
   */
  private static final String ATTR_BYTES_WRITTEN = "bytesWritten";



  /**
   * The name of the attribute that contains the number of compare requests.
   */
  private static final String ATTR_COMPARE_REQUESTS = "compareRequests";



  /**
   * The name of the attribute that contains the number of compare responses.
   */
  private static final String ATTR_COMPARE_RESPONSES = "compareResponses";



  /**
   * The name of the attribute that contains the number of connections
   * closed.
   */
  private static final String ATTR_CONNECTIONS_CLOSED = "connectionsClosed";



  /**
   * The name of the attribute that contains the number of connections
   * established.
   */
  private static final String ATTR_CONNECTIONS_ESTABLISHED =
       "connectionsEstablished";



  /**
   * The name of the attribute that contains the number of delete requests.
   */
  private static final String ATTR_DELETE_REQUESTS = "deleteRequests";



  /**
   * The name of the attribute that contains the number of delete responses.
   */
  private static final String ATTR_DELETE_RESPONSES = "deleteResponses";



  /**
   * The name of the attribute that contains the number of extended requests.
   */
  private static final String ATTR_EXTENDED_REQUESTS = "extendedRequests";



  /**
   * The name of the attribute that contains the number of extended responses.
   */
  private static final String ATTR_EXTENDED_RESPONSES = "extendedResponses";



  /**
   * The name of the attribute that contains the number of LDAP messages read.
   */
  private static final String ATTR_LDAP_MESSAGES_READ = "ldapMessagesRead";



  /**
   * The name of the attribute that contains the number of LDAP messages
   * written.
   */
  private static final String ATTR_LDAP_MESSAGES_WRITTEN =
       "ldapMessagesWritten";



  /**
   * The name of the attribute that contains the number of modify requests.
   */
  private static final String ATTR_MODIFY_REQUESTS = "modifyRequests";



  /**
   * The name of the attribute that contains the number of modify responses.
   */
  private static final String ATTR_MODIFY_RESPONSES = "modifyResponses";



  /**
   * The name of the attribute that contains the number of modify DN requests.
   */
  private static final String ATTR_MODIFY_DN_REQUESTS = "modifyDNRequests";



  /**
   * The name of the attribute that contains the number of modify DN responses.
   */
  private static final String ATTR_MODIFY_DN_RESPONSES = "modifyDNResponses";



  /**
   * The name of the attribute that contains the number of operations abandoned.
   */
  private static final String ATTR_OPS_ABANDONED = "operationsAbandoned";



  /**
   * The name of the attribute that contains the number of operations completed.
   */
  private static final String ATTR_OPS_COMPLETED = "operationsCompleted";



  /**
   * The name of the attribute that contains the number of operations initiated.
   */
  private static final String ATTR_OPS_INITIATED = "operationsInitiated";



  /**
   * The name of the attribute that contains the number of search requests.
   */
  private static final String ATTR_SEARCH_REQUESTS = "searchRequests";



  /**
   * The name of the attribute that contains the number of search result done
   * responses.
   */
  private static final String ATTR_SEARCH_RESULT_DONE_RESPONSES =
       "searchResultsDone";



  /**
   * The name of the attribute that contains the number of search result entry
   * responses.
   */
  private static final String ATTR_SEARCH_RESULT_ENTRY_RESPONSES =
       "searchResultEntries";



  /**
   * The name of the attribute that contains the number of search result
   * reference responses.
   */
  private static final String ATTR_SEARCH_RESULT_REFERENCE_RESPONSES =
       "searchResultReferences";



  /**
   * The name of the attribute that contains the number of unbind requests.
   */
  private static final String ATTR_UNBIND_REQUESTS = "unbindRequests";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4869341619766489249L;



  // The number of abandon requests.
  private final Long abandonRequests;

  // The number of add requests.
  private final Long addRequests;

  // The number of add responses.
  private final Long addResponses;

  // The number of bind requests.
  private final Long bindRequests;

  // The number of bind responses.
  private final Long bindResponses;

  // The number of bytes read.
  private final Long bytesRead;

  // The number of bytes written.
  private final Long bytesWritten;

  // The number of compare requests.
  private final Long compareRequests;

  // The number of compare responses.
  private final Long compareResponses;

  // The number of connections that have been closed.
  private final Long connectionsClosed;

  // The number of connections that have been established.
  private final Long connectionsEstablished;

  // The number of delete requests.
  private final Long deleteRequests;

  // The number of delete responses.
  private final Long deleteResponses;

  // The number of extended requests.
  private final Long extendedRequests;

  // The number of extended responses.
  private final Long extendedResponses;

  // The number of LDAP messages read.
  private final Long ldapMessagesRead;

  // The number of LDAP messages written.
  private final Long ldapMessagesWritten;

  // The number of modify requests.
  private final Long modifyRequests;

  // The number of modify responses.
  private final Long modifyResponses;

  // The number of modify DN requests.
  private final Long modifyDNRequests;

  // The number of modify DN responses.
  private final Long modifyDNResponses;

  // The number of operations abandoned.
  private final Long opsAbandoned;

  // The number of operations completed.
  private final Long opsCompleted;

  // The number of operations initiated.
  private final Long opsInitiated;

  // The number of search requests.
  private final Long searchRequests;

  // The number of search result done responses.
  private final Long searchDoneResponses;

  // The number of search result entry responses.
  private final Long searchEntryResponses;

  // The number of search result reference responses.
  private final Long searchReferenceResponses;

  // The number of unbind requests.
  private final Long unbindRequests;



  /**
   * Creates a new LDAP statistics monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as an LDAP statistics monitor entry.
   *                It must not be {@code null}.
   */
  public LDAPStatisticsMonitorEntry(final Entry entry)
  {
    super(entry);

    abandonRequests          = getLong(ATTR_ABANDON_REQUESTS);
    addRequests              = getLong(ATTR_ADD_REQUESTS);
    addResponses             = getLong(ATTR_ADD_RESPONSES);
    bindRequests             = getLong(ATTR_BIND_REQUESTS);
    bindResponses            = getLong(ATTR_BIND_RESPONSES);
    bytesRead                = getLong(ATTR_BYTES_READ);
    bytesWritten             = getLong(ATTR_BYTES_WRITTEN);
    compareRequests          = getLong(ATTR_COMPARE_REQUESTS);
    compareResponses         = getLong(ATTR_COMPARE_RESPONSES);
    connectionsClosed        = getLong(ATTR_CONNECTIONS_CLOSED);
    connectionsEstablished   = getLong(ATTR_CONNECTIONS_ESTABLISHED);
    deleteRequests           = getLong(ATTR_DELETE_REQUESTS);
    deleteResponses          = getLong(ATTR_DELETE_RESPONSES);
    extendedRequests         = getLong(ATTR_EXTENDED_REQUESTS);
    extendedResponses        = getLong(ATTR_EXTENDED_RESPONSES);
    ldapMessagesRead         = getLong(ATTR_LDAP_MESSAGES_READ);
    ldapMessagesWritten      = getLong(ATTR_LDAP_MESSAGES_WRITTEN);
    modifyRequests           = getLong(ATTR_MODIFY_REQUESTS);
    modifyResponses          = getLong(ATTR_MODIFY_RESPONSES);
    modifyDNRequests         = getLong(ATTR_MODIFY_DN_REQUESTS);
    modifyDNResponses        = getLong(ATTR_MODIFY_DN_RESPONSES);
    opsAbandoned             = getLong(ATTR_OPS_ABANDONED);
    opsCompleted             = getLong(ATTR_OPS_COMPLETED);
    opsInitiated             = getLong(ATTR_OPS_INITIATED);
    searchRequests           = getLong(ATTR_SEARCH_REQUESTS);
    searchDoneResponses      = getLong(ATTR_SEARCH_RESULT_DONE_RESPONSES);
    searchEntryResponses     = getLong(ATTR_SEARCH_RESULT_ENTRY_RESPONSES);
    searchReferenceResponses = getLong(ATTR_SEARCH_RESULT_REFERENCE_RESPONSES);
    unbindRequests           = getLong(ATTR_UNBIND_REQUESTS);
  }



  /**
   * Retrieves the number of connections established since the associated
   * connection handler was started.
   *
   * @return  The number of connections established since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getConnectionsEstablished()
  {
    return connectionsEstablished;
  }



  /**
   * Retrieves the number of connections closed since the associated connection
   * handler was started.
   *
   * @return  The number of connections closed since the associated connection
   *          handler was started, or {@code null} if it was not included in the
   *          monitor entry.
   */
  public Long getConnectionsClosed()
  {
    return connectionsClosed;
  }



  /**
   * Retrieves the number of operations initiated since the associated
   * connection handler was started.
   *
   * @return  The number of operations initiated since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getOperationsInitiated()
  {
    return opsInitiated;
  }



  /**
   * Retrieves the number of operations completed since the associated
   * connection handler was started.
   *
   * @return  The number of operations completed since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getOperationsCompleted()
  {
    return opsCompleted;
  }



  /**
   * Retrieves the number of operations abandoned since the associated
   * connection handler was started.
   *
   * @return  The number of operations abandoned since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getOperationsAbandoned()
  {
    return opsAbandoned;
  }



  /**
   * Retrieves the number of bytes read from clients since the associated
   * connection handler was started.
   *
   * @return  The number of bytes read from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getBytesRead()
  {
    return bytesRead;
  }



  /**
   * Retrieves the number of bytes written to clients since the associated
   * connection handler was started.
   *
   * @return  The number of bytes written to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getBytesWritten()
  {
    return bytesWritten;
  }



  /**
   * Retrieves the number of LDAP messages read from clients since the
   * associated connection handler was started.
   *
   * @return  The number of LDAP messages read from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getLDAPMessagesRead()
  {
    return ldapMessagesRead;
  }



  /**
   * Retrieves the number of LDAP messages written to clients since the
   * associated connection handler was started.
   *
   * @return  The number of LDAP messages written to clients since the
   *          associated connection handler was started, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public Long getLDAPMessagesWritten()
  {
    return ldapMessagesWritten;
  }



  /**
   * Retrieves the number of abandon requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of abandon requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getAbandonRequests()
  {
    return abandonRequests;
  }



  /**
   * Retrieves the number of add requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of add requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getAddRequests()
  {
    return addRequests;
  }



  /**
   * Retrieves the number of add responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of add responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getAddResponses()
  {
    return addResponses;
  }



  /**
   * Retrieves the number of bind requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of bind requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getBindRequests()
  {
    return bindRequests;
  }



  /**
   * Retrieves the number of bind responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of bind responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getBindResponses()
  {
    return bindResponses;
  }



  /**
   * Retrieves the number of compare requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of compare requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getCompareRequests()
  {
    return compareRequests;
  }



  /**
   * Retrieves the number of compare responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of compare responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getCompareResponses()
  {
    return compareResponses;
  }



  /**
   * Retrieves the number of delete requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of delete requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getDeleteRequests()
  {
    return deleteRequests;
  }



  /**
   * Retrieves the number of delete responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of delete responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getDeleteResponses()
  {
    return deleteResponses;
  }



  /**
   * Retrieves the number of extended requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of extended requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getExtendedRequests()
  {
    return extendedRequests;
  }



  /**
   * Retrieves the number of extended responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of extended responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getExtendedResponses()
  {
    return extendedResponses;
  }



  /**
   * Retrieves the number of modify requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of modify requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getModifyRequests()
  {
    return modifyRequests;
  }



  /**
   * Retrieves the number of modify responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of modify responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getModifyResponses()
  {
    return modifyResponses;
  }



  /**
   * Retrieves the number of modify DN requests from clients since the
   * associated connection handler was started.
   *
   * @return  The number of modify DN requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getModifyDNRequests()
  {
    return modifyDNRequests;
  }



  /**
   * Retrieves the number of modify DN responses to clients since the associated
   * connection handler was started.
   *
   * @return  The number of modify DN responses to clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getModifyDNResponses()
  {
    return modifyDNResponses;
  }



  /**
   * Retrieves the number of search requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of search requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getSearchRequests()
  {
    return searchRequests;
  }



  /**
   * Retrieves the number of search result entries sent to clients since the
   * associated connection handler was started.
   *
   * @return  The number of search result entries sent to clients since the
   *          associated connection handler was started, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public Long getSearchResultEntries()
  {
    return searchEntryResponses;
  }



  /**
   * Retrieves the number of search result references sent to clients since the
   * associated connection handler was started.
   *
   * @return  The number of search result references sent to clients since the
   *          associated connection handler was started, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public Long getSearchResultReferences()
  {
    return searchReferenceResponses;
  }



  /**
   * Retrieves the number of search result done responses to clients since the
   * associated connection handler was started.
   *
   * @return  The number of search result done responses to clients since the
   *          associated connection handler was started, or {@code null} if it
   *          was not included in the monitor entry.
   */
  public Long getSearchDoneResponses()
  {
    return searchDoneResponses;
  }



  /**
   * Retrieves the number of unbind requests from clients since the associated
   * connection handler was started.
   *
   * @return  The number of unbind requests from clients since the associated
   *          connection handler was started, or {@code null} if it was not
   *          included in the monitor entry.
   */
  public Long getUnbindRequests()
  {
    return unbindRequests;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_LDAP_STATS_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_LDAP_STATS_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>();

    if (connectionsEstablished != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONNECTIONS_ESTABLISHED,
           INFO_LDAP_STATS_DISPNAME_CONNECTIONS_ESTABLISHED.get(),
           INFO_LDAP_STATS_DESC_CONNECTIONS_ESTABLISHED.get(),
           connectionsEstablished);
    }

    if (connectionsClosed != null)
    {
      addMonitorAttribute(attrs,
           ATTR_CONNECTIONS_CLOSED,
           INFO_LDAP_STATS_DISPNAME_CONNECTIONS_CLOSED.get(),
           INFO_LDAP_STATS_DESC_CONNECTIONS_CLOSED.get(),
           connectionsClosed);
    }

    if (bytesRead != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BYTES_READ,
           INFO_LDAP_STATS_DISPNAME_BYTES_READ.get(),
           INFO_LDAP_STATS_DESC_BYTES_READ.get(),
           bytesRead);
    }

    if (bytesWritten != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BYTES_WRITTEN,
           INFO_LDAP_STATS_DISPNAME_BYTES_WRITTEN.get(),
           INFO_LDAP_STATS_DESC_BYTES_WRITTEN.get(),
           bytesWritten);
    }

    if (ldapMessagesRead != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LDAP_MESSAGES_READ,
           INFO_LDAP_STATS_DISPNAME_LDAP_MESSAGES_READ.get(),
           INFO_LDAP_STATS_DESC_LDAP_MESSAGES_READ.get(),
           ldapMessagesRead);
    }

    if (ldapMessagesWritten != null)
    {
      addMonitorAttribute(attrs,
           ATTR_LDAP_MESSAGES_WRITTEN,
           INFO_LDAP_STATS_DISPNAME_LDAP_MESSAGES_WRITTEN.get(),
           INFO_LDAP_STATS_DESC_LDAP_MESSAGES_WRITTEN.get(),
           ldapMessagesWritten);
    }

    if (opsInitiated != null)
    {
      addMonitorAttribute(attrs,
           ATTR_OPS_INITIATED,
           INFO_LDAP_STATS_DISPNAME_OPS_INITIATED.get(),
           INFO_LDAP_STATS_DESC_OPS_INITIATED.get(),
           opsInitiated);
    }

    if (opsCompleted != null)
    {
      addMonitorAttribute(attrs,
           ATTR_OPS_COMPLETED,
           INFO_LDAP_STATS_DISPNAME_OPS_COMPLETED.get(),
           INFO_LDAP_STATS_DESC_OPS_COMPLETED.get(),
           opsCompleted);
    }

    if (opsAbandoned != null)
    {
      addMonitorAttribute(attrs,
           ATTR_OPS_ABANDONED,
           INFO_LDAP_STATS_DISPNAME_OPS_ABANDONED.get(),
           INFO_LDAP_STATS_DESC_OPS_ABANDONED.get(),
           opsAbandoned);
    }

    if (abandonRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ABANDON_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_ABANDON_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_ABANDON_REQUESTS.get(),
           abandonRequests);
    }

    if (addRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_ADD_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_ADD_REQUESTS.get(),
           addRequests);
    }

    if (addResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_ADD_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_ADD_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_ADD_RESPONSES.get(),
           addResponses);
    }

    if (bindRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_BIND_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_BIND_REQUESTS.get(),
           bindRequests);
    }

    if (bindResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_BIND_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_BIND_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_BIND_RESPONSES.get(),
           bindResponses);
    }

    if (compareRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_COMPARE_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_COMPARE_REQUESTS.get(),
           compareRequests);
    }

    if (compareResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_COMPARE_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_COMPARE_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_COMPARE_RESPONSES.get(),
           compareResponses);
    }

    if (deleteRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_DELETE_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_DELETE_REQUESTS.get(),
           deleteRequests);
    }

    if (deleteResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_DELETE_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_DELETE_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_DELETE_RESPONSES.get(),
           deleteResponses);
    }

    if (extendedRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EXTENDED_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_EXTENDED_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_EXTENDED_REQUESTS.get(),
           extendedRequests);
    }

    if (extendedResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_EXTENDED_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_EXTENDED_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_EXTENDED_RESPONSES.get(),
           extendedResponses);
    }

    if (modifyRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_MODIFY_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_MODIFY_REQUESTS.get(),
           modifyRequests);
    }

    if (modifyResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_MODIFY_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_MODIFY_RESPONSES.get(),
           modifyResponses);
    }

    if (modifyDNRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_MODIFY_DN_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_MODIFY_DN_REQUESTS.get(),
           modifyDNRequests);
    }

    if (modifyDNResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_MODIFY_DN_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_MODIFY_DN_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_MODIFY_DN_RESPONSES.get(),
           modifyDNResponses);
    }

    if (searchRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_SEARCH_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_SEARCH_REQUESTS.get(),
           searchRequests);
    }

    if (searchEntryResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_RESULT_ENTRY_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_SEARCH_ENTRY_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_SEARCH_ENTRY_RESPONSES.get(),
           searchEntryResponses);
    }

    if (searchReferenceResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_RESULT_REFERENCE_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_SEARCH_REFERENCE_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_SEARCH_REFERENCE_RESPONSES.get(),
           searchReferenceResponses);
    }

    if (searchDoneResponses != null)
    {
      addMonitorAttribute(attrs,
           ATTR_SEARCH_RESULT_DONE_RESPONSES,
           INFO_LDAP_STATS_DISPNAME_SEARCH_DONE_RESPONSES.get(),
           INFO_LDAP_STATS_DESC_SEARCH_DONE_RESPONSES.get(),
           searchDoneResponses);
    }

    if (unbindRequests != null)
    {
      addMonitorAttribute(attrs,
           ATTR_UNBIND_REQUESTS,
           INFO_LDAP_STATS_DISPNAME_UNBIND_REQUESTS.get(),
           INFO_LDAP_STATS_DESC_UNBIND_REQUESTS.get(),
           unbindRequests);
    }

    return Collections.unmodifiableMap(attrs);
  }
}
