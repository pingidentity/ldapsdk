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



import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the LDAPStatisticsMonitorEntry class.
 */
public class LDAPStatisticsMonitorEntryTestCase
       extends LDAPSDKTestCase
{
  /**
   * Provides test coverage for the constructor with a valid entry with all
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorAllValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=LDAP Connection Handler 0.0.0.0 port 389 Statistics," +
              "cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-statistics-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Connection Handler 0.0.0.0 port 389 Statistics",
         "connectionsEstablished: 100",
         "connectionsClosed: 99",
         "bytesRead: 98",
         "bytesWritten: 97",
         "ldapMessagesRead: 96",
         "ldapMessagesWritten: 95",
         "operationsInitiated: 94",
         "operationsCompleted: 93",
         "operationsAbandoned: 92",
         "abandonRequests: 91",
         "addRequests: 90",
         "addResponses: 89",
         "bindRequests: 88",
         "bindResponses: 87",
         "compareRequests: 86",
         "compareResponses: 85",
         "deleteRequests: 84",
         "deleteResponses: 83",
         "extendedRequests: 82",
         "extendedResponses: 81",
         "modifyRequests: 80",
         "modifyResponses: 79",
         "modifyDNRequests: 78",
         "modifyDNResponses: 77",
         "searchRequests: 76",
         "searchResultEntries: 75",
         "searchResultReferences: 74",
         "searchResultsDone: 73",
         "unbindRequests: 72");

    LDAPStatisticsMonitorEntry me = new LDAPStatisticsMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-ldap-statistics-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 LDAPStatisticsMonitorEntry.class.getName());

    assertNotNull(me.getConnectionsEstablished());
    assertEquals(me.getConnectionsEstablished().longValue(), 100L);

    assertNotNull(me.getConnectionsClosed());
    assertEquals(me.getConnectionsClosed().longValue(), 99L);

    assertNotNull(me.getBytesRead());
    assertEquals(me.getBytesRead().longValue(), 98L);

    assertNotNull(me.getBytesWritten ());
    assertEquals(me.getBytesWritten().longValue(), 97L);

    assertNotNull(me.getLDAPMessagesRead());
    assertEquals(me.getLDAPMessagesRead().longValue(), 96L);

    assertNotNull(me.getLDAPMessagesWritten ());
    assertEquals(me.getLDAPMessagesWritten().longValue(), 95L);

    assertNotNull(me.getOperationsInitiated());
    assertEquals(me.getOperationsInitiated().longValue(), 94L);

    assertNotNull(me.getOperationsCompleted());
    assertEquals(me.getOperationsCompleted().longValue(), 93L);

    assertNotNull(me.getOperationsAbandoned());
    assertEquals(me.getOperationsAbandoned().longValue(), 92L);

    assertNotNull(me.getAbandonRequests());
    assertEquals(me.getAbandonRequests().longValue(), 91L);

    assertNotNull(me.getAddRequests());
    assertEquals(me.getAddRequests().longValue(), 90L);

    assertNotNull(me.getAddResponses());
    assertEquals(me.getAddResponses().longValue(), 89L);

    assertNotNull(me.getBindRequests());
    assertEquals(me.getBindRequests().longValue(), 88L);

    assertNotNull(me.getBindResponses());
    assertEquals(me.getBindResponses().longValue(), 87L);

    assertNotNull(me.getCompareRequests());
    assertEquals(me.getCompareRequests().longValue(), 86L);

    assertNotNull(me.getCompareResponses());
    assertEquals(me.getCompareResponses().longValue(), 85L);

    assertNotNull(me.getDeleteRequests());
    assertEquals(me.getDeleteRequests().longValue(), 84L);

    assertNotNull(me.getDeleteResponses());
    assertEquals(me.getDeleteResponses().longValue(), 83L);

    assertNotNull(me.getExtendedRequests());
    assertEquals(me.getExtendedRequests().longValue(), 82L);

    assertNotNull(me.getExtendedResponses());
    assertEquals(me.getExtendedResponses().longValue(), 81L);

    assertNotNull(me.getModifyRequests());
    assertEquals(me.getModifyRequests().longValue(), 80L);

    assertNotNull(me.getModifyResponses());
    assertEquals(me.getModifyResponses().longValue(), 79L);

    assertNotNull(me.getModifyDNRequests());
    assertEquals(me.getModifyDNRequests().longValue(), 78L);

    assertNotNull(me.getModifyDNResponses());
    assertEquals(me.getModifyDNResponses().longValue(), 77L);

    assertNotNull(me.getSearchRequests());
    assertEquals(me.getSearchRequests().longValue(), 76L);

    assertNotNull(me.getSearchResultEntries());
    assertEquals(me.getSearchResultEntries().longValue(), 75L);

    assertNotNull(me.getSearchResultReferences());
    assertEquals(me.getSearchResultReferences().longValue(), 74L);

    assertNotNull(me.getSearchDoneResponses());
    assertEquals(me.getSearchDoneResponses().longValue(), 73L);

    assertNotNull(me.getUnbindRequests());
    assertEquals(me.getUnbindRequests().longValue(), 72L);


    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("connectionsestablished"));
    assertEquals(attrs.get("connectionsestablished").getLongValue(),
                 Long.valueOf(100L));

    assertNotNull(attrs.get("connectionsclosed"));
    assertEquals(attrs.get("connectionsclosed").getLongValue(),
                 Long.valueOf(99L));

    assertNotNull(attrs.get("bytesread"));
    assertEquals(attrs.get("bytesread").getLongValue(),
                 Long.valueOf(98L));

    assertNotNull(attrs.get("byteswritten"));
    assertEquals(attrs.get("byteswritten").getLongValue(),
                 Long.valueOf(97L));

    assertNotNull(attrs.get("ldapmessagesread"));
    assertEquals(attrs.get("ldapmessagesread").getLongValue(),
                 Long.valueOf(96L));

    assertNotNull(attrs.get("ldapmessageswritten"));
    assertEquals(attrs.get("ldapmessageswritten").getLongValue(),
                 Long.valueOf(95L));

    assertNotNull(attrs.get("operationsinitiated"));
    assertEquals(attrs.get("operationsinitiated").getLongValue(),
                 Long.valueOf(94L));

    assertNotNull(attrs.get("operationscompleted"));
    assertEquals(attrs.get("operationscompleted").getLongValue(),
                 Long.valueOf(93L));

    assertNotNull(attrs.get("operationsabandoned"));
    assertEquals(attrs.get("operationsabandoned").getLongValue(),
                 Long.valueOf(92L));

    assertNotNull(attrs.get("abandonrequests"));
    assertEquals(attrs.get("abandonrequests").getLongValue(),
                 Long.valueOf(91L));

    assertNotNull(attrs.get("addrequests"));
    assertEquals(attrs.get("addrequests").getLongValue(),
                 Long.valueOf(90L));

    assertNotNull(attrs.get("addresponses"));
    assertEquals(attrs.get("addresponses").getLongValue(),
                 Long.valueOf(89L));

    assertNotNull(attrs.get("bindrequests"));
    assertEquals(attrs.get("bindrequests").getLongValue(),
                 Long.valueOf(88L));

    assertNotNull(attrs.get("bindresponses"));
    assertEquals(attrs.get("bindresponses").getLongValue(),
                 Long.valueOf(87L));

    assertNotNull(attrs.get("comparerequests"));
    assertEquals(attrs.get("comparerequests").getLongValue(),
                 Long.valueOf(86L));

    assertNotNull(attrs.get("compareresponses"));
    assertEquals(attrs.get("compareresponses").getLongValue(),
                 Long.valueOf(85L));

    assertNotNull(attrs.get("deleterequests"));
    assertEquals(attrs.get("deleterequests").getLongValue(),
                 Long.valueOf(84L));

    assertNotNull(attrs.get("deleteresponses"));
    assertEquals(attrs.get("deleteresponses").getLongValue(),
                 Long.valueOf(83L));

    assertNotNull(attrs.get("extendedrequests"));
    assertEquals(attrs.get("extendedrequests").getLongValue(),
                 Long.valueOf(82L));

    assertNotNull(attrs.get("extendedresponses"));
    assertEquals(attrs.get("extendedresponses").getLongValue(),
                 Long.valueOf(81L));

    assertNotNull(attrs.get("modifyrequests"));
    assertEquals(attrs.get("modifyrequests").getLongValue(),
                 Long.valueOf(80L));

    assertNotNull(attrs.get("modifyresponses"));
    assertEquals(attrs.get("modifyresponses").getLongValue(),
                 Long.valueOf(79L));

    assertNotNull(attrs.get("modifydnrequests"));
    assertEquals(attrs.get("modifydnrequests").getLongValue(),
                 Long.valueOf(78L));

    assertNotNull(attrs.get("modifydnresponses"));
    assertEquals(attrs.get("modifydnresponses").getLongValue(),
                 Long.valueOf(77L));

    assertNotNull(attrs.get("searchrequests"));
    assertEquals(attrs.get("searchrequests").getLongValue(),
                 Long.valueOf(76L));

    assertNotNull(attrs.get("searchresultentries"));
    assertEquals(attrs.get("searchresultentries").getLongValue(),
                 Long.valueOf(75L));

    assertNotNull(attrs.get("searchresultreferences"));
    assertEquals(attrs.get("searchresultreferences").getLongValue(),
                 Long.valueOf(74L));

    assertNotNull(attrs.get("searchresultsdone"));
    assertEquals(attrs.get("searchresultsdone").getLongValue(),
                 Long.valueOf(73L));

    assertNotNull(attrs.get("unbindrequests"));
    assertEquals(attrs.get("unbindrequests").getLongValue(),
                 Long.valueOf(72L));
  }



  /**
   * Provides test coverage for the constructor with a valid entry with no
   * values present.
   *
   * @throws  Exception  If an unexpected problem occurs.
   */
  @Test()
  public void testConstructorNoValues()
         throws Exception
  {
    Entry e = new Entry(
         "dn: cn=LDAP Connection Handler 0.0.0.0 port 389 Statistics," +
              "cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-ldap-statistics-monitor-entry",
         "objectClass: extensibleObject",
         "cn: LDAP Connection Handler 0.0.0.0 port 389 Statistics");

    LDAPStatisticsMonitorEntry me = new LDAPStatisticsMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-ldap-statistics-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 LDAPStatisticsMonitorEntry.class.getName());

    assertNull(me.getConnectionsEstablished());

    assertNull(me.getConnectionsClosed());

    assertNull(me.getBytesRead());

    assertNull(me.getBytesWritten ());

    assertNull(me.getLDAPMessagesRead());

    assertNull(me.getLDAPMessagesWritten ());

    assertNull(me.getOperationsInitiated());

    assertNull(me.getOperationsCompleted());

    assertNull(me.getOperationsAbandoned());

    assertNull(me.getAbandonRequests());

    assertNull(me.getAddRequests());

    assertNull(me.getAddResponses());

    assertNull(me.getBindRequests());

    assertNull(me.getBindResponses());

    assertNull(me.getCompareRequests());

    assertNull(me.getCompareResponses());

    assertNull(me.getDeleteRequests());

    assertNull(me.getDeleteResponses());

    assertNull(me.getExtendedRequests());

    assertNull(me.getExtendedResponses());

    assertNull(me.getModifyRequests());

    assertNull(me.getModifyResponses());

    assertNull(me.getModifyDNRequests());

    assertNull(me.getModifyDNResponses());

    assertNull(me.getSearchRequests());

    assertNull(me.getSearchResultEntries());

    assertNull(me.getSearchResultReferences());

    assertNull(me.getSearchDoneResponses());

    assertNull(me.getUnbindRequests());
  }
}
