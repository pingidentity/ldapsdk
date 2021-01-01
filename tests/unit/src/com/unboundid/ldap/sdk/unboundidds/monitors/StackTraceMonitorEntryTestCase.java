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



import java.util.Arrays;
import java.util.LinkedList;
import java.util.Map;

import org.testng.annotations.Test;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.LDAPSDKTestCase;



/**
 * This class provides test coverage for the StackTraceMonitorEntry class.
 */
public class StackTraceMonitorEntryTestCase
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
    Map<Thread,StackTraceElement[]> traces = Thread.getAllStackTraces();

    LinkedList<String> ldifLines = new LinkedList<String>();
    ldifLines.addAll(Arrays.asList(
         "dn: cn=JVM Stack Trace,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-stack-trace-monitor-entry",
         "objectClass: extensibleObject",
         "cn: JVM Stack Trace"));

    int expectedElements = 0;
    for (Thread t : traces.keySet())
    {
      ldifLines.add("jvmThread: id=" + t.getId() + " ---------- " +
                    t.getName() + " ----------");

      StackTraceElement[] elements = traces.get(t);
      expectedElements += elements.length;
      for (int i=0; i < elements.length; i++)
      {
        StringBuilder line = new StringBuilder();
        line.append("jvmThread: id=");
        line.append(t.getId());
        line.append(" frame[");
        line.append(i);
        line.append("]=");
        line.append(elements[i].getClassName());
        line.append('.');
        line.append(elements[i].getMethodName());
        line.append('(');

        if (elements[i].getFileName() == null)
        {
          line.append("Unknown Source)");
        }
        else
        {
          line.append(elements[i].getFileName());
          int lineNumber = elements[i].getLineNumber();
          if (lineNumber >= 0)
          {
            line.append(':');
            line.append(lineNumber);
            line.append(')');
          }
          else if (lineNumber == -2)
          {
            line.append(":native)");
          }
          else
          {
            line.append(')');
          }
        }

        ldifLines.add(line.toString());
      }
    }

    Entry e = new Entry(ldifLines.toArray(new String[0]));

    StackTraceMonitorEntry me = new StackTraceMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-stack-trace-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 StackTraceMonitorEntry.class.getName());

    assertNotNull(me.getStackTraces());
    assertEquals(me.getStackTraces().size(), traces.size());

    int observedElements = 0;
    for (ThreadStackTrace t : me.getStackTraces())
    {
      assertTrue(t.getThreadID() >= 0);
      assertNotNull(t.getThreadName());
      assertNotNull(t.getStackTraceElements());
      observedElements += t.getStackTraceElements().size();
    }

    assertEquals(observedElements, expectedElements);

    assertNotNull(me.getMonitorDisplayName());

    assertNotNull(me.getMonitorDescription());

    Map<String,MonitorAttribute> attrs = me.getMonitorAttributes();
    assertNotNull(me.getMonitorAttributes());
    assertFalse(me.getMonitorAttributes().isEmpty());

    assertNotNull(attrs.get("jvmthread"));
    assertTrue(attrs.get("jvmthread").hasMultipleValues());
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
         "dn: cn=JVM Stack Trace,cn=monitor",
         "objectClass: top",
         "objectClass: ds-monitor-entry",
         "objectClass: ds-stack-trace-monitor-entry",
         "objectClass: extensibleObject",
         "cn: JVM Stack Trace");


    StackTraceMonitorEntry me = new StackTraceMonitorEntry(e);
    assertNotNull(me.toString());

    assertEquals(me.getMonitorClass(), "ds-stack-trace-monitor-entry");

    assertEquals(MonitorEntry.decode(e).getClass().getName(),
                 StackTraceMonitorEntry.class.getName());

    assertNotNull(me.getStackTraces());
    assertEquals(me.getStackTraces().size(), 0);
  }
}
