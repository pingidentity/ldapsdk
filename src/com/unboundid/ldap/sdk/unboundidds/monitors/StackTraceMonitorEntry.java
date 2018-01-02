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



import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.monitors.MonitorMessages.*;
import static com.unboundid.util.Debug.*;



/**
 * This class defines a monitor entry that provides access to the Directory
 * Server stack trace information.  The information that is available through
 * this monitor is roughly the equivalent of what can be accessed using the
 * {@link Thread#getAllStackTraces} method.  See the {@link ThreadStackTrace}
 * class for more information about what is available in each stack trace.
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
 * The server should present at most one stack trace monitor entry.  It can be
 * retrieved using the {@link MonitorManager#getStackTraceMonitorEntry} method.
 * The {@link StackTraceMonitorEntry#getStackTraces} method can be used to
 * retrieve the stack traces for each thread.  Alternately, this information may
 * be accessed using the generic API (although in this case, only the string
 * representations of each stack trace frame are available).  See the
 * {@link MonitorManager} class documentation for an example that demonstrates
 * the use of the generic API for accessing monitor data.
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class StackTraceMonitorEntry
       extends MonitorEntry
{
  /**
   * The structural object class used in stack trace monitor entries.
   */
  static final String STACK_TRACE_MONITOR_OC =
       "ds-stack-trace-monitor-entry";



  /**
   * The name of the attribute that contains the JVM stack trace for each
   * thread.
   */
  private static final String ATTR_JVM_STACK_TRACE = "jvmThread";



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -9008690818438183908L;



  // The list of thread stack traces.
  private final List<ThreadStackTrace> stackTraces;



  /**
   * Creates a new stack trace monitor entry from the provided entry.
   *
   * @param  entry  The entry to be parsed as a stack trace monitor entry.
   *                It must not be {@code null}.
   */
  public StackTraceMonitorEntry(final Entry entry)
  {
    super(entry);

    final List<String> traceLines = getStrings(ATTR_JVM_STACK_TRACE);
    if (traceLines.isEmpty())
    {
      stackTraces = Collections.emptyList();
    }
    else
    {
      final ArrayList<ThreadStackTrace> traces =
           new ArrayList<ThreadStackTrace>(100);

      try
      {
        int currentThreadID = -1;
        String currentName  = null;
        ArrayList<StackTraceElement> currentElements =
             new ArrayList<StackTraceElement>(20);
        for (final String line : traceLines)
        {
          final int equalPos = line.indexOf('=');
          final int spacePos = line.indexOf(' ', equalPos);
          final int id = Integer.parseInt(line.substring(equalPos+1, spacePos));
          if (id != currentThreadID)
          {
            if (currentThreadID >= 0)
            {
              traces.add(new ThreadStackTrace(currentThreadID, currentName,
                                              currentElements));
            }

            currentThreadID = id;
            currentElements = new ArrayList<StackTraceElement>(20);

            final int dashesPos1 = line.indexOf("---------- ", spacePos);
            final int dashesPos2 = line.indexOf(" ----------", dashesPos1);
            currentName = line.substring((dashesPos1 + 11), dashesPos2);
          }
          else
          {
            final int bePos = line.indexOf("]=");
            final String traceLine = line.substring(bePos+2);

            final String fileName;
            int lineNumber          = -1;
            final int closeParenPos = traceLine.lastIndexOf(')');
            final int openParenPos  = traceLine.lastIndexOf('(', closeParenPos);
            final int colonPos      = traceLine.lastIndexOf(':', closeParenPos);
            if (colonPos < 0)
            {
              fileName = traceLine.substring(openParenPos+1, closeParenPos);
            }
            else
            {
              fileName = traceLine.substring(openParenPos+1, colonPos);

              final String lineNumberStr =
                   traceLine.substring(colonPos+1, closeParenPos);
              if (lineNumberStr.equalsIgnoreCase("native"))
              {
                lineNumber = -2;
              }
              else
              {
                try
                {
                  lineNumber = Integer.parseInt(lineNumberStr);
                } catch (final Exception e) {}
              }
            }

            final int periodPos     = traceLine.lastIndexOf('.', openParenPos);
            final String className  = traceLine.substring(0, periodPos);
            final String methodName =
                 traceLine.substring(periodPos+1, openParenPos);

            currentElements.add(new StackTraceElement(className, methodName,
                                                      fileName, lineNumber));
          }
        }

        if (currentThreadID >= 0)
        {
          traces.add(new ThreadStackTrace(currentThreadID, currentName,
                                          currentElements));
        }
      }
      catch (final Exception e)
      {
        debugException(e);
      }

      stackTraces = Collections.unmodifiableList(traces);
    }
  }



  /**
   * Retrieves the list of thread stack traces.
   *
   * @return  The list of thread stack traces, or an empty list if it was not
   *          included in the monitor entry or a problem occurs while decoding
   *          the stack traces.
   */
  public List<ThreadStackTrace> getStackTraces()
  {
    return stackTraces;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDisplayName()
  {
    return INFO_STACK_TRACE_MONITOR_DISPNAME.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getMonitorDescription()
  {
    return INFO_STACK_TRACE_MONITOR_DESC.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<String,MonitorAttribute> getMonitorAttributes()
  {
    final LinkedHashMap<String,MonitorAttribute> attrs =
         new LinkedHashMap<String,MonitorAttribute>();

    final Attribute traceAttr = getEntry().getAttribute(ATTR_JVM_STACK_TRACE);
    if (traceAttr != null)
    {
      addMonitorAttribute(attrs,
           ATTR_JVM_STACK_TRACE,
           INFO_STACK_TRACE_DISPNAME_TRACE.get(),
           INFO_STACK_TRACE_DESC_TRACE.get(),
           Collections.unmodifiableList(Arrays.asList(traceAttr.getValues())));
    }

    return Collections.unmodifiableMap(attrs);
  }
}
