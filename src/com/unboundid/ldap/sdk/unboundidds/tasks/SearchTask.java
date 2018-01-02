/*
 * Copyright 2009-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tasks;



import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.Attribute;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tasks.TaskMessages.*;
import static com.unboundid.util.Debug.*;
import static com.unboundid.util.StaticUtils.*;
import static com.unboundid.util.Validator.*;



/**
 * This class defines a Directory Server task that can be used to perform an
 * internal search within the server and write the contents to an LDIF file.
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
 * The properties that are available for use with this type of task include:
 * <UL>
 *   <LI>The base DN to use for the search.  This is required.</LI>
 *   <LI>The scope to use for the search.  This is required.</LI>
 *   <LI>The filter to use for the search.  This is required.</LI>
 *   <LI>The attributes to return.  This is optional and multivalued.</LI>
 *   <LI>The authorization DN to use for the search.  This is optional.</LI>
 *   <LI>The path to the output file to use.  This is required.</LI>
 * </UL>
 */
@NotMutable()
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class SearchTask
       extends Task
{
  /**
   * The fully-qualified name of the Java class that is used for the search
   * task.
   */
  static final String SEARCH_TASK_CLASS =
       "com.unboundid.directory.server.tasks.SearchTask";



  /**
   * The name of the attribute used to specify the search base DN.
   */
  private static final String ATTR_BASE_DN = "ds-task-search-base-dn";



  /**
   * The name of the attribute used to specify the search scope.
   */
  private static final String ATTR_SCOPE = "ds-task-search-scope";



  /**
   * The name of the attribute used to specify the search filter.
   */
  private static final String ATTR_FILTER = "ds-task-search-filter";



  /**
   * The name of the attribute used to specify the attribute(s) to return.
   */
  private static final String ATTR_RETURN_ATTR =
       "ds-task-search-return-attribute";



  /**
   * The name of the attribute used to specify the authorization DN.
   */
  private static final String ATTR_AUTHZ_DN = "ds-task-search-authz-dn";



  /**
   * The name of the attribute used to specify the output file.
   */
  private static final String ATTR_OUTPUT_FILE = "ds-task-search-output-file";



  /**
   * The name of the object class used in search task entries.
   */
  private static final String OC_SEARCH_TASK = "ds-task-search";



  /**
   * The task property that will be used for the base DN.
   */
  private static final TaskProperty PROPERTY_BASE_DN =
       new TaskProperty(ATTR_BASE_DN,
            INFO_SEARCH_TASK_DISPLAY_NAME_BASE_DN.get(),
            INFO_SEARCH_TASK_DESCRIPTION_BASE_DN.get(), String.class, true,
            false, false);



  /**
   * The allowed values for the scope property.
   */
  private static final Object[] ALLOWED_SCOPE_VALUES =
  {
    "base", "baseobject", "0",
    "one", "onelevel", "singlelevel", "1",
    "sub", "subtree", "wholesubtree", "2",
    "subord", "subordinate", "subordinatesubtree", "3"
  };



  /**
   * The task property that will be used for the scope.
   */
  private static final TaskProperty PROPERTY_SCOPE =
       new TaskProperty(ATTR_SCOPE,
            INFO_SEARCH_TASK_DISPLAY_NAME_SCOPE.get(),
            INFO_SEARCH_TASK_DESCRIPTION_SCOPE.get(), String.class, true,
            false, false, ALLOWED_SCOPE_VALUES);



  /**
   * The task property that will be used for the filter.
   */
  private static final TaskProperty PROPERTY_FILTER =
       new TaskProperty(ATTR_FILTER,
            INFO_SEARCH_TASK_DISPLAY_NAME_FILTER.get(),
            INFO_SEARCH_TASK_DESCRIPTION_FILTER.get(), String.class, true,
            false, false);



  /**
   * The task property that will be used for the requested attributes.
   */
  private static final TaskProperty PROPERTY_REQUESTED_ATTR =
       new TaskProperty(ATTR_RETURN_ATTR,
            INFO_SEARCH_TASK_DISPLAY_NAME_RETURN_ATTR.get(),
            INFO_SEARCH_TASK_DESCRIPTION_RETURN_ATTR.get(), String.class, false,
            true, false);



  /**
   * The task property that will be used for the authorization DN.
   */
  private static final TaskProperty PROPERTY_AUTHZ_DN =
       new TaskProperty(ATTR_AUTHZ_DN,
            INFO_SEARCH_TASK_DISPLAY_NAME_AUTHZ_DN.get(),
            INFO_SEARCH_TASK_DESCRIPTION_AUTHZ_DN.get(), String.class, false,
            false, true);



  /**
   * The task property that will be used for the output file.
   */
  private static final TaskProperty PROPERTY_OUTPUT_FILE =
       new TaskProperty(ATTR_OUTPUT_FILE,
            INFO_SEARCH_TASK_DISPLAY_NAME_OUTPUT_FILE.get(),
            INFO_SEARCH_TASK_DESCRIPTION_NAME_OUTPUT_FILE.get(), String.class,
            true, false, false);



  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -1742374271508548328L;



  // The search filter.
  private final Filter filter;

  // The list of attributes to return.
  private final List<String> attributes;

  // The search scope.
  private final SearchScope scope;

  // The authorization DN.
  private final String authzDN;

  // The search base DN.
  private final String baseDN;

  // The output file path.
  private final String outputFile;



  /**
   * Creates a new uninitialized search task instance which should only be used
   * for obtaining general information about this task, including the task name,
   * description, and supported properties.  Attempts to use a task created with
   * this constructor for any other reason will likely fail.
   */
  public SearchTask()
  {
    filter     = null;
    attributes = null;
    scope      = null;
    authzDN    = null;
    baseDN     = null;
    outputFile = null;
  }



  /**
   * Creates a new search task with the provided information.
   *
   * @param  taskID      The task ID to use for this task.  If it is
   *                     {@code null} then a UUID will be generated for use as
   *                     the task ID.
   * @param  baseDN      The base DN to use for the search.  It must not be
   *                     {@code null}.
   * @param  scope       The scope to use for the search.  It must not be
   *                     {@code null}.
   * @param  filter      The filter to use for the search.  It must not be
   *                     {@code null}.
   * @param  attributes  The list of attributes to include in matching entries.
   *                     If it is {@code null} or empty, then all user
   *                     attributes will be selected.
   * @param  outputFile  The path to the file (on the server filesystem) to
   *                     which the results should be written.  It must not be
   *                     {@code null}.
   */
  public SearchTask(final String taskID, final String baseDN,
                    final SearchScope scope, final Filter filter,
                    final List<String> attributes, final String outputFile)
  {
    this(taskID, baseDN, scope, filter, attributes, outputFile, null, null,
         null, null, null, null);
  }



  /**
   * Creates a new search task with the provided information.
   *
   * @param  taskID      The task ID to use for this task.  If it is
   *                     {@code null} then a UUID will be generated for use as
   *                     the task ID.
   * @param  baseDN      The base DN to use for the search.  It must not be
   *                     {@code null}.
   * @param  scope       The scope to use for the search.  It must not be
   *                     {@code null}.
   * @param  filter      The filter to use for the search.  It must not be
   *                     {@code null}.
   * @param  attributes  The list of attributes to include in matching entries.
   *                     If it is {@code null} or empty, then all user
   *                     attributes will be selected.
   * @param  outputFile  The path to the file (on the server filesystem) to
   *                     which the results should be written.  It must not be
   *                     {@code null}.
   * @param  authzDN     The DN of the user as whom the search should be
   *                     processed.  If this is {@code null}, then it will be
   *                     processed as an internal root user.
   */
  public SearchTask(final String taskID, final String baseDN,
                    final SearchScope scope, final Filter filter,
                    final List<String> attributes, final String outputFile,
                    final String authzDN)
  {
    this(taskID, baseDN, scope, filter, attributes, outputFile, authzDN, null,
         null, null, null, null);
  }



  /**
   * Creates a new search task with the provided information.
   *
   * @param  taskID                  The task ID to use for this task.  If it is
   *                                 {@code null} then a UUID will be generated
   *                                 for use as the task ID.
   * @param  baseDN                  The base DN to use for the search.  It must
   *                                 not be {@code null}.
   * @param  scope                   The scope to use for the search.  It must
   *                                 not be {@code null}.
   * @param  filter                  The filter to use for the search.  It must
   *                                 not be {@code null}.
   * @param  attributes              The list of attributes to include in
   *                                 matching entries.  If it is {@code null} or
   *                                 empty, then all user attributes will be
   *                                 selected.
   * @param  outputFile              The path to the file (on the server
   *                                 filesystem) to which the results should be
   *                                 written.  It must not be {@code null}.
   * @param  authzDN                 The DN of the user as whom the search
   *                                 should be processed.  If this is
   *                                 {@code null}, then it will be processed as
   *                                 an internal root user.
   * @param  scheduledStartTime      The time that this task should start
   *                                 running.
   * @param  dependencyIDs           The list of task IDs that will be required
   *                                 to complete before this task will be
   *                                 eligible to start.
   * @param  failedDependencyAction  Indicates what action should be taken if
   *                                 any of the dependencies for this task do
   *                                 not complete successfully.
   * @param  notifyOnCompletion      The list of e-mail addresses of individuals
   *                                 that should be notified when this task
   *                                 completes.
   * @param  notifyOnError           The list of e-mail addresses of individuals
   *                                 that should be notified if this task does
   *                                 not complete successfully.
   */
  public SearchTask(final String taskID, final String baseDN,
                    final SearchScope scope, final Filter filter,
                    final List<String> attributes, final String outputFile,
                    final String authzDN,  final Date scheduledStartTime,
                    final List<String> dependencyIDs,
                    final FailedDependencyAction failedDependencyAction,
                    final List<String> notifyOnCompletion,
                    final List<String> notifyOnError)
  {
    super(taskID, SEARCH_TASK_CLASS, scheduledStartTime, dependencyIDs,
         failedDependencyAction, notifyOnCompletion, notifyOnError);

    ensureNotNull(baseDN, scope, filter, outputFile);

    this.baseDN     = baseDN;
    this.scope      = scope;
    this.filter     = filter;
    this.outputFile = outputFile;
    this.authzDN    = authzDN;

    if (attributes == null)
    {
      this.attributes = Collections.emptyList();
    }
    else
    {
      this.attributes = Collections.unmodifiableList(attributes);
    }
  }



  /**
   * Creates a new search task from the provided entry.
   *
   * @param  entry  The entry to use to create this search task.
   *
   * @throws  TaskException  If the provided entry cannot be parsed as a search
   *                         task entry.
   */
  public SearchTask(final Entry entry)
         throws TaskException
  {
    super(entry);


    // Get the base DN.  It must be present.
    baseDN = entry.getAttributeValue(ATTR_BASE_DN);
    if (baseDN == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_ENTRY_NO_BASE_DN.get(
           entry.getDN()));
    }


    // Get the scope.  It must be present.
    final String scopeStr = toLowerCase(entry.getAttributeValue(ATTR_SCOPE));
    if (scopeStr == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_ENTRY_NO_SCOPE.get(
           entry.getDN()));
    }

    if (scopeStr.equals("base") || scopeStr.equals("baseobject") ||
        scopeStr.equals("0"))
    {
      scope = SearchScope.BASE;
    }
    else if (scopeStr.equals("one") || scopeStr.equals("onelevel") ||
             scopeStr.equals("singlelevel") || scopeStr.equals("1"))
    {
      scope = SearchScope.ONE;
    }
    else if (scopeStr.equals("sub") || scopeStr.equals("subtree") ||
             scopeStr.equals("wholesubtree") || scopeStr.equals("2"))
    {
      scope = SearchScope.SUB;
    }
    else if (scopeStr.equals("subord") || scopeStr.equals("subordinate") ||
             scopeStr.equals("subordinatesubtree") || scopeStr.equals("3"))
    {
      scope = SearchScope.SUBORDINATE_SUBTREE;
    }
    else
    {
      throw new TaskException(ERR_SEARCH_TASK_ENTRY_INVALID_SCOPE.get(
           entry.getDN(), scopeStr));
    }


    // Get the filter.  It must be present.
    final String filterStr = entry.getAttributeValue(ATTR_FILTER);
    if (filterStr == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_ENTRY_NO_FILTER.get(
           entry.getDN()));
    }
    try
    {
      filter = Filter.create(filterStr);
    }
    catch (final LDAPException le)
    {
      debugException(le);
      throw new TaskException(ERR_SEARCH_TASK_ENTRY_INVALID_FILTER.get(
           entry.getDN(), filterStr), le);
    }


    // Get the list of requested attributes.  It is optional.
    final String[] attrs = entry.getAttributeValues(ATTR_RETURN_ATTR);
    if (attrs == null)
    {
      attributes = Collections.emptyList();
    }
    else
    {
      attributes = Collections.unmodifiableList(Arrays.asList(attrs));
    }


    // Get the authorization DN.  It is optional.
    authzDN = entry.getAttributeValue(ATTR_AUTHZ_DN);


    // Get the path to the output file.  It must be present.
    outputFile = entry.getAttributeValue(ATTR_OUTPUT_FILE);
    if (outputFile == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_ENTRY_NO_OUTPUT_FILE.get(
           entry.getDN()));
    }
  }



  /**
   * Creates a new search task from the provided set of task properties.
   *
   * @param  properties  The set of task properties and their corresponding
   *                     values to use for the task.  It must not be
   *                     {@code null}.
   *
   * @throws  TaskException  If the provided set of properties cannot be used to
   *                         create a valid add schema file task.
   */
  public SearchTask(final Map<TaskProperty,List<Object>> properties)
         throws TaskException
  {
    super(SEARCH_TASK_CLASS, properties);

    Filter      tmpFilter  = null;
    SearchScope tmpScope   = null;
    String      tmpAuthzDN = null;
    String      tmpBaseDN  = null;
    String      tmpFile    = null;
    String[]    tmpAttrs   = null;

    for (final Map.Entry<TaskProperty,List<Object>> entry :
         properties.entrySet())
    {
      final TaskProperty p = entry.getKey();
      final String attrName = toLowerCase(p.getAttributeName());
      final List<Object> values = entry.getValue();

      if (attrName.equals(ATTR_BASE_DN))
      {
        tmpBaseDN = parseString(p, values, null);
      }
      else if (attrName.equals(ATTR_SCOPE))
      {
        final String scopeStr = toLowerCase(parseString(p, values, null));
        if (scopeStr != null)
        {
          if (scopeStr.equals("base") || scopeStr.equals("baseobject") ||
               scopeStr.equals("0"))
          {
            tmpScope = SearchScope.BASE;
          }
          else if (scopeStr.equals("one") || scopeStr.equals("onelevel") ||
               scopeStr.equals("singlelevel") || scopeStr.equals("1"))
          {
            tmpScope = SearchScope.ONE;
          }
          else if (scopeStr.equals("sub") || scopeStr.equals("subtree") ||
                   scopeStr.equals("wholesubtree") || scopeStr.equals("2"))
          {
            tmpScope = SearchScope.SUB;
          }
          else if (scopeStr.equals("subord") ||
                   scopeStr.equals("subordinate") ||
                   scopeStr.equals("subordinatesubtree") ||
                   scopeStr.equals("3"))
          {
            tmpScope = SearchScope.SUBORDINATE_SUBTREE;
          }
          else
          {
            throw new TaskException(ERR_SEARCH_TASK_INVALID_SCOPE_PROPERTY.get(
                 scopeStr));
          }
        }
      }
      else if (attrName.equals(ATTR_FILTER))
      {
        final String filterStr = parseString(p, values, null);
        if (filterStr != null)
        {
          try
          {
            tmpFilter = Filter.create(filterStr);
          }
          catch (final LDAPException le)
          {
            debugException(le);
            throw new TaskException(ERR_SEARCH_TASK_INVALID_FILTER_PROPERTY.get(
                 filterStr), le);
          }
        }
      }
      else if (attrName.equals(ATTR_RETURN_ATTR))
      {
        tmpAttrs = parseStrings(p, values, null);
      }
      else if (attrName.equals(ATTR_OUTPUT_FILE))
      {
        tmpFile = parseString(p, values, null);
      }
      else if (attrName.equals(ATTR_AUTHZ_DN))
      {
        tmpAuthzDN = parseString(p, values, null);
      }
    }

    baseDN = tmpBaseDN;
    if (baseDN == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_NO_BASE_PROPERTY.get());
    }

    scope = tmpScope;
    if (scope == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_NO_SCOPE_PROPERTY.get());
    }

    filter = tmpFilter;
    if (filter == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_NO_FILTER_PROPERTY.get());
    }

    outputFile = tmpFile;
    if (outputFile == null)
    {
      throw new TaskException(ERR_SEARCH_TASK_NO_OUTPUT_FILE_PROPERTY.get());
    }


    if (tmpAttrs == null)
    {
      attributes = Collections.emptyList();
    }
    else
    {
      attributes = Collections.unmodifiableList(Arrays.asList(tmpAttrs));
    }

    authzDN = tmpAuthzDN;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskName()
  {
    return INFO_TASK_NAME_SEARCH.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public String getTaskDescription()
  {
    return INFO_TASK_DESCRIPTION_SEARCH.get();
  }



  /**
   * Retrieves the base DN for the search.
   *
   * @return  The base DN for the search.
   */
  public String getBaseDN()
  {
    return baseDN;
  }



  /**
   * Retrieves the scope for the search.
   *
   * @return  The scope for the search.
   */
  public SearchScope getScope()
  {
    return scope;
  }



  /**
   * Retrieves the filter for the search.
   *
   * @return  The filter for the search.
   */
  public Filter getFilter()
  {
    return filter;
  }



  /**
   * Retrieves the list of attributes to include in matching entries.
   *
   * @return  The list of attributes to include in matching entries, or an
   *          empty list of all user attributes should be requested.
   */
  public List<String> getAttributes()
  {
    return attributes;
  }



  /**
   * Retrieves the DN of the user as whom the request should be processed.
   *
   * @return  The DN of the user as whom the request should be processed, or
   *          {@code null} if it should be processed as an internal root user.
   */
  public String getAuthzDN()
  {
    return authzDN;
  }



  /**
   * Retrieves the path to the file on the server filesystem to which the
   * results should be written.
   *
   * @return  The path to the file on the server filesystem to which the results
   *          should be written.
   */
  public String getOutputFile()
  {
    return outputFile;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<String> getAdditionalObjectClasses()
  {
    return Arrays.asList(OC_SEARCH_TASK);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  protected List<Attribute> getAdditionalAttributes()
  {
    final LinkedList<Attribute> attrs = new LinkedList<Attribute>();

    attrs.add(new Attribute(ATTR_BASE_DN, baseDN));
    attrs.add(new Attribute(ATTR_SCOPE, String.valueOf(scope.intValue())));
    attrs.add(new Attribute(ATTR_FILTER, filter.toString()));
    attrs.add(new Attribute(ATTR_OUTPUT_FILE, outputFile));

    if ((attributes != null) && (! attributes.isEmpty()))
    {
      attrs.add(new Attribute(ATTR_RETURN_ATTR, attributes));
    }

    if (authzDN != null)
    {
      attrs.add(new Attribute(ATTR_AUTHZ_DN, authzDN));
    }

    return Collections.unmodifiableList(attrs);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public List<TaskProperty> getTaskSpecificProperties()
  {
    final LinkedList<TaskProperty> props = new LinkedList<TaskProperty>();

    props.add(PROPERTY_BASE_DN);
    props.add(PROPERTY_SCOPE);
    props.add(PROPERTY_FILTER);
    props.add(PROPERTY_REQUESTED_ATTR);
    props.add(PROPERTY_AUTHZ_DN);
    props.add(PROPERTY_OUTPUT_FILE);

    return Collections.unmodifiableList(props);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public Map<TaskProperty,List<Object>> getTaskPropertyValues()
  {
    final LinkedHashMap<TaskProperty,List<Object>> props =
         new LinkedHashMap<TaskProperty,List<Object>>(6);

    props.put(PROPERTY_BASE_DN,
         Collections.<Object>unmodifiableList(Arrays.asList(baseDN)));

    props.put(PROPERTY_SCOPE, Collections.<Object>unmodifiableList(
         Arrays.asList(String.valueOf(scope.intValue()))));

    props.put(PROPERTY_FILTER, Collections.<Object>unmodifiableList(
         Arrays.asList(filter.toString())));

    if ((attributes != null) && (! attributes.isEmpty()))
    {
      final LinkedList<Object> attrObjects = new LinkedList<Object>();
      attrObjects.addAll(attributes);

      props.put(PROPERTY_REQUESTED_ATTR,
           Collections.unmodifiableList(attrObjects));
    }

    if (authzDN != null)
    {
      props.put(PROPERTY_AUTHZ_DN,
           Collections.<Object>unmodifiableList(Arrays.asList(authzDN)));
    }

    props.put(PROPERTY_OUTPUT_FILE,
         Collections.<Object>unmodifiableList(Arrays.asList(outputFile)));

    props.putAll(super.getTaskPropertyValues());
    return Collections.unmodifiableMap(props);
  }
}
