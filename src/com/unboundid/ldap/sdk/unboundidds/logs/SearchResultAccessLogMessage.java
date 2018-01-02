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
package com.unboundid.ldap.sdk.unboundidds.logs;



import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.StringTokenizer;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.NotMutable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a data structure that holds information about a log
 * message that may appear in the Directory Server access log about the result
 * of a search operation processed by the Directory Server.
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
public final class SearchResultAccessLogMessage
       extends SearchRequestAccessLogMessage
       implements OperationResultAccessLogMessage
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 7181644154168110011L;



  // Indicates whether the search was unindexed.
  private final Boolean isUnindexed;

  // Indicates whether the any uncached data was accessed in the course of
  // processing this operation.
  private final Boolean uncachedDataAccessed;

  // The processing time for the operation.
  private final Double processingTime;

  // The queue time for the operation.
  private final Double queueTime;

  // The list of indexes for which keys near the index entry limit were accessed
  // while processing the operation.
  private final List<String> indexesWithKeysAccessedNearEntryLimit;

  // The list of indexes for which keys over the index entry limit were accessed
  // while processing the operation.
  private final List<String> indexesWithKeysAccessedOverEntryLimit;

  // The list of privileges required for processing the operation that the
  // requester did not have.
  private final List<String> missingPrivileges;

  // The list of privileges used during the course of processing the operation
  // before an alternate authorization identity was assigned.
  private final List<String> preAuthZUsedPrivileges;

  // The list of referral URLs for the operation.
  private final List<String> referralURLs;

  // The list of response control OIDs for the operation.
  private final List<String> responseControlOIDs;

  // The list of servers accessed while processing the operation.
  private final List<String> serversAccessed;

  // The list of privileges used during the course of processing the operation.
  private final List<String> usedPrivileges;

  // The number of entries returned to the client.
  private final Long entriesReturned;

  // The number of intermediate response messages returned to the client.
  private final Long intermediateResponsesReturned;

  // The result code for the operation.
  private final ResultCode resultCode;

  // Additional information about the operation result.
  private final String additionalInformation;

  // The alternate authorization DN for the operation.
  private final String authzDN;

  // The diagnostic message for the operation.
  private final String diagnosticMessage;

  // The intermediate client result for the operation.
  private final String intermediateClientResult;

  // The matched DN for the operation.
  private final String matchedDN;

  // The port of the backend server to which the request has been forwarded.
  private final Integer targetPort;

  // The address of the backend server to which the request has been forwarded.
  private final String targetHost;

  // The protocol used to forward the request to the backend server.
  private final String targetProtocol;



  /**
   * Creates a new search result access log message from the provided message
   * string.
   *
   * @param  s  The string to be parsed as a search result access log message.
   *
   * @throws  LogException  If the provided string cannot be parsed as a valid
   *                        log message.
   */
  public SearchResultAccessLogMessage(final String s)
         throws LogException
  {
    this(new LogMessage(s));
  }



  /**
   * Creates a new search result access log message from the provided log
   * message.
   *
   * @param  m  The log message to be parsed as a search result access log
   *            message.
   */
  public SearchResultAccessLogMessage(final LogMessage m)
  {
    super(m);

    diagnosticMessage = getNamedValue("message");
    additionalInformation = getNamedValue("additionalInfo");
    matchedDN = getNamedValue("matchedDN");
    processingTime = getNamedValueAsDouble("etime");
    queueTime = getNamedValueAsDouble("qtime");
    intermediateClientResult = getNamedValue("from");
    entriesReturned = getNamedValueAsLong("entriesReturned");
    isUnindexed = getNamedValueAsBoolean("unindexed");
    authzDN = getNamedValue("authzDN");
    targetHost = getNamedValue("targetHost");
    targetPort = getNamedValueAsInteger("targetPort");
    targetProtocol = getNamedValue("targetProtocol");

    intermediateResponsesReturned =
         getNamedValueAsLong("intermediateResponsesReturned");

    final Integer rcInteger = getNamedValueAsInteger("resultCode");
    if (rcInteger == null)
    {
      resultCode = null;
    }
    else
    {
      resultCode = ResultCode.valueOf(rcInteger);
    }

    final String refStr = getNamedValue("referralURLs");
    if ((refStr == null) || (refStr.length() == 0))
    {
      referralURLs = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> refs = new LinkedList<String>();
      int startPos = 0;
      while (true)
      {
        final int commaPos = refStr.indexOf(",ldap", startPos);
        if (commaPos < 0)
        {
          refs.add(refStr.substring(startPos));
          break;
        }
        else
        {
          refs.add(refStr.substring(startPos, commaPos));
          startPos = commaPos + 1;
        }
      }
      referralURLs = Collections.unmodifiableList(refs);
    }

    final String controlStr = getNamedValue("responseControls");
    if (controlStr == null)
    {
      responseControlOIDs = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> controlList = new LinkedList<String>();
      final StringTokenizer t = new StringTokenizer(controlStr, ",");
      while (t.hasMoreTokens())
      {
        controlList.add(t.nextToken());
      }
      responseControlOIDs = Collections.unmodifiableList(controlList);
    }

    final String serversAccessedStr = getNamedValue("serversAccessed");
    if ((serversAccessedStr == null) || (serversAccessedStr.length() == 0))
    {
      serversAccessed = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> servers = new LinkedList<String>();
      final StringTokenizer tokenizer =
           new StringTokenizer(serversAccessedStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        servers.add(tokenizer.nextToken());
      }
      serversAccessed = Collections.unmodifiableList(servers);
    }

    uncachedDataAccessed = getNamedValueAsBoolean("uncachedDataAccessed");

    final String usedPrivilegesStr = getNamedValue("usedPrivileges");
    if ((usedPrivilegesStr == null) || (usedPrivilegesStr.length() == 0))
    {
      usedPrivileges = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> privileges = new LinkedList<String>();
      final StringTokenizer tokenizer =
           new StringTokenizer(usedPrivilegesStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        privileges.add(tokenizer.nextToken());
      }
      usedPrivileges = Collections.unmodifiableList(privileges);
    }

    final String preAuthZUsedPrivilegesStr =
         getNamedValue("preAuthZUsedPrivileges");
    if ((preAuthZUsedPrivilegesStr == null) ||
         (preAuthZUsedPrivilegesStr.length() == 0))
    {
      preAuthZUsedPrivileges = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> privileges = new LinkedList<String>();
      final StringTokenizer tokenizer =
           new StringTokenizer(preAuthZUsedPrivilegesStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        privileges.add(tokenizer.nextToken());
      }
      preAuthZUsedPrivileges = Collections.unmodifiableList(privileges);
    }

    final String missingPrivilegesStr = getNamedValue("missingPrivileges");
    if ((missingPrivilegesStr == null) || (missingPrivilegesStr.length() == 0))
    {
      missingPrivileges = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> privileges = new LinkedList<String>();
      final StringTokenizer tokenizer =
           new StringTokenizer(missingPrivilegesStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        privileges.add(tokenizer.nextToken());
      }
      missingPrivileges = Collections.unmodifiableList(privileges);
    }

    final String indexesNearLimitStr =
         getNamedValue("indexesWithKeysAccessedNearEntryLimit");
    if ((indexesNearLimitStr == null) || (indexesNearLimitStr.length() == 0))
    {
      indexesWithKeysAccessedNearEntryLimit = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> indexes = new LinkedList<String>();
      final StringTokenizer tokenizer =
           new StringTokenizer(indexesNearLimitStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        indexes.add(tokenizer.nextToken());
      }
      indexesWithKeysAccessedNearEntryLimit =
           Collections.unmodifiableList(indexes);
    }

    final String indexesOverLimitStr =
         getNamedValue("indexesWithKeysAccessedExceedingEntryLimit");
    if ((indexesOverLimitStr == null) || (indexesOverLimitStr.length() == 0))
    {
      indexesWithKeysAccessedOverEntryLimit = Collections.emptyList();
    }
    else
    {
      final LinkedList<String> indexes = new LinkedList<String>();
      final StringTokenizer tokenizer =
           new StringTokenizer(indexesOverLimitStr, ",");
      while (tokenizer.hasMoreTokens())
      {
        indexes.add(tokenizer.nextToken());
      }
      indexesWithKeysAccessedOverEntryLimit =
           Collections.unmodifiableList(indexes);
    }
  }



  /**
   * Retrieves the result code for the operation.
   *
   * @return  The result code for the operation, or {@code null} if it is not
   *          included in the log message.
   */
  public ResultCode getResultCode()
  {
    return resultCode;
  }



  /**
   * Retrieves the diagnostic message for the operation.
   *
   * @return  The diagnostic message for the operation, or {@code null} if it is
   *          not included in the log message.
   */
  public String getDiagnosticMessage()
  {
    return diagnosticMessage;
  }



  /**
   * Retrieves a message with additional information about the result of the
   * operation.
   *
   * @return  A message with additional information about the result of the
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  public String getAdditionalInformation()
  {
    return additionalInformation;
  }



  /**
   * Retrieves the matched DN for the operation.
   *
   * @return  The matched DN for the operation, or {@code null} if it is not
   *          included in the log message.
   */
  public String getMatchedDN()
  {
    return matchedDN;
  }



  /**
   * Retrieves the list of referral URLs for the operation.
   *
   * @return  The list of referral URLs for the operation, or an empty list if
   *          it is not included in the log message.
   */
  public List<String> getReferralURLs()
  {
    return referralURLs;
  }



  /**
   * Retrieves the number of intermediate response messages returned in the
   * course of processing the operation.
   *
   * @return  The number of intermediate response messages returned to the
   *          client in the course of processing the operation, or {@code null}
   *          if it is not included in the log message.
   */
  public Long getIntermediateResponsesReturned()
  {
    return intermediateResponsesReturned;
  }



  /**
   * Retrieves the length of time in milliseconds required to process the
   * operation.
   *
   * @return  The length of time in milliseconds required to process the
   *          operation, or {@code null} if it is not included in the log
   *          message.
   */
  public Double getProcessingTimeMillis()
  {
    return processingTime;
  }



  /**
   * Retrieves the length of time in milliseconds the operation was required to
   * wait on the work queue.
   *
   * @return  The length of time in milliseconds the operation was required to
   *          wait on the work queue, or {@code null} if it is not included in
   *          the log message.
   */
  public Double getQueueTimeMillis()
  {
    return queueTime;
  }



  /**
   * Retrieves the OIDs of any response controls contained in the log message.
   *
   * @return  The OIDs of any response controls contained in the log message, or
   *          an empty list if it is not included in the log message.
   */
  public List<String> getResponseControlOIDs()
  {
    return responseControlOIDs;
  }



  /**
   * Retrieves a list of the additional servers that were accessed in the course
   * of processing the operation.  For example, if the access log message is
   * from a Directory Proxy Server instance, then this may contain a list of the
   * backend servers used to process the operation.
   *
   * @return  A list of the additional servers that were accessed in the course
   *          of processing the operation, or an empty list if it is not
   *          included in the log message.
   */
  public List<String> getServersAccessed()
  {
    return serversAccessed;
  }



  /**
   * Indicates whether the server accessed any uncached data in the course of
   * processing the operation.
   *
   * @return  {@code true} if the server was known to access uncached data in
   *          the course of processing the operation, {@code false} if the
   *          server was known not to access uncached data, or {@code null} if
   *          it is not included in the log message (and the server likely did
   *          not access uncached data).
   */
  public Boolean getUncachedDataAccessed()
  {
    return uncachedDataAccessed;
  }



  /**
   * Retrieves the content of the intermediate client result for the
   * operation.
   *
   * @return  The content of the intermediate client result for the operation,
   *          or {@code null} if it is not included in the log message.
   */
  public String getIntermediateClientResult()
  {
    return intermediateClientResult;
  }



  /**
   * Retrieves the number of entries returned to the client.
   *
   * @return  The number of entries returned to the client, or {@code null} if
   *          it is not included in the log message.
   */
  public Long getEntriesReturned()
  {
    return entriesReturned;
  }



  /**
   * Indicates whether the search was unindexed.
   *
   * @return  {@code Boolean.TRUE} if the search was unindexed,
   *          {@code Boolean.FALSE} if it was not, or {@code null} if it is not
   *          included in the log message.
   */
  public Boolean isUnindexed()
  {
    return isUnindexed;
  }



  /**
   * Retrieves the alternate authorization DN for the operation.
   *
   * @return  The alternate authorization DN for the operation, or {@code null}
   *          if it is not included in the log message.
   */
  public String getAlternateAuthorizationDN()
  {
    return authzDN;
  }



  /**
   * Retrieves the address of the backend server to which the request has been
   * forwarded.
   *
   * @return  The address of the backend server to which the request has been
   *          forwarded, or {@code null} if it is not included in the log
   *          message.
   */
  public String getTargetHost()
  {
    return targetHost;
  }



  /**
   * Retrieves the port of the backend server to which the request has been
   * forwarded.
   *
   * @return  The port of the backend server to which the request has been
   *          forwarded, or {@code null} if it is not included in the log
   *          message.
   */
  public Integer getTargetPort()
  {
    return targetPort;
  }



  /**
   * Retrieves the protocol used to forward the request to the backend server.
   *
   * @return  The protocol used to forward the request to the backend server, or
   *          {@code null} if it is not included in the log message.
   */
  public String getTargetProtocol()
  {
    return targetProtocol;
  }



  /**
   * Retrieves the names of any privileges used during the course of processing
   * the operation.
   *
   * @return  The names of any privileges used during the course of processing
   *          the operation, or an empty list if no privileges were used or this
   *          is not included in the log message.
   */
  public List<String> getUsedPrivileges()
  {
    return usedPrivileges;
  }



  /**
   * Retrieves the names of any privileges used during the course of processing
   * the operation before an alternate authorization identity was assigned.
   *
   * @return  The names of any privileges used during the course of processing
   *          the operation before an alternate authorization identity was
   *          assigned, or an empty list if no privileges were used or this is
   *          not included in the log message.
   */
  public List<String> getPreAuthorizationUsedPrivileges()
  {
    return preAuthZUsedPrivileges;
  }



  /**
   * Retrieves the names of any privileges that would have been required for
   * processing the operation but that the requester did not have.
   *
   * @return  The names of any privileges that would have been required for
   *          processing the operation but that the requester did not have, or
   *          an empty list if there were no missing privileges or this is not
   *          included in the log message.
   */
  public List<String> getMissingPrivileges()
  {
    return missingPrivileges;
  }



  /**
   * Retrieves the names of any indexes for which one or more keys near
   * (typically, within 80% of) the index entry limit were accessed while
   * processing the operation.
   *
   * @return  The names of any indexes for which one or more keys near the index
   *          entry limit were accessed while processing the operation, or an
   *          empty list if no such index keys were accessed, or if this is not
   *          included in the log message.
   */
  public List<String> getIndexesWithKeysAccessedNearEntryLimit()
  {
    return indexesWithKeysAccessedNearEntryLimit;
  }



  /**
   * Retrieves the names of any indexes for which one or more keys over the
   * index entry limit were accessed while processing the operation.
   *
   * @return  The names of any indexes for which one or more keys over the index
   *          entry limit were accessed while processing the operation, or an
   *          empty list if no such index keys were accessed, or if this is not
   *          included in the log message.
   */
  public List<String> getIndexesWithKeysAccessedOverEntryLimit()
  {
    return indexesWithKeysAccessedOverEntryLimit;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public AccessLogMessageType getMessageType()
  {
    return AccessLogMessageType.RESULT;
  }
}
