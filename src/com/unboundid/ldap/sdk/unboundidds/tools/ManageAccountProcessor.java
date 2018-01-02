/*
 * Copyright 2016-2018 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright (C) 2016-2018 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.tools;



import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.ExtendedResult;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPConnectionPool;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityError;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityNotice;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateAccountUsabilityWarning;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedRequest;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateExtendedResult;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateOperation;
import com.unboundid.ldif.LDIFWriter;
import com.unboundid.util.Debug;
import com.unboundid.util.FixedRateBarrier;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.util.args.TimestampArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ManageAccount.*;
import static com.unboundid.ldap.sdk.unboundidds.extensions.
            PasswordPolicyStateOperation.*;
import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a mechanism for ensuring that entries targeted by the
 * manage-account tool are processed properly, whether by the thread providing
 * the DN of the entry to update, or by a separate worker thread.
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
final class ManageAccountProcessor
{
  // The argument parser for the manage-account tool.
  private final ArgumentParser parser;

  // Indicates whether to suppress result operations without values.
  private final boolean suppressEmptyResultOperations;

  // The optional rate limiter that will be used when processing operations.
  private final FixedRateBarrier rateLimiter;

  // The connection pool to use for all LDAP communication.
  private final LDAPConnectionPool pool;

  // An LDIF writer that will be used to record information about all results.
  private final LDIFWriter outputWriter;

  // An optional LDIF writer that will be used to record information about
  // failed operations.
  private final LDIFWriter rejectWriter;

  // An optional queue used to hold the DNs of entries to process.
  private final LinkedBlockingQueue<String> dnQueue;

  // The list of processor threads that have been created.
  private final List<ManageAccountProcessorThread> processorThreads;

  // A handle to the manage-account tool instance with which this processor is
  // associated.
  private final ManageAccount manageAccount;

  // The password policy state operation to be processed.
  private final PasswordPolicyStateOperation pwpStateOperation;

  // The string representation of the core manage-account command line (minus
  // connection, authentication, and target user arguments) being processed.
  private final String commandLine;



  /**
   * Creates a new manage account processor with the provided information.
   *
   * @param  manageAccount  A handle to the manage-account tool instance with
   *                        which this processor is associated.
   * @param  pool           The connection pool to use for all LDAP
   *                        communication.
   * @param  rateLimiter    An optional rate limiter that will be used when
   *                        processing operations.
   * @param  outputWriter   The writer that will be used to write information
   *                        about all operations processed, whether successful
   *                        or not.
   * @param  rejectWriter   An optional LDIF writer that will be used to record
   *                        information about failed operations.
   *
   * @throws  LDAPException  If a problem is encountered while initializing this
   *                         account processor.
   */
  ManageAccountProcessor(final ManageAccount manageAccount,
                         final LDAPConnectionPool pool,
                         final FixedRateBarrier rateLimiter,
                         final LDIFWriter outputWriter,
                         final LDIFWriter rejectWriter)
       throws LDAPException
  {
    this.manageAccount = manageAccount;
    this.pool          = pool;
    this.rateLimiter   = rateLimiter;
    this.outputWriter  = outputWriter;
    this.rejectWriter  = rejectWriter;

    parser = manageAccount.getArgumentParser();

    suppressEmptyResultOperations = parser.getBooleanArgument(
         ARG_SUPPRESS_EMPTY_RESULT_OPERATIONS).isPresent();


    // Create the password policy state operation that will be processed for
    // each matching entry.
    final StringBuilder commandBuffer = new StringBuilder();
    pwpStateOperation = createPasswordPolicyStateOperation(commandBuffer);
    commandLine = commandBuffer.toString();


    // Figure out how many threads to use to process manage-account operations.
    // If there should be more than one, then create a queue to hold the DNs
    // of the entries to process.
    final int numThreads =
         parser.getIntegerArgument(ARG_NUM_THREADS).getValue();
    if (numThreads > 1)
    {
      dnQueue = new LinkedBlockingQueue<String>(100);

      processorThreads =
           new ArrayList<ManageAccountProcessorThread>(numThreads);
      for (int i=1; i <= numThreads; i++)
      {
        final ManageAccountProcessorThread processorThread =
             new ManageAccountProcessorThread(i, this);
        processorThread.start();
        processorThreads.add(processorThread);
      }
    }
    else
    {
      dnQueue = null;
      processorThreads = Collections.emptyList();
    }
  }



  /**
   * Ensures that the password policy state operation is processed for the entry
   * with the given DN.  This will either process the operation immediately in
   * the current thread (if a single manage-account thread is configured), or
   * will enqueue the DN to be processed by another thread.
   *
   * @param  dn  The DN of the entry to process.
   */
  void process(final String dn)
  {
    if (dnQueue == null)
    {
      if (pwpStateOperation == null)
      {
        process(new PasswordPolicyStateExtendedRequest(dn));
      }
      else
      {
        process(new PasswordPolicyStateExtendedRequest(dn, pwpStateOperation));
      }
    }
    else
    {
      while (! manageAccount.cancelRequested())
      {
        try
        {
          if (dnQueue.offer(dn, 100L, TimeUnit.MILLISECONDS))
          {
            return;
          }
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Retrieves the next password policy state extended request to be processed.
   * This should only be called by {@link ManageAccountProcessorThread}
   * instances.
   *
   * @return  The next password policy state extended request to be processed,
   *          or {@code null} if no more processing should be performed.
   */
  PasswordPolicyStateExtendedRequest getRequest()
  {
    // If the tool has been interrupted, then return null to signal that the
    // thread should exit.
    if (manageAccount.cancelRequested())
    {
      return null;
    }


    // Get the DN of the next entry to process.  Get it without waiting if we
    // can, but check for cancel and end of input regularly.
    String dn = dnQueue.poll();
    while (dn == null)
    {
      if (manageAccount.cancelRequested())
      {
        return null;
      }

      if (manageAccount.allDNsProvided())
      {
        dn = dnQueue.poll();
        if (dn == null)
        {
          return null;
        }
        else
        {
          break;
        }
      }

      try
      {
        dn = dnQueue.poll(100L, TimeUnit.MILLISECONDS);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);

        if (e instanceof InterruptedException)
        {
          Thread.currentThread().interrupt();
        }
      }
    }

    if (pwpStateOperation == null)
    {
      return new PasswordPolicyStateExtendedRequest(dn);
    }
    else
    {
      return new PasswordPolicyStateExtendedRequest(dn, pwpStateOperation);
    }
  }



  /**
   * Performs the appropriate processing for the provided password policy state
   * extended request.
   *
   * @param  request  The password policy state extended request to process.
   */
  void process(final PasswordPolicyStateExtendedRequest request)
  {
    // Get a connection to use to process the operation.
    LDAPConnection conn;
    try
    {
      conn = pool.getConnection();
    }
    catch (final LDAPException le)
    {
      Debug.debugException(le);
      handleResult(request, le);
      return;
    }


    boolean alreadyReleased = false;
    boolean releaseAsDefunct = true;
    try
    {
      // If there is a rate limiter, then wait until it allows us to proceed.
      if (rateLimiter != null)
      {
        rateLimiter.await();
      }


      // Try to process the operation.
      PasswordPolicyStateExtendedResult result;
      try
      {
        result =
             (PasswordPolicyStateExtendedResult)
             conn.processExtendedOperation(request);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        try
        {
          result =
               new PasswordPolicyStateExtendedResult(new ExtendedResult(le));
        }
        catch (final LDAPException le2)
        {
          Debug.debugException(le2);
          result = null;
        }
      }


      // If we have a non-null result with a result code that indicates that
      // the connection is still usable, then we're done and we can release
      // the connection for re-use.
      if ((result != null) && (result.getResultCode().isConnectionUsable()))
      {
        handleResult(request, result);
        releaseAsDefunct = false;
        return;
      }


      // If we've gotten here, then something went very wrong with the first
      // attempt.  Try to replace the connection with a newly-created one.
      try
      {
        alreadyReleased = true;
        conn = pool.replaceDefunctConnection(conn);
        alreadyReleased = false;
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        // We couldn't replace the connection, so there's nothing else to try.
        handleResult(request, le);
        return;
      }


      // Make a second attempt at processing the operation.
      try
      {
        result =
             (PasswordPolicyStateExtendedResult)
             conn.processExtendedOperation(request);
      }
      catch (final LDAPException le)
      {
        Debug.debugException(le);

        try
        {
          result =
               new PasswordPolicyStateExtendedResult(new ExtendedResult(le));
        }
        catch (final LDAPException le2)
        {
          Debug.debugException(le2);
          handleResult(request, le);
          return;
        }
      }

      if (result.getResultCode().isConnectionUsable())
      {
        releaseAsDefunct = false;
      }

      handleResult(request, result);
    }
    finally
    {
      if (! alreadyReleased)
      {
        if (releaseAsDefunct)
        {
          pool.releaseDefunctConnection(conn);
        }
        else
        {
          pool.releaseConnection(conn);
        }
      }
    }
  }



  /**
   * Performs the appropriate processing for a result that failed with an
   * {@code LDAPException}.
   *
   * @param  request  The request that was processed.
   * @param  le       The exception caught during processing.
   */
  void handleResult(final PasswordPolicyStateExtendedRequest request,
                    final LDAPException le)
  {
    try
    {
      final PasswordPolicyStateExtendedResult result =
           new PasswordPolicyStateExtendedResult(new ExtendedResult(le));
      handleResult(request, result);
      return;
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
    }

    handleResult(createResultEntry(request, le.toLDAPResult()), true);
  }



  /**
   * Performs the appropriate processing for the provided result.
   *
   * @param  request  The request that was processed.
   * @param  result   The result of the processing.
   */
  void handleResult(final PasswordPolicyStateExtendedRequest request,
                    final PasswordPolicyStateExtendedResult result)
  {
    handleResult(createResultEntry(request, result),
         (result.getResultCode() != ResultCode.SUCCESS));
  }



  /**
   * Ensures that the provided message (e.g., information about an error
   * encountered from something other than a password policy state operation) is
   * written to the output writer and optionally the reject writer.  The message
   * will be written as an LDIF comment.
   *
   * @param  message    The message to be written.  It must not be {@code null}.
   * @param  isFailure  Indicates whether the message should also be written to
   *                    the reject writer if one is defined.
   */
  void handleMessage(final String message, final boolean isFailure)
  {
    synchronized (outputWriter)
    {
      try
      {
        outputWriter.writeComment(message, true, true);
        outputWriter.flush();
      }
      catch (final Exception e)
      {
        // We can't really do anything about this.
        Debug.debugException(e);
      }
    }

    if (isFailure && (rejectWriter != null))
    {
      synchronized (rejectWriter)
      {
        try
        {
          rejectWriter.writeComment(message, true, true);
          rejectWriter.flush();
        }
        catch (final Exception e)
        {
          // We can't really do anything about this.
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Creates an entry that encapsulates the content of the provided result.
   *
   * @param  request  The request that was processed.
   * @param  result   The result of the processing.
   *
   * @return  The entry that was created.
   */
  private Entry createResultEntry(
                     final PasswordPolicyStateExtendedRequest request,
                     final LDAPResult result)
  {
    final Entry e = new Entry(request.getUserDN());
    e.addAttribute("base-command-line",
         commandLine + " --targetDN " +
              StaticUtils.cleanExampleCommandLineArgument(e.getDN()));

    e.addAttribute("result-code",
         String.valueOf(result.getResultCode().intValue()));

    final String resultCodeName = result.getResultCode().getName();
    if (resultCodeName != null)
    {
      e.addAttribute("result-code-name", resultCodeName);
    }

    final String diagnosticMessage = result.getDiagnosticMessage();
    if (diagnosticMessage != null)
    {
      e.addAttribute("diagnostic-message", diagnosticMessage);
    }

    final String matchedDN = result.getMatchedDN();
    if (matchedDN != null)
    {
      e.addAttribute("matched-dn", matchedDN);
    }

    final String[] referralURLs = result.getReferralURLs();
    if ((referralURLs != null) && (referralURLs.length > 0))
    {
      e.addAttribute("referral-url", referralURLs);
    }

    if (! (result instanceof PasswordPolicyStateExtendedResult))
    {
      return e;
    }

    final PasswordPolicyStateExtendedResult r =
         (PasswordPolicyStateExtendedResult) result;
    for (final PasswordPolicyStateOperation o : r.getOperations())
    {
      final String[] values = o.getStringValues();
      if (values.length == 0)
      {
        if (suppressEmptyResultOperations)
        {
          continue;
        }
      }

      final String attrName;
      final ManageAccountSubCommandType subcommandType =
           ManageAccountSubCommandType.forOperationType(o.getOperationType());
      if (subcommandType == null)
      {
        if (o.getOperationType() == 39)
        {
          // This is a deprecated response that the client doesn't support, but
          // older servers may return it.
          attrName = "get-password-history";
        }
        else
        {
          // This result may come from a newer version of the server that has
          // additional password policy state operation types.
          attrName = "unrecognized-operation-type-" + o.getOperationType();
        }
      }
      else
      {
        attrName = subcommandType.getPrimaryName();
      }

      if (values.length == 0)
      {
        e.addAttribute(attrName, "");
      }
      else
      {
        // There may be some subcommands that require special treatment.  Handle
        // those specially.  Otherwise, just go with the string representations.
        switch (subcommandType)
        {
          case GET_ACCOUNT_USABILITY_NOTICES:
            final String[] notices = new String[values.length];
            for (int i=0; i < values.length; i++)
            {
              try
              {
                notices[i] = new PasswordPolicyStateAccountUsabilityNotice(
                     values[i]).getMessage();
              }
              catch (final Exception ex)
              {
                Debug.debugException(ex);
                notices[i] = values[i];
              }
            }
            e.addAttribute(attrName, notices);
            break;

          case GET_ACCOUNT_USABILITY_WARNINGS:
            final String[] warnings = new String[values.length];
            for (int i=0; i < values.length; i++)
            {
              try
              {
                warnings[i] = new PasswordPolicyStateAccountUsabilityWarning(
                     values[i]).getMessage();
              }
              catch (final Exception ex)
              {
                Debug.debugException(ex);
                warnings[i] = values[i];
              }
            }
            e.addAttribute(attrName, warnings);
            break;

          case GET_ACCOUNT_USABILITY_ERRORS:
            final String[] errors = new String[values.length];
            for (int i=0; i < values.length; i++)
            {
              try
              {
                errors[i] = new PasswordPolicyStateAccountUsabilityError(
                     values[i]).getMessage();
              }
              catch (final Exception ex)
              {
                Debug.debugException(ex);
                errors[i] = values[i];
              }
            }
            e.addAttribute(attrName, errors);
            break;

          default:
            e.addAttribute(attrName, values);
            break;
        }
      }
    }


    return e;
  }



  /**
   * Ensures that the provided entry is output to either the tool's output or
   * error stream, and also to the reject writer if appropriate.
   *
   * @param  resultEntry  The entry to be written.
   * @param  isFailure    Indicates whether the operation was considered a
   *                      failure and should be recorded in the reject writer.
   */
  private void handleResult(final Entry resultEntry, final boolean isFailure)
  {
    synchronized (outputWriter)
    {
      try
      {
        outputWriter.writeEntry(resultEntry);
        outputWriter.flush();
      }
      catch (final Exception e)
      {
        // We can't really do anything about this.
        Debug.debugException(e);
      }
    }

    if (isFailure && (rejectWriter != null))
    {
      synchronized (rejectWriter)
      {
        try
        {
          rejectWriter.writeEntry(resultEntry);
          rejectWriter.flush();
        }
        catch (final Exception e)
        {
          // We can't really do anything about this.
          Debug.debugException(e);
        }
      }
    }
  }



  /**
   * Creates the password policy state operation that will be processed against
   * all target entries.
   *
   * @param  commandBuffer  The buffer to which the manage-account command line
   *                        should be appended.
   *
   * @return  The password policy state operation that was created.
   *
   * @throws  LDAPException  If a problem is encountered while creating the
   *                         password policy state operation.
   */
  private PasswordPolicyStateOperation createPasswordPolicyStateOperation(
                                            final StringBuilder commandBuffer)
          throws LDAPException
  {
    final SubCommand subcommand = parser.getSelectedSubCommand();
    if (subcommand == null)
    {
      // This should never happen.
      throw new LDAPException(ResultCode.PARAM_ERROR,
           ERR_MANAGE_ACCT_PROCESSOR_NO_SUBCOMMAND.get(
                manageAccount.getToolName()));
    }

    final ManageAccountSubCommandType subcommandType =
         ManageAccountSubCommandType.forName(subcommand.getPrimaryName());
    if (subcommandType == null)
    {
      // This should also never happen.
      throw new LDAPException(ResultCode.LOCAL_ERROR,
           ERR_MANAGE_ACCT_PROCESSOR_UNSUPPORTED_SUBCOMMAND.get(
                subcommand.getPrimaryName(), manageAccount.getToolName()));
    }

    commandBuffer.append(manageAccount.getToolName());
    commandBuffer.append(' ');
    commandBuffer.append(subcommandType.getPrimaryName());

    switch (subcommandType)
    {
      case GET_ALL:
        // The get-all operation is invoked by sending a password policy state
        // extended request without any operations.
        return null;

      case GET_PASSWORD_POLICY_DN:
        return createGetPasswordPolicyDNOperation();

      case GET_ACCOUNT_IS_USABLE:
        return createGetAccountIsUsableOperation();

      case GET_ACCOUNT_USABILITY_NOTICES:
        return createGetAccountUsabilityNoticesOperation();

      case GET_ACCOUNT_USABILITY_WARNINGS:
        return createGetAccountUsabilityWarningsOperation();

      case GET_ACCOUNT_USABILITY_ERRORS:
        return createGetAccountUsabilityErrorsOperation();

      case GET_PASSWORD_CHANGED_TIME:
        return createGetPasswordChangedTimeOperation();

      case SET_PASSWORD_CHANGED_TIME:
        return createSetPasswordChangedTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_PASSWORD_CHANGED_TIME:
        return createClearPasswordChangedTimeOperation();

      case GET_ACCOUNT_IS_DISABLED:
        return createGetAccountDisabledStateOperation();

      case SET_ACCOUNT_IS_DISABLED:
        return createSetAccountDisabledStateOperation(
             getBoolean(subcommand, commandBuffer));

      case CLEAR_ACCOUNT_IS_DISABLED:
        return createClearAccountDisabledStateOperation();

      case GET_ACCOUNT_ACTIVATION_TIME:
        return createGetAccountActivationTimeOperation();

      case SET_ACCOUNT_ACTIVATION_TIME:
        return createSetAccountActivationTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_ACCOUNT_ACTIVATION_TIME:
        return createClearAccountActivationTimeOperation();

      case GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION:
        return createGetSecondsUntilAccountActivationOperation();

      case GET_ACCOUNT_IS_NOT_YET_ACTIVE:
        return createGetAccountIsNotYetActiveOperation();

      case GET_ACCOUNT_EXPIRATION_TIME:
        return createGetAccountExpirationTimeOperation();

      case SET_ACCOUNT_EXPIRATION_TIME:
        return createSetAccountExpirationTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_ACCOUNT_EXPIRATION_TIME:
        return createClearAccountExpirationTimeOperation();

      case GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION:
        return createGetSecondsUntilAccountExpirationOperation();

      case GET_ACCOUNT_IS_EXPIRED:
        return createGetAccountIsExpiredOperation();

      case GET_PASSWORD_EXPIRATION_WARNED_TIME:
        return createGetPasswordExpirationWarnedTimeOperation();

      case SET_PASSWORD_EXPIRATION_WARNED_TIME:
        return createSetPasswordExpirationWarnedTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_PASSWORD_EXPIRATION_WARNED_TIME:
        return createClearPasswordExpirationWarnedTimeOperation();

      case GET_SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING:
        return createGetSecondsUntilPasswordExpirationWarningOperation();

      case GET_PASSWORD_EXPIRATION_TIME:
        return createGetPasswordExpirationTimeOperation();

      case GET_SECONDS_UNTIL_PASSWORD_EXPIRATION:
        return createGetSecondsUntilPasswordExpirationOperation();

      case GET_PASSWORD_IS_EXPIRED:
        return createGetPasswordIsExpiredOperation();

      case GET_ACCOUNT_IS_FAILURE_LOCKED:
        return createGetAccountIsFailureLockedOperation();

      case SET_ACCOUNT_IS_FAILURE_LOCKED:
        return createSetAccountIsFailureLockedOperation(
             getBoolean(subcommand, commandBuffer));

      case GET_FAILURE_LOCKOUT_TIME:
        return createGetFailureLockoutTimeOperation();

      case GET_SECONDS_UNTIL_AUTHENTICATION_FAILURE_UNLOCK:
        return createGetSecondsUntilAuthenticationFailureUnlockOperation();

      case GET_AUTHENTICATION_FAILURE_TIMES:
        return createGetAuthenticationFailureTimesOperation();

      case ADD_AUTHENTICATION_FAILURE_TIME:
        return createAddAuthenticationFailureTimeOperation(
             getDates(subcommand, commandBuffer));

      case SET_AUTHENTICATION_FAILURE_TIMES:
        return createSetAuthenticationFailureTimesOperation(
             getDates(subcommand, commandBuffer));

      case CLEAR_AUTHENTICATION_FAILURE_TIMES:
        return createClearAuthenticationFailureTimesOperation();

      case GET_REMAINING_AUTHENTICATION_FAILURE_COUNT:
        return createGetRemainingAuthenticationFailureCountOperation();

      case GET_ACCOUNT_IS_IDLE_LOCKED:
        return createGetAccountIsIdleLockedOperation();

      case GET_SECONDS_UNTIL_IDLE_LOCKOUT:
        return createGetSecondsUntilIdleLockoutOperation();

      case GET_IDLE_LOCKOUT_TIME:
        return createGetIdleLockoutTimeOperation();

      case GET_MUST_CHANGE_PASSWORD:
        return createGetPasswordResetStateOperation();

      case SET_MUST_CHANGE_PASSWORD:
        return createSetPasswordResetStateOperation(
             getBoolean(subcommand, commandBuffer));

      case CLEAR_MUST_CHANGE_PASSWORD:
        return createClearPasswordResetStateOperation();

      case GET_ACCOUNT_IS_PASSWORD_RESET_LOCKED:
        return createGetAccountIsResetLockedOperation();

      case GET_SECONDS_UNTIL_PASSWORD_RESET_LOCKOUT:
        return createGetSecondsUntilPasswordResetLockoutOperation();

      case GET_PASSWORD_RESET_LOCKOUT_TIME:
        return createGetResetLockoutTimeOperation();

      case GET_LAST_LOGIN_TIME:
        return createGetLastLoginTimeOperation();

      case SET_LAST_LOGIN_TIME:
        return createSetLastLoginTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_LAST_LOGIN_TIME:
        return createClearLastLoginTimeOperation();

      case GET_LAST_LOGIN_IP_ADDRESS:
        return createGetLastLoginIPAddressOperation();

      case SET_LAST_LOGIN_IP_ADDRESS:
        return createSetLastLoginIPAddressOperation(
             getString(subcommand, commandBuffer));

      case CLEAR_LAST_LOGIN_IP_ADDRESS:
        return createClearLastLoginIPAddressOperation();

      case GET_GRACE_LOGIN_USE_TIMES:
        return createGetGraceLoginUseTimesOperation();

      case ADD_GRACE_LOGIN_USE_TIME:
        return createAddGraceLoginUseTimeOperation(
             getDates(subcommand, commandBuffer));

      case SET_GRACE_LOGIN_USE_TIMES:
        return createSetGraceLoginUseTimesOperation(
             getDates(subcommand, commandBuffer));

      case CLEAR_GRACE_LOGIN_USE_TIMES:
        return createClearGraceLoginUseTimesOperation();

      case GET_REMAINING_GRACE_LOGIN_COUNT:
        return createGetRemainingGraceLoginCountOperation();

      case GET_PASSWORD_CHANGED_BY_REQUIRED_TIME:
        return createGetPasswordChangedByRequiredTimeOperation();

      case SET_PASSWORD_CHANGED_BY_REQUIRED_TIME:
        return createSetPasswordChangedByRequiredTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_PASSWORD_CHANGED_BY_REQUIRED_TIME:
        return createClearPasswordChangedByRequiredTimeOperation();

      case GET_SECONDS_UNTIL_REQUIRED_PASSWORD_CHANGE_TIME:
        return createGetSecondsUntilRequiredChangeTimeOperation();

      case GET_PASSWORD_HISTORY_COUNT:
        return createGetPasswordHistoryCountOperation();

      case CLEAR_PASSWORD_HISTORY:
        return createClearPasswordHistoryOperation();

      case GET_HAS_RETIRED_PASSWORD:
        return createHasRetiredPasswordOperation();

      case GET_PASSWORD_RETIRED_TIME:
        return createGetPasswordRetiredTimeOperation();

      case GET_RETIRED_PASSWORD_EXPIRATION_TIME:
        return createGetRetiredPasswordExpirationTimeOperation();

      case CLEAR_RETIRED_PASSWORD:
        return createPurgeRetiredPasswordOperation();

      case GET_AVAILABLE_SASL_MECHANISMS:
        return createGetAvailableSASLMechanismsOperation();

      case GET_AVAILABLE_OTP_DELIVERY_MECHANISMS:
        return createGetAvailableOTPDeliveryMechanismsOperation();

      case GET_HAS_TOTP_SHARED_SECRET:
        return createHasTOTPSharedSecret();

      case ADD_TOTP_SHARED_SECRET:
        return createAddTOTPSharedSecretOperation(
             getStrings(subcommand, commandBuffer));

      case REMOVE_TOTP_SHARED_SECRET:
        return createRemoveTOTPSharedSecretOperation(
             getStrings(subcommand, commandBuffer));

      case SET_TOTP_SHARED_SECRETS:
        return createSetTOTPSharedSecretsOperation(
             getStrings(subcommand, commandBuffer));

      case CLEAR_TOTP_SHARED_SECRETS:
        return createClearTOTPSharedSecretsOperation();

      case GET_HAS_REGISTERED_YUBIKEY_PUBLIC_ID:
        return createHasYubiKeyPublicIDOperation();

      case GET_REGISTERED_YUBIKEY_PUBLIC_IDS:
        return createGetRegisteredYubiKeyPublicIDsOperation();

      case ADD_REGISTERED_YUBIKEY_PUBLIC_ID:
        return createAddRegisteredYubiKeyPublicIDOperation(
             getStrings(subcommand, commandBuffer));

      case REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID:
        return createRemoveRegisteredYubiKeyPublicIDOperation(
             getStrings(subcommand, commandBuffer));

      case SET_REGISTERED_YUBIKEY_PUBLIC_IDS:
        return createSetRegisteredYubiKeyPublicIDsOperation(
             getStrings(subcommand, commandBuffer));

      case CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS:
        return createClearRegisteredYubiKeyPublicIDsOperation();

      case GET_HAS_STATIC_PASSWORD:
        return createHasStaticPasswordOperation();

      default:
        // This should never happen.
        throw new LDAPException(ResultCode.LOCAL_ERROR,
             ERR_MANAGE_ACCT_PROCESSOR_UNSUPPORTED_SUBCOMMAND.get(
                  subcommand.getPrimaryName(), manageAccount.getToolName()));
    }
  }



  /**
   * Retrieves the value of the "operationValue" argument from the provided
   * subcommand's argument parser as a {@code Date}.
   *
   * @param  subcommand     The subcommand to examine.
   * @param  commandBuffer  The buffer to which the manage-account command line
   *                        should be appended.
   *
   * @return  The value of the "operationValue" argument.
   */
  private static boolean getBoolean(final SubCommand subcommand,
                                    final StringBuilder commandBuffer)
  {
    final ArgumentParser parser = subcommand.getArgumentParser();
    final BooleanValueArgument arg =
         parser.getBooleanValueArgument("operationValue");

    final boolean booleanValue = arg.getValue();
    if (arg.isPresent())
    {
      commandBuffer.append(' ');
      commandBuffer.append(arg.getIdentifierString());
      commandBuffer.append(' ');
      commandBuffer.append(booleanValue);
    }

    return booleanValue;
  }



  /**
   * Retrieves the value of the "operationValue" argument from the provided
   * subcommand's argument parser as a {@code Date}.
   *
   * @param  subcommand     The subcommand to examine.
   * @param  commandBuffer  The buffer to which the manage-account command line
   *                        should be appended.
   *
   * @return  The value of the "operationValue" argument.
   */
  private static Date getDate(final SubCommand subcommand,
                              final StringBuilder commandBuffer)
  {
    final ArgumentParser parser = subcommand.getArgumentParser();
    final TimestampArgument arg = parser.getTimestampArgument("operationValue");

    final Date dateValue = arg.getValue();
    if (arg.isPresent())
    {
      commandBuffer.append(' ');
      commandBuffer.append(arg.getIdentifierString());
      commandBuffer.append(' ');
      commandBuffer.append(StaticUtils.encodeGeneralizedTime(dateValue));
    }

    return dateValue;
  }



  /**
   * Retrieves the value of the "operationValue" argument from the provided
   * subcommand's argument parser as an array of {@code Date} objects.
   *
   * @param  subcommand     The subcommand to examine.
   * @param  commandBuffer  The buffer to which the manage-account command line
   *                        should be appended.
   *
   * @return  The value of the "operationValue" argument.
   */
  private static Date[] getDates(final SubCommand subcommand,
                                 final StringBuilder commandBuffer)
  {
    final ArgumentParser parser = subcommand.getArgumentParser();
    final TimestampArgument arg = parser.getTimestampArgument("operationValue");

    final List<Date> dateList = arg.getValues();
    final Date[] dateArray = new Date[dateList.size()];
    dateList.toArray(dateArray);

    if (arg.isPresent())
    {
      for (final Date d : dateArray)
      {
        commandBuffer.append(' ');
        commandBuffer.append(arg.getIdentifierString());
        commandBuffer.append(' ');
        commandBuffer.append(StaticUtils.encodeGeneralizedTime(d));
      }
    }

    return dateArray;
  }



  /**
   * Retrieves the value of the "operationValue" argument from the provided
   * subcommand's argument parser as a {@code String}.
   *
   * @param  subcommand     The subcommand to examine.
   * @param  commandBuffer  The buffer to which the manage-account command line
   *                        should be appended.
   *
   * @return  The value of the "operationValue" argument.
   */
  private static String getString(final SubCommand subcommand,
                                  final StringBuilder commandBuffer)
  {
    final ArgumentParser parser = subcommand.getArgumentParser();
    final StringArgument arg = parser.getStringArgument("operationValue");

    final String stringValue = arg.getValue();

    if (arg.isPresent())
    {
      commandBuffer.append(' ');
      commandBuffer.append(arg.getIdentifierString());
      commandBuffer.append(' ');
      commandBuffer.append(
           StaticUtils.cleanExampleCommandLineArgument(stringValue));
    }

    return stringValue;
  }



  /**
   * Retrieves the value of the "operationValue" argument from the provided
   * subcommand's argument parser as an array of {@code String} objects.
   *
   * @param  subcommand     The subcommand to examine.
   * @param  commandBuffer  The buffer to which the manage-account command line
   *                        should be appended.
   *
   * @return  The value of the "operationValue" argument.
   */
  private static String[] getStrings(final SubCommand subcommand,
                                     final StringBuilder commandBuffer)
  {
    final ArgumentParser parser = subcommand.getArgumentParser();
    final StringArgument arg = parser.getStringArgument("operationValue");

    final List<String> stringList = arg.getValues();
    final String[] stringArray = new String[stringList.size()];
    stringList.toArray(stringArray);

    if (arg.isPresent())
    {
      for (final String s : stringArray)
      {
        commandBuffer.append(' ');
        commandBuffer.append(arg.getIdentifierString());
        commandBuffer.append(' ');
        commandBuffer.append(StaticUtils.cleanExampleCommandLineArgument(s));
      }
    }

    return stringArray;
  }



  /**
   * Blocks until all entries have been processed.
   */
  void waitForCompletion()
  {
    // If we don't have a DN queue, then all of the operations are processed
    // synchronously and we know that we're done.
    if (dnQueue == null)
    {
      return;
    }

    while (true)
    {
      // If the manage-account tool has been interrupted, then we can declare
      // the processing complete.  We don't care about what's in the queue or
      // what the processor threads are doing.
      if (manageAccount.cancelRequested())
      {
        return;
      }


      // If all of the DNs have been provided, then we still need to wait until
      // the queue is empty and all of the processor threads have completed.
      if (manageAccount.allDNsProvided() && (dnQueue.peek() == null))
      {
        for (final ManageAccountProcessorThread t : processorThreads)
        {
          try
          {
            t.join();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);

            if (e instanceof InterruptedException)
            {
              Thread.currentThread().interrupt();
            }
          }
        }

        return;
      }

      try
      {
        Thread.sleep(10L);
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
  }
}
