/*
 * Copyright 2016-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2016-2021 Ping Identity Corporation
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
 * Copyright (C) 2016-2021 Ping Identity Corporation
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
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanValueArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.util.args.TimestampArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a mechanism for ensuring that entries targeted by the
 * manage-account tool are processed properly, whether by the thread providing
 * the DN of the entry to update, or by a separate worker thread.
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
final class ManageAccountProcessor
{
  // The argument parser for the manage-account tool.
  @NotNull private final ArgumentParser parser;

  // Indicates whether to suppress result operations without values.
  private final boolean suppressEmptyResultOperations;

  // The optional rate limiter that will be used when processing operations.
  @Nullable private final FixedRateBarrier rateLimiter;

  // The connection pool to use for all LDAP communication.
  @NotNull private final LDAPConnectionPool pool;

  // An LDIF writer that will be used to record information about all results.
  @NotNull private final LDIFWriter outputWriter;

  // An optional LDIF writer that will be used to record information about
  // failed operations.
  @Nullable private final LDIFWriter rejectWriter;

  // An optional queue used to hold the DNs of entries to process.
  @Nullable private final LinkedBlockingQueue<String> dnQueue;

  // The list of processor threads that have been created.
  @NotNull private final List<ManageAccountProcessorThread> processorThreads;

  // A handle to the manage-account tool instance with which this processor is
  // associated.
  @NotNull private final ManageAccount manageAccount;

  // The password policy state operation to be processed.
  @NotNull private final PasswordPolicyStateOperation pwpStateOperation;

  // The string representation of the core manage-account command line (minus
  // connection, authentication, and target user arguments) being processed.
  @NotNull private final String commandLine;



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
  ManageAccountProcessor(@NotNull final ManageAccount manageAccount,
                         @NotNull final LDAPConnectionPool pool,
                         @Nullable final FixedRateBarrier rateLimiter,
                         @NotNull final LDIFWriter outputWriter,
                         @Nullable final LDIFWriter rejectWriter)
       throws LDAPException
  {
    this.manageAccount = manageAccount;
    this.pool          = pool;
    this.rateLimiter   = rateLimiter;
    this.outputWriter  = outputWriter;
    this.rejectWriter  = rejectWriter;

    parser = manageAccount.getArgumentParser();

    suppressEmptyResultOperations = parser.getBooleanArgument(
         ManageAccount.ARG_SUPPRESS_EMPTY_RESULT_OPERATIONS).isPresent();


    // Create the password policy state operation that will be processed for
    // each matching entry.
    final StringBuilder commandBuffer = new StringBuilder();
    pwpStateOperation = createPasswordPolicyStateOperation(commandBuffer);
    commandLine = commandBuffer.toString();


    // Figure out how many threads to use to process manage-account operations.
    // If there should be more than one, then create a queue to hold the DNs
    // of the entries to process.
    final int numThreads =
         parser.getIntegerArgument(ManageAccount.ARG_NUM_THREADS).getValue();
    if (numThreads > 1)
    {
      dnQueue = new LinkedBlockingQueue<>(100);

      processorThreads = new ArrayList<>(numThreads);
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
  void process(@NotNull final String dn)
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
  @Nullable()
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
  void process(@NotNull final PasswordPolicyStateExtendedRequest request)
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
  private void handleResult(
                    @NotNull final PasswordPolicyStateExtendedRequest request,
                    @NotNull final LDAPException le)
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
  private void handleResult(
                    @NotNull final PasswordPolicyStateExtendedRequest request,
                    @NotNull final PasswordPolicyStateExtendedResult result)
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
  void handleMessage(@NotNull final String message, final boolean isFailure)
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
  @NotNull()
  private Entry createResultEntry(
                     @NotNull final PasswordPolicyStateExtendedRequest request,
                     @NotNull final LDAPResult result)
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
  private void handleResult(@NotNull final Entry resultEntry,
                            final boolean isFailure)
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
  @NotNull()
  private PasswordPolicyStateOperation createPasswordPolicyStateOperation(
               @NotNull final StringBuilder commandBuffer)
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
        return PasswordPolicyStateOperation.
             createGetPasswordPolicyDNOperation();

      case GET_ACCOUNT_IS_USABLE:
        return PasswordPolicyStateOperation.createGetAccountIsUsableOperation();

      case GET_ACCOUNT_USABILITY_NOTICES:
        return PasswordPolicyStateOperation.
             createGetAccountUsabilityNoticesOperation();

      case GET_ACCOUNT_USABILITY_WARNINGS:
        return PasswordPolicyStateOperation.
             createGetAccountUsabilityWarningsOperation();

      case GET_ACCOUNT_USABILITY_ERRORS:
        return PasswordPolicyStateOperation.
             createGetAccountUsabilityErrorsOperation();

      case GET_PASSWORD_CHANGED_TIME:
        return PasswordPolicyStateOperation.
             createGetPasswordChangedTimeOperation();

      case SET_PASSWORD_CHANGED_TIME:
        return PasswordPolicyStateOperation.
             createSetPasswordChangedTimeOperation(
                  getDate(subcommand, commandBuffer));

      case CLEAR_PASSWORD_CHANGED_TIME:
        return PasswordPolicyStateOperation.
             createClearPasswordChangedTimeOperation();

      case GET_ACCOUNT_IS_DISABLED:
        return PasswordPolicyStateOperation.
             createGetAccountDisabledStateOperation();

      case SET_ACCOUNT_IS_DISABLED:
        return PasswordPolicyStateOperation.
             createSetAccountDisabledStateOperation(
                  getBoolean(subcommand, commandBuffer));

      case CLEAR_ACCOUNT_IS_DISABLED:
        return PasswordPolicyStateOperation.
             createClearAccountDisabledStateOperation();

      case GET_ACCOUNT_ACTIVATION_TIME:
        return PasswordPolicyStateOperation.
             createGetAccountActivationTimeOperation();

      case SET_ACCOUNT_ACTIVATION_TIME:
        return PasswordPolicyStateOperation.
             createSetAccountActivationTimeOperation(
                  getDate(subcommand, commandBuffer));

      case CLEAR_ACCOUNT_ACTIVATION_TIME:
        return PasswordPolicyStateOperation.
             createClearAccountActivationTimeOperation();

      case GET_SECONDS_UNTIL_ACCOUNT_ACTIVATION:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilAccountActivationOperation();

      case GET_ACCOUNT_IS_NOT_YET_ACTIVE:
        return PasswordPolicyStateOperation.
             createGetAccountIsNotYetActiveOperation();

      case GET_ACCOUNT_EXPIRATION_TIME:
        return PasswordPolicyStateOperation.
             createGetAccountExpirationTimeOperation();

      case SET_ACCOUNT_EXPIRATION_TIME:
        return PasswordPolicyStateOperation.
             createSetAccountExpirationTimeOperation(
                  getDate(subcommand, commandBuffer));

      case CLEAR_ACCOUNT_EXPIRATION_TIME:
        return PasswordPolicyStateOperation.
             createClearAccountExpirationTimeOperation();

      case GET_SECONDS_UNTIL_ACCOUNT_EXPIRATION:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilAccountExpirationOperation();

      case GET_ACCOUNT_IS_EXPIRED:
        return PasswordPolicyStateOperation.
             createGetAccountIsExpiredOperation();

      case GET_PASSWORD_EXPIRATION_WARNED_TIME:
        return PasswordPolicyStateOperation.
             createGetPasswordExpirationWarnedTimeOperation();

      case SET_PASSWORD_EXPIRATION_WARNED_TIME:
        return PasswordPolicyStateOperation.
             createSetPasswordExpirationWarnedTimeOperation(
                  getDate(subcommand, commandBuffer));

      case CLEAR_PASSWORD_EXPIRATION_WARNED_TIME:
        return PasswordPolicyStateOperation.
             createClearPasswordExpirationWarnedTimeOperation();

      case GET_SECONDS_UNTIL_PASSWORD_EXPIRATION_WARNING:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilPasswordExpirationWarningOperation();

      case GET_PASSWORD_EXPIRATION_TIME:
        return PasswordPolicyStateOperation.
             createGetPasswordExpirationTimeOperation();

      case GET_SECONDS_UNTIL_PASSWORD_EXPIRATION:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilPasswordExpirationOperation();

      case GET_PASSWORD_IS_EXPIRED:
        return PasswordPolicyStateOperation.
             createGetPasswordIsExpiredOperation();

      case GET_ACCOUNT_IS_FAILURE_LOCKED:
        return PasswordPolicyStateOperation.
             createGetAccountIsFailureLockedOperation();

      case SET_ACCOUNT_IS_FAILURE_LOCKED:
        return PasswordPolicyStateOperation.
             createSetAccountIsFailureLockedOperation(
                  getBoolean(subcommand, commandBuffer));

      case GET_FAILURE_LOCKOUT_TIME:
        return PasswordPolicyStateOperation.
             createGetFailureLockoutTimeOperation();

      case GET_SECONDS_UNTIL_AUTHENTICATION_FAILURE_UNLOCK:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilAuthenticationFailureUnlockOperation();

      case GET_AUTHENTICATION_FAILURE_TIMES:
        return PasswordPolicyStateOperation.
             createGetAuthenticationFailureTimesOperation();

      case ADD_AUTHENTICATION_FAILURE_TIME:
        return PasswordPolicyStateOperation.
             createAddAuthenticationFailureTimeOperation(
                  getDates(subcommand, commandBuffer));

      case SET_AUTHENTICATION_FAILURE_TIMES:
        return PasswordPolicyStateOperation.
             createSetAuthenticationFailureTimesOperation(
                  getDates(subcommand, commandBuffer));

      case CLEAR_AUTHENTICATION_FAILURE_TIMES:
        return PasswordPolicyStateOperation.
             createClearAuthenticationFailureTimesOperation();

      case GET_REMAINING_AUTHENTICATION_FAILURE_COUNT:
        return PasswordPolicyStateOperation.
             createGetRemainingAuthenticationFailureCountOperation();

      case GET_ACCOUNT_IS_IDLE_LOCKED:
        return PasswordPolicyStateOperation.
             createGetAccountIsIdleLockedOperation();

      case GET_SECONDS_UNTIL_IDLE_LOCKOUT:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilIdleLockoutOperation();

      case GET_IDLE_LOCKOUT_TIME:
        return PasswordPolicyStateOperation.createGetIdleLockoutTimeOperation();

      case GET_MUST_CHANGE_PASSWORD:
        return PasswordPolicyStateOperation.
             createGetPasswordResetStateOperation();

      case SET_MUST_CHANGE_PASSWORD:
        return PasswordPolicyStateOperation.
             createSetPasswordResetStateOperation(
                  getBoolean(subcommand, commandBuffer));

      case CLEAR_MUST_CHANGE_PASSWORD:
        return PasswordPolicyStateOperation.
             createClearPasswordResetStateOperation();

      case GET_ACCOUNT_IS_PASSWORD_RESET_LOCKED:
        return PasswordPolicyStateOperation.
             createGetAccountIsResetLockedOperation();

      case GET_SECONDS_UNTIL_PASSWORD_RESET_LOCKOUT:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilPasswordResetLockoutOperation();

      case GET_PASSWORD_RESET_LOCKOUT_TIME:
        return PasswordPolicyStateOperation.
             createGetResetLockoutTimeOperation();

      case GET_LAST_LOGIN_TIME:
        return PasswordPolicyStateOperation.createGetLastLoginTimeOperation();

      case SET_LAST_LOGIN_TIME:
        return PasswordPolicyStateOperation.createSetLastLoginTimeOperation(
             getDate(subcommand, commandBuffer));

      case CLEAR_LAST_LOGIN_TIME:
        return PasswordPolicyStateOperation.createClearLastLoginTimeOperation();

      case GET_LAST_LOGIN_IP_ADDRESS:
        return PasswordPolicyStateOperation.
             createGetLastLoginIPAddressOperation();

      case SET_LAST_LOGIN_IP_ADDRESS:
        return PasswordPolicyStateOperation.
             createSetLastLoginIPAddressOperation(
                  getString(subcommand, commandBuffer));

      case CLEAR_LAST_LOGIN_IP_ADDRESS:
        return PasswordPolicyStateOperation.
             createClearLastLoginIPAddressOperation();

      case GET_GRACE_LOGIN_USE_TIMES:
        return PasswordPolicyStateOperation.
             createGetGraceLoginUseTimesOperation();

      case ADD_GRACE_LOGIN_USE_TIME:
        return PasswordPolicyStateOperation.createAddGraceLoginUseTimeOperation(
             getDates(subcommand, commandBuffer));

      case SET_GRACE_LOGIN_USE_TIMES:
        return PasswordPolicyStateOperation.
             createSetGraceLoginUseTimesOperation(
                  getDates(subcommand, commandBuffer));

      case CLEAR_GRACE_LOGIN_USE_TIMES:
        return PasswordPolicyStateOperation.
             createClearGraceLoginUseTimesOperation();

      case GET_REMAINING_GRACE_LOGIN_COUNT:
        return PasswordPolicyStateOperation.
             createGetRemainingGraceLoginCountOperation();

      case GET_PASSWORD_CHANGED_BY_REQUIRED_TIME:
        return PasswordPolicyStateOperation.
             createGetPasswordChangedByRequiredTimeOperation();

      case SET_PASSWORD_CHANGED_BY_REQUIRED_TIME:
        return PasswordPolicyStateOperation.
             createSetPasswordChangedByRequiredTimeOperation(
                  getDate(subcommand, commandBuffer));

      case CLEAR_PASSWORD_CHANGED_BY_REQUIRED_TIME:
        return PasswordPolicyStateOperation.
             createClearPasswordChangedByRequiredTimeOperation();

      case GET_SECONDS_UNTIL_REQUIRED_PASSWORD_CHANGE_TIME:
        return PasswordPolicyStateOperation.
             createGetSecondsUntilRequiredChangeTimeOperation();

      case GET_PASSWORD_HISTORY_COUNT:
        return PasswordPolicyStateOperation.
             createGetPasswordHistoryCountOperation();

      case CLEAR_PASSWORD_HISTORY:
        return PasswordPolicyStateOperation.
             createClearPasswordHistoryOperation();

      case GET_HAS_RETIRED_PASSWORD:
        return PasswordPolicyStateOperation.createHasRetiredPasswordOperation();

      case GET_PASSWORD_RETIRED_TIME:
        return PasswordPolicyStateOperation.
             createGetPasswordRetiredTimeOperation();

      case GET_RETIRED_PASSWORD_EXPIRATION_TIME:
        return PasswordPolicyStateOperation.
             createGetRetiredPasswordExpirationTimeOperation();

      case CLEAR_RETIRED_PASSWORD:
        return PasswordPolicyStateOperation.
             createPurgeRetiredPasswordOperation();

      case GET_AVAILABLE_SASL_MECHANISMS:
        return PasswordPolicyStateOperation.
             createGetAvailableSASLMechanismsOperation();

      case GET_AVAILABLE_OTP_DELIVERY_MECHANISMS:
        return PasswordPolicyStateOperation.
             createGetAvailableOTPDeliveryMechanismsOperation();

      case GET_HAS_TOTP_SHARED_SECRET:
        return PasswordPolicyStateOperation.
             createHasTOTPSharedSecretOperation();

      case ADD_TOTP_SHARED_SECRET:
        return PasswordPolicyStateOperation.createAddTOTPSharedSecretOperation(
             getStrings(subcommand, commandBuffer));

      case REMOVE_TOTP_SHARED_SECRET:
        return PasswordPolicyStateOperation.
             createRemoveTOTPSharedSecretOperation(
                  getStrings(subcommand, commandBuffer));

      case SET_TOTP_SHARED_SECRETS:
        return PasswordPolicyStateOperation.createSetTOTPSharedSecretsOperation(
             getStrings(subcommand, commandBuffer));

      case CLEAR_TOTP_SHARED_SECRETS:
        return PasswordPolicyStateOperation.
             createClearTOTPSharedSecretsOperation();

      case GET_HAS_REGISTERED_YUBIKEY_PUBLIC_ID:
        return PasswordPolicyStateOperation.createHasYubiKeyPublicIDOperation();

      case GET_REGISTERED_YUBIKEY_PUBLIC_IDS:
        return PasswordPolicyStateOperation.
             createGetRegisteredYubiKeyPublicIDsOperation();

      case ADD_REGISTERED_YUBIKEY_PUBLIC_ID:
        return PasswordPolicyStateOperation.
             createAddRegisteredYubiKeyPublicIDOperation(
                  getStrings(subcommand, commandBuffer));

      case REMOVE_REGISTERED_YUBIKEY_PUBLIC_ID:
        return PasswordPolicyStateOperation.
             createRemoveRegisteredYubiKeyPublicIDOperation(
                  getStrings(subcommand, commandBuffer));

      case SET_REGISTERED_YUBIKEY_PUBLIC_IDS:
        return PasswordPolicyStateOperation.
             createSetRegisteredYubiKeyPublicIDsOperation(
                  getStrings(subcommand, commandBuffer));

      case CLEAR_REGISTERED_YUBIKEY_PUBLIC_IDS:
        return PasswordPolicyStateOperation.
             createClearRegisteredYubiKeyPublicIDsOperation();

      case GET_HAS_STATIC_PASSWORD:
        return PasswordPolicyStateOperation.createHasStaticPasswordOperation();

      case GET_LAST_BIND_PASSWORD_VALIDATION_TIME:
        return PasswordPolicyStateOperation.
             createGetLastBindPasswordValidationTimeOperation();

      case GET_SECONDS_SINCE_LAST_BIND_PASSWORD_VALIDATION:
        return PasswordPolicyStateOperation.
             createGetSecondsSinceLastBindPasswordValidationOperation();

      case SET_LAST_BIND_PASSWORD_VALIDATION_TIME:
        return PasswordPolicyStateOperation.
             createSetLastBindPasswordValidationTimeOperation(
                  getDate(subcommand, commandBuffer));

      case CLEAR_LAST_BIND_PASSWORD_VALIDATION_TIME:
        return PasswordPolicyStateOperation.
             createClearLastBindPasswordValidationTimeOperation();

      case GET_ACCOUNT_IS_VALIDATION_LOCKED:
        return PasswordPolicyStateOperation.
             createGetAccountIsValidationLockedOperation();

      case SET_ACCOUNT_IS_VALIDATION_LOCKED:
        return PasswordPolicyStateOperation.
             createSetAccountIsValidationLockedOperation(
                  getBoolean(subcommand, commandBuffer));

      case GET_RECENT_LOGIN_HISTORY:
        return PasswordPolicyStateOperation.
             createGetRecentLoginHistoryOperation();

      case CLEAR_RECENT_LOGIN_HISTORY:
        return PasswordPolicyStateOperation.
             createClearRecentLoginHistoryOperation();

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
  private static boolean getBoolean(@NotNull final SubCommand subcommand,
                                    @NotNull final StringBuilder commandBuffer)
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
  @NotNull()
  private static Date getDate(@NotNull final SubCommand subcommand,
                              @NotNull final StringBuilder commandBuffer)
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
  @NotNull()
  private static Date[] getDates(@NotNull final SubCommand subcommand,
                                 @NotNull final StringBuilder commandBuffer)
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
  @NotNull()
  private static String getString(@NotNull final SubCommand subcommand,
                                  @NotNull final StringBuilder commandBuffer)
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
  @NotNull()
  private static String[] getStrings(@NotNull final SubCommand subcommand,
                                     @NotNull final StringBuilder commandBuffer)
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
