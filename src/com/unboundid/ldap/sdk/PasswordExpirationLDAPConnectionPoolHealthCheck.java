/*
 * Copyright 2015-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2015-2021 Ping Identity Corporation
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
 * Copyright (C) 2015-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk;



import java.io.OutputStream;
import java.io.Writer;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.sdk.controls.PasswordExpiredControl;
import com.unboundid.ldap.sdk.controls.PasswordExpiringControl;
import com.unboundid.ldap.sdk.experimental.
            DraftBeheraLDAPPasswordPolicy10ResponseControl;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.LDAPMessages.*;



/**
 * This class provides an {@link LDAPConnectionPoolHealthCheck} implementation
 * that may be used to output a warning message about a password expiration that
 * has occurred or is about to occur.  It examines a bind result to see if it
 * includes a {@link PasswordExpiringControl}, a {@link PasswordExpiredControl},
 * or a {@link DraftBeheraLDAPPasswordPolicy10ResponseControl} that might
 * indicate that the user's password is about to expire, has already expired, or
 * is in a state that requires the user to change the password before they will
 * be allowed to perform any other operation.  In the event of a warning about
 * an upcoming problem, the health check may write a message to a given
 * {@code OutputStream} or {@code Writer}.  In the event of a problem that will
 * interfere with connection use, it will throw an exception to indicate that
 * the connection is not valid.
 */
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
public final class PasswordExpirationLDAPConnectionPoolHealthCheck
       extends LDAPConnectionPoolHealthCheck
{
  // The time that the last expiration warning message was written.
  @NotNull private final AtomicLong lastWarningTime = new AtomicLong(0L);

  // The length of time in milliseconds that should elapse between warning
  // messages about a potential upcoming problem.
  @Nullable private final Long millisBetweenRepeatWarnings;

  // The output stream to which the expiration message will be written, if
  // provided.
  @Nullable private final OutputStream outputStream;

  // The writer to which the expiration message will be written, if provided.
  @Nullable private final Writer writer;



  /**
   * Creates a new instance of this health check that will throw an exception
   * for any password policy-related warnings or errors encountered.
   */
  public PasswordExpirationLDAPConnectionPoolHealthCheck()
  {
    this(null, null, null);
  }



  /**
   * Creates a new instance of this health check that will write any password
   * policy-related warning message to the provided {@code OutputStream}.  It
   * will only write the first warning and will suppress all subsequent
   * warnings.  It will throw an exception for any password policy-related
   * errors encountered.
   *
   * @param  outputStream  The output stream to which a warning message should
   *                       be written.
   */
  public PasswordExpirationLDAPConnectionPoolHealthCheck(
              @Nullable final OutputStream outputStream)
  {
    this(outputStream, null, null);
  }



  /**
   * Creates a new instance of this health check that will write any password
   * policy-related warning message to the provided {@code Writer}.  It will
   * only write the first warning and will suppress all subsequent warnings.  It
   * will throw an exception for any password policy-related errors encountered.
   *
   * @param  writer  The writer to which a warning message should be written.
   */
  public PasswordExpirationLDAPConnectionPoolHealthCheck(
              @Nullable final Writer writer)
  {
    this(null, writer, null);
  }



  /**
   * Creates a new instance of this health check that will write any password
   * policy-related warning messages to the provided {@code OutputStream}.  It
   * may write or suppress some or all subsequent warnings.  It will throw an
   * exception for any password-policy related errors encountered.
   *
   * @param  outputStream                 The output stream to which warning
   *                                      messages should be written.
   * @param  millisBetweenRepeatWarnings  The minimum length of time in
   *                                      milliseconds that should be allowed to
   *                                      elapse between repeat warning
   *                                      messages.  A value that is less than
   *                                      or equal to zero indicates that all
   *                                      warning messages should always be
   *                                      written.  A positive value indicates
   *                                      that some warning messages may be
   *                                      suppressed if they are encountered too
   *                                      soon after writing a previous warning.
   *                                      A value of {@code null} indicates that
   *                                      only the first warning message should
   *                                      be written and all subsequent warnings
   *                                      should be suppressed.
   */
  public PasswordExpirationLDAPConnectionPoolHealthCheck(
              @Nullable final OutputStream outputStream,
              @Nullable final Long millisBetweenRepeatWarnings)
  {
    this(outputStream, null, millisBetweenRepeatWarnings);
  }



  /**
   * Creates a new instance of this health check that will write any password
   * policy-related warning messages to the provided {@code OutputStream}.  It
   * may write or suppress some or all subsequent warnings.  It will throw an
   * exception for any password-policy related errors encountered.
   *
   * @param  writer                       The writer to which warning messages
   *                                      should be written.
   * @param  millisBetweenRepeatWarnings  The minimum length of time in
   *                                      milliseconds that should be allowed to
   *                                      elapse between repeat warning
   *                                      messages.  A value that is less than
   *                                      or equal to zero indicates that all
   *                                      warning messages should always be
   *                                      written.  A positive value indicates
   *                                      that some warning messages may be
   *                                      suppressed if they are encountered too
   *                                      soon after writing a previous warning.
   *                                      A value of {@code null} indicates that
   *                                      only the first warning message should
   *                                      be written and all subsequent warnings
   *                                      should be suppressed.
   */
  public PasswordExpirationLDAPConnectionPoolHealthCheck(
              @Nullable final Writer writer,
              @Nullable final Long millisBetweenRepeatWarnings)
  {
    this(null, writer, millisBetweenRepeatWarnings);
  }



  /**
   * Creates a new instance of this health check that may behave in a variety of
   * ways.  All password policy-related errors will always result in an
   * exception.  If both the {@code outputStream} and {@code writer} arguments
   * are {@code null}, then all password policy-related warnings will also
   * result in exceptions.  If either the {@code outputStream} or {@code writer}
   * is non-{@code null}, then warning messages may be written to that target.
   *
   * @param  outputStream                 The output stream to which warning
   *                                      messages should be written.
   * @param  writer                       The writer to which warning messages
   *                                      should be written.
   * @param  millisBetweenRepeatWarnings  The minimum length of time in
   *                                      milliseconds that should be allowed to
   *                                      elapse between repeat warning
   *                                      messages.  A value that is less than
   *                                      or equal to zero indicates that all
   *                                      warning messages should always be
   *                                      written.  A positive value indicates
   *                                      that some warning messages may be
   *                                      suppressed if they are encountered too
   *                                      soon after writing a previous warning.
   *                                      A value of {@code null} indicates that
   *                                      only the first warning message should
   *                                      be written and all subsequent warnings
   *                                      should be suppressed.
   */
  private PasswordExpirationLDAPConnectionPoolHealthCheck(
               @Nullable final OutputStream outputStream,
               @Nullable final Writer writer,
               @Nullable final Long millisBetweenRepeatWarnings)
  {
    this.outputStream                = outputStream;
    this.writer                      = writer;
    this.millisBetweenRepeatWarnings = millisBetweenRepeatWarnings;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void ensureConnectionValidAfterAuthentication(
                   @NotNull final LDAPConnection connection,
                   @NotNull final BindResult bindResult)
         throws LDAPException
  {
    // See if the bind result includes a password expired control.  This will
    // always result in an exception.
    final PasswordExpiredControl expiredControl =
         PasswordExpiredControl.get(bindResult);
    if (expiredControl != null)
    {
      // NOTE:  Some directory servers use this control for a dual purpose.  If
      // the bind result has a non-success result code, then it indicates that
      // the user's password is expired in the traditional sense.  However, if
      // the bind result includes this control with a result code of success,
      // then that will be taken to mean that the authentication was successful
      // but that the user must change their password before they will be
      // allowed to perform any other kind of operation.  We'll throw an
      // exception either way, but will use a different message for each
      // situation.
      if (bindResult.getResultCode() == ResultCode.SUCCESS)
      {
        throw new LDAPException(ResultCode.ADMIN_LIMIT_EXCEEDED,
             ERR_PW_EXP_WITH_SUCCESS.get());
      }
      else
      {
        if (bindResult.getDiagnosticMessage() == null)
        {
          throw new LDAPException(bindResult.getResultCode(),
               ERR_PW_EXP_WITH_FAILURE_NO_MSG.get());
        }
        else
        {
          throw new LDAPException(bindResult.getResultCode(),
               ERR_PW_EXP_WITH_FAILURE_WITH_MSG.get(
                    bindResult.getDiagnosticMessage()));
        }
      }
    }


    // See if the bind result includes a password policy response control that
    // indicates an error condition.  If so, then we will always throw an
    // exception as a result of that.
    final DraftBeheraLDAPPasswordPolicy10ResponseControl pwPolicyControl =
         DraftBeheraLDAPPasswordPolicy10ResponseControl.get(bindResult);
    if ((pwPolicyControl != null) && (pwPolicyControl.getErrorType() != null))
    {
      final ResultCode resultCode;
      if (bindResult.getResultCode() == ResultCode.SUCCESS)
      {
        resultCode = ResultCode.ADMIN_LIMIT_EXCEEDED;
      }
      else
      {
        resultCode = bindResult.getResultCode();
      }

      final String message;
      if (bindResult.getDiagnosticMessage() == null)
      {
        message = ERR_PW_POLICY_ERROR_NO_MSG.get(
             pwPolicyControl.getErrorType().toString());
      }
      else
      {
        message = ERR_PW_POLICY_ERROR_WITH_MSG.get(
             pwPolicyControl.getErrorType().toString(),
             bindResult.getDiagnosticMessage());
      }

      throw new LDAPException(resultCode, message);
    }


    // If we've gotten to this point, then we know that there can only possibly
    // be a warning.  If we know that we're going to suppress any subsequent
    // warning, then there's no point in continuing.
    if (millisBetweenRepeatWarnings == null)
    {
      if (! lastWarningTime.compareAndSet(0L, System.currentTimeMillis()))
      {
        return;
      }
    }
    else if (millisBetweenRepeatWarnings > 0L)
    {
      final long millisSinceLastWarning =
           System.currentTimeMillis() - lastWarningTime.get();
      if (millisSinceLastWarning < millisBetweenRepeatWarnings)
      {
        return;
      }
    }


    // If there was a password policy response control that didn't have an
    // error condition but did have a warning condition, then handle that.
    String message = null;
    if ((pwPolicyControl != null) && (pwPolicyControl.getWarningType() != null))
    {
      switch (pwPolicyControl.getWarningType())
      {
        case TIME_BEFORE_EXPIRATION:
          message = WARN_PW_EXPIRING.get(
               StaticUtils.secondsToHumanReadableDuration(
                    pwPolicyControl.getWarningValue()));
          break;
        case GRACE_LOGINS_REMAINING:
          message = WARN_PW_POLICY_GRACE_LOGIN.get(
               pwPolicyControl.getWarningValue());
          break;
      }
    }


    // See if the bind result includes a password expiring control.
    final PasswordExpiringControl expiringControl =
         PasswordExpiringControl.get(bindResult);
    if ((message == null) && (expiringControl != null))
    {
      message = WARN_PW_EXPIRING.get(
           StaticUtils.secondsToHumanReadableDuration(
                expiringControl.getSecondsUntilExpiration()));
    }

    if (message != null)
    {
      warn(message);
    }
  }



  /**
   * Handles the provided warning message as appropriate.  It will be written to
   * the output stream, to the error stream, or thrown as an exception.
   *
   * @param  message  The warning message to be handled.
   *
   * @throws  LDAPException  If the warning should be treated as an error.
   */
  private void warn(@NotNull final String message)
          throws LDAPException
  {
    if (outputStream != null)
    {
      try
      {
        outputStream.write(StaticUtils.getBytes(message + StaticUtils.EOL));
        outputStream.flush();
        lastWarningTime.set(System.currentTimeMillis());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
    else if (writer != null)
    {
      try
      {
        writer.write(message + StaticUtils.EOL);
        writer.flush();
        lastWarningTime.set(System.currentTimeMillis());
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }
    else
    {
      lastWarningTime.set(System.currentTimeMillis());
      throw new LDAPException(ResultCode.ADMIN_LIMIT_EXCEEDED, message);
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("WarnAboutPasswordExpirationLDAPConnectionPoolHealthCheck(");
    buffer.append("throwExceptionOnWarning=");
    buffer.append((outputStream == null) && (writer == null));

    if (millisBetweenRepeatWarnings == null)
    {
      buffer.append(", suppressSubsequentWarnings=true");
    }
    else if (millisBetweenRepeatWarnings > 0L)
    {
      buffer.append(", millisBetweenRepeatWarnings=");
      buffer.append(millisBetweenRepeatWarnings);
    }
    else
    {
      buffer.append(", suppressSubsequentWarnings=false");
    }

    buffer.append(')');
  }
}
