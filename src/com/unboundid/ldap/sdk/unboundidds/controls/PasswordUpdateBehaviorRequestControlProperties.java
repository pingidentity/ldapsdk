/*
 * Copyright 2017-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2017-2021 Ping Identity Corporation
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
 * Copyright (C) 2017-2021 Ping Identity Corporation
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
package com.unboundid.ldap.sdk.unboundidds.controls;



import java.io.Serializable;

import com.unboundid.util.Mutable;
import com.unboundid.util.Nullable;
import com.unboundid.util.NotNull;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;



/**
 * This class provides a set of properties that can be used in conjunction with
 * the {@link PasswordUpdateBehaviorRequestControl}.
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
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class PasswordUpdateBehaviorRequestControlProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = -529840713192839805L;



  // Indicates whether the requester should be allowed to provide a pre-encoded
  // password.
  @Nullable private Boolean allowPreEncodedPassword;

  // Indicates whether to ignore any minimum password age configured in the
  // password policy.
  @Nullable private Boolean ignoreMinimumPasswordAge;

  // Indicates whether to skip the process of checking whether the provided
  // password matches the new current password or is in the password history.
  @Nullable private Boolean ignorePasswordHistory;

  // Indicates whether to treat the password change as a self change.
  @Nullable private Boolean isSelfChange;

  // Indicates whether to update the user's account to indicate that they must
  // change their password the next time they authenticate.
  @Nullable private Boolean mustChangePassword;

  // Indicates whether to skip password validation for the new password.
  @Nullable private Boolean skipPasswordValidation;

  // Specifies the password storage scheme to use for the new password.
  @Nullable private String passwordStorageScheme;



  /**
   * Creates a new password update behavior request control properties object
   * with none of the properties set, which will cause the server to behave as
   * if the control had not been included in the request.
   */
  public PasswordUpdateBehaviorRequestControlProperties()
  {
    isSelfChange = null;
    allowPreEncodedPassword = null;
    skipPasswordValidation = null;
    ignorePasswordHistory = null;
    ignoreMinimumPasswordAge = null;
    passwordStorageScheme = null;
    mustChangePassword = null;
  }



  /**
   * Creates a new password update behavior request control properties object
   * with the settings used for the provided password update behavior request
   * control.
   *
   * @param  control  The control to use to initialize this properties object.
   */
  public PasswordUpdateBehaviorRequestControlProperties(
              @NotNull final PasswordUpdateBehaviorRequestControl control)
  {
    isSelfChange = control.getIsSelfChange();
    allowPreEncodedPassword = control.getAllowPreEncodedPassword();
    skipPasswordValidation = control.getSkipPasswordValidation();
    ignorePasswordHistory = control.getIgnorePasswordHistory();
    ignoreMinimumPasswordAge = control.getIgnoreMinimumPasswordAge();
    passwordStorageScheme = control.getPasswordStorageScheme();
    mustChangePassword = control.getMustChangePassword();
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the server's automatic classification of the password update as a
   * self change or an administrative reset, and if so, what the overridden
   * value should be.
   *
   * @return  {@code Boolean.TRUE} if the server should treat the password
   *          update as a self change, {@code Boolean.FALSE} if the server
   *          should treat the password update as an administrative reset, or
   *          {@code null} if the server should automatically determine whether
   *          the password update is a self change or an administrative reset.
   */
  @Nullable()
  public Boolean getIsSelfChange()
  {
    return isSelfChange;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the server's automatic classification of the password update as a
   * self change or an administrative reset, and if so, what the overridden
   * value should be.
   * <BR><BR>
   * Normally, the server will consider a password update to be a self change if
   * it contains the user's current password in addition to the new password, or
   * if the user entry being updated is the entry for the authorization identity
   * for the requested operation.  Conversely, if the password change does not
   * include the target user's current password in addition to the new password,
   * and the user performing the password change doesn't own the entry being
   * updated, then it will be considered an administrative reset.  But if this
   * method is called with a value of {@code Boolean.TRUE}, then the server will
   * consider the password update to be a self change even if it would have
   * otherwise been considered an administrative reset, and if this method is
   * called with a value of {@code Boolean.FALSE}, then the server will consider
   * the password update to be an administrative reset even if it would have
   * otherwise been considered a self change.
   * <BR><BR>
   * Note that this only applies to modify requests and password modify extended
   * requests.  It does not apply to add requests, which will always be
   * considered administrative resets because a user can't change their own
   * password before their account exists in the server.  However, the password
   * update behavior request control can still be used to override the server's
   * default behavior for other properties that do apply to add operations.
   *
   * @param  isSelfChange  Specifies whether the control should override the
   *                       server's automatic classification of the password
   *                       update as a self change or an administrative reset.
   *                       If this is {@code Boolean.TRUE}, then it indicates
   *                       that the server should treat the password update as a
   *                       self change.  If this is {@code Boolean.FALSE}, then
   *                       it indicates that the server should treat the
   *                       password update as an administrative reset.  If this
   *                       is {@code null}, it indicates that the server should
   *                       automatically determine whether the password change
   *                       is a self change or an administrative reset.
   */
  public void setIsSelfChange(@Nullable final Boolean isSelfChange)
  {
    this.isSelfChange = isSelfChange;
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the value of the {@code allow-pre-encoded-passwords} configuration
   * property for the target user's password policy, and if so, what the
   * overridden value should be.
   *
   * @return  {@code Boolean.TRUE} if the server should accept a pre-encoded
   *          password in the password update even if the server's password
   *          policy configuration would normally not permit this,
   *          {@code Boolean.FALSE} if the server should reject a pre-encoded
   *          password in the password update even if the server's password
   *          policy configuration would normally accept it, or {@code null} if
   *          the password policy configuration should be used to determine
   *          whether to accept pre-encoded passwords.
   */
  @Nullable()
  public Boolean getAllowPreEncodedPassword()
  {
    return allowPreEncodedPassword;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the value of the {@code allow-pre-encoded-passwords} configuration
   * property for the target user's password policy, and if so, what the
   * overridden value should be.
   * <BR><BR>
   * Note that certain types of validation cannot be performed for new passwords
   * that are pre-encoded.  It will not be possible to invoke password
   * validators on a pre-encoded password, and it will not be possible to
   * compare the a pre-encoded new password against the current password or one
   * in the password history.  Allowing end users to provide pre-encoded
   * passwords could create a loophole in which the user could continue using
   * the same password longer than they would otherwise be permitted to because
   * they could keep changing the password to a different encoded representation
   * of the same password, or to a weaker password than the server would
   * normally allow.
   *
   * @param  allowPreEncodedPassword  Specifies whether the password update
   *                                  behavior request control should override
   *                                  the value of the
   *                                  {@code allow-pre-encoded-passwords}
   *                                  configuration property for the target
   *                                  user's password policy, and if so, what
   *                                  the overridden value should be.  If this
   *                                  is {@code Boolean.TRUE}, then the server
   *                                  will permit a pre-encoded password, even
   *                                  if it would normally reject them.  If this
   *                                  is {@code Boolean.FALSE}, then the server
   *                                  will reject a pre-encoded password, even
   *                                  if it would normally accept it.  If this
   *                                  is {@code null}, then the server will use
   *                                  the password policy configuration to
   *                                  determine whether to accept a pre-encoded
   *                                  password.
   */
  public void setAllowPreEncodedPassword(
                   @Nullable final Boolean allowPreEncodedPassword)
  {
    this.allowPreEncodedPassword = allowPreEncodedPassword;
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the server's normal behavior with regard to invoking password
   * validators for any new passwords included in the password update, and if
   * so, what the overridden behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the server should skip invoking the
   *          password validators configured in the target user's password
   *          policy validators for any new passwords included in the password
   *          update even if the server would normally perform password
   *          validation, {@code Boolean.FALSE} if the server should invoke the
   *          password validators even if it would normally skip them, or
   *          {@code null} if the password policy configuration should be used
   *          to determine whether to skip password validation.
   */
  @Nullable()
  public Boolean getSkipPasswordValidation()
  {
    return skipPasswordValidation;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the server's normal behavior with regard to invoking password
   * validators for any new passwords included in the password update, and if
   * so, what the overridden behavior should be.
   * <BR><BR>
   * Note that if password validation is to be performed, it will use the set of
   * password validators set in the target user's password policy.  It is not
   * possible to customize which validators will be used on a per-request basis.
   * <BR><BR>
   * Also note that password validation can only be performed for new passwords
   * that are not pre-encoded.  Pre-encoded passwords cannot be checked against
   * password validators or the password history.
   *
   * @param  skipPasswordValidation  Specifies whether the password update
   *                                 behavior request control should override
   *                                 the server's normal behavior with regard to
   *                                 invoking password validators for any new
   *                                 passwords included in the password update,
   *                                 and if so, what the overridden behavior
   *                                 should be.  If this is
   *                                 {@code Boolean.TRUE}, then the server will
   *                                 skip new password validation even if it
   *                                 would normally perform it.  If this is
   *                                 {@code Boolean.FALSE}, then the server will
   *                                 perform new password validation even if it
   *                                 would normally skip it.  If this is
   *                                 {@code null}, then the server will use the
   *                                 password policy configuration to determine
   *                                 whether to perform new password validation.
   */
  public void setSkipPasswordValidation(
                   @Nullable final Boolean skipPasswordValidation)
  {
    this.skipPasswordValidation = skipPasswordValidation;
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the server's normal behavior with regard to checking the password
   * history for any new passwords included in the password update, and if so,
   * what the overridden behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the server should not check to see whether
   *          any new password matches the current password or is in the user's
   *          password history even if it would normally perform that check,
   *          {@code Boolean.FALSE} if the server should check to see whether
   *          any new password matches the current or previous password even if
   *          it would normally not perform such a check, or {@code null} if the
   *          password policy configuration should be used to determine whether
   *          to ignore the password history.
   */
  @Nullable()
  public Boolean getIgnorePasswordHistory()
  {
    return ignorePasswordHistory;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the server's normal behavior with regard to checking the password
   * history for any new passwords included in the password update, and if so,
   * what the overridden behavior should be.
   * <BR><BR>
   * Note that if the target user's password policy is not configured to
   * maintain a password history, then there may not be any previous passwords
   * to check.  In that case, overriding the behavior to check the password
   * history will only compare the new password against the current password.
   * <BR><BR>
   * Also note that this setting only applies to the validation of the new
   * password.  It will not affect the server's behavior with regard to storing
   * the new or previous password in the password history.
   * <BR><BR>
   * Finally, password history validation can only be performed for new
   * passwords that are not pre-encoded.  Pre-encoded passwords cannot be
   * checked against password validators or the password history.
   *
   * @param  ignorePasswordHistory  Specifies whether the password update
   *                                behavior request control should override the
   *                                server's normal behavior with regard to
   *                                checking the password history for any new
   *                                passwords included in the password update,
   *                                and if so, what the overridden behavior
   *                                should be.  If this is {@code Boolean.TRUE},
   *                                then the server will skip password history
   *                                validation even if it would have normally
   *                                performed it.  If this is
   *                                {@code Boolean.FALSE}, then the server will
   *                                perform password history validation even if
   *                                it would have normally skipped it.  If this
   *                                is {@code null}, then the server will use
   *                                the password policy configuration to
   *                                determine whether to perform password
   *                                history validation.
   */
  public void setIgnorePasswordHistory(
                   @Nullable final Boolean ignorePasswordHistory)
  {
    this.ignorePasswordHistory = ignorePasswordHistory;
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the server's normal behavior with regard to checking the
   * minimum password age, and if so, what the overridden behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the server should accept the password
   *          change even if it has been less than the configured minimum
   *          password age since the password was last changed,
   *          {@code Boolean.FALSE} if the server should reject the password
   *          change if it has been less than teh configured minimum password
   *          age, or {@code null} if the password policy configuration should
   *          be used to determine the appropriate behavior.
   */
  @Nullable()
  public Boolean getIgnoreMinimumPasswordAge()
  {
    return ignoreMinimumPasswordAge;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the server's normal behavior with regard to checking the
   * minimum password age, and if so, what the overridden behavior should be.
   * <BR><BR>
   * Normally, if a minimum password age is configured, then it will apply only
   * for self password changes but not for administrative resets.  With this
   * value set to {@code Boolean.TRUE}, then the configured minimum password
   * age will be ignored even for self changes.  With this value set to
   * {@code Boolean.FALSE}, then the configured minimum password age will be
   * enforced even for administrative resets.  In any case, this will only be
   * used if the target user's password policy is configured with a nonzero
   * minimum password age.
   *
   * @param  ignoreMinimumPasswordAge  Specifies whether the password update
   *                                   behavior request control should override
   *                                   the server's normal behavior with regard
   *                                   to checking the minimum password age, and
   *                                   if so, what the overridden behavior
   *                                   should be.  If this is
   *                                   {@code Boolean.TRUE}, then the minimum
   *                                   password age will not be enforced, even
   *                                   for self password changes.  If this is
   *                                   {@code Boolean.FALSE}, then the minimum
   *                                   password age will be enforced, even for
   *                                   administrative resets.  If this is
   *                                   {@code null}, then the server's default
   *                                   behavior will be used so that the minimum
   *                                   password age will be enforced for self
   *                                   changes but not for administrative
   *                                   resets.
   */
  public void setIgnoreMinimumPasswordAge(
                   @Nullable final Boolean ignoreMinimumPasswordAge)
  {
    this.ignoreMinimumPasswordAge = ignoreMinimumPasswordAge;
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the server's normal behavior with regard to selecting the password
   * storage scheme to use to encode new password values, and if so, which
   * password storage scheme should be used.
   *
   * @return  The name of the password storage scheme that should be used to
   *          encode any new password values, or {@code null} if the target
   *          user's password policy configuration should determine the
   *          appropriate schemes for encoding new passwords.
   */
  @Nullable()
  public String getPasswordStorageScheme()
  {
    return passwordStorageScheme;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the server's normal behavior with regard to selecting the password
   * storage scheme to use to encode new password values, and if so, which
   * password storage scheme should be used.
   * <BR><BR>
   * If a non-{@code null} password storage scheme name is provided, then it
   * must be the prefix used in front of passwords encoded with that scheme,
   * optionally including or omitting the curly braces.  The specified scheme
   * must be enabled for use in the server but does not otherwise need to be
   * associated with the target user's password policy.
   *
   * @param  passwordStorageScheme  The name of the password storage scheme that
   *                                should be used to encode any new password
   *                                values.  It may optionally be enclosed in
   *                                curly braces.  It may be {@code null} if the
   *                                password policy configuration should be used
   *                                to determine which password storage schemes
   *                                should be used to encode new passwords.
   */
  public void setPasswordStorageScheme(
                   @Nullable final String passwordStorageScheme)
  {
    this.passwordStorageScheme = passwordStorageScheme;
  }



  /**
   * Indicates whether the password update behavior request control should
   * override the server's normal behavior with regard to requiring a password
   * change, and if so, what that behavior should be.
   *
   * @return  {@code Boolean.TRUE} if the user will be required to change their
   *          password before being allowed to perform any other operation,
   *          {@code Boolean.FALSE} if the user will not be required to change
   *          their password before being allowed to perform any other
   *          operation, or {@code null} if the password policy configuration
   *          should be used to control this behavior.
   */
  @Nullable()
  public Boolean getMustChangePassword()
  {
    return mustChangePassword;
  }



  /**
   * Specifies whether the password update behavior request control should
   * override the server's normal behavior with regard to requiring a password
   * change, and if so, what that behavior should be.
   * <BR><BR>
   * Note that the "must change password" behavior will only be enforced if the
   * target user's password policy is configured with either
   * {@code force-change-on-add} or {@code force-change-on-reset} set to
   * {@code true}.  If both of those properties are set to {@code false}, then
   * this method will have no effect.
   * <BR><BR>
   * Normally, if {@code force-change-on-reset} is {@code true}, then the server
   * will put the user's account into a "must change password" state after an
   * administrative password reset, but not after a self change.  If this
   * method is called with a value of {@code Boolean.TRUE}, then the "must
   * change password" flag will be set, even if the password update is a self
   * change.  It this method is called with a value of {@code Boolean.FALSE},
   * then the "must change password" flag will not be set even if the password
   * update is an administrative change.  If this method is called with a value
   * of {@code null}, then the server's normal logic will be used to determine
   * whether to set the "must change password" flag.
   *
   * @param  mustChangePassword  Specifies whether the password update behavior
   *                             request control should override the server's
   *                             normal behavior with regard to requiring a
   *                             password change, and if so, what that behavior
   *                             should be.  If this is {@code Boolean.TRUE},
   *                             then the user entry will be required to change
   *                             their password after their next login even if
   *                             this is a self change.  If this is
   *                             {@code Boolean.FALSE}, then the user will not
   *                             be required to change their password after the
   *                             next login even if this is an administrative
   *                             reset.  If this is {@code null}, then the
   *                             server's normal logic will be used to make the
   *                             determination.
   */
  public void setMustChangePassword(@Nullable final Boolean mustChangePassword)
  {
    this.mustChangePassword = mustChangePassword;
  }



  /**
   * Retrieves a string representation of this password update behavior request
   * control properties object.
   *
   * @return  A string representation of this password update behavior request
   *          control properties object.
   */
  @Override()
  @NotNull()
  public String toString()
  {
    final StringBuilder buffer = new StringBuilder();
    toString(buffer);
    return buffer.toString();
  }



  /**
   * Appends a string representation of this password update behavior request
   * control properties object to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("PasswordUpdateBehaviorRequestControlProperties(");

    boolean appended = appendNameValuePair(buffer, "isSelfChange", isSelfChange,
         false);
    appended = appendNameValuePair(buffer, "allowPreEncodedPassword",
         allowPreEncodedPassword, appended);
    appended = appendNameValuePair(buffer, "skipPasswordValidation",
         skipPasswordValidation, appended);
    appended = appendNameValuePair(buffer, "ignorePasswordHistory",
         ignorePasswordHistory, appended);
    appended = appendNameValuePair(buffer, "ignoreMinimumPasswordAge",
         ignoreMinimumPasswordAge, appended);
    appended = appendNameValuePair(buffer, "passwordStorageScheme",
         passwordStorageScheme, appended);
    appendNameValuePair(buffer, "mustChangePassword",
         mustChangePassword, appended);

    buffer.append(')');
  }



  /**
   * Appends a name-value pair to the provided buffer, if appropriate.
   *
   * @param  buffer                The buffer to which the name-value pair
   *                               should be appended.  It must not be
   *                               {@code null}.
   * @param  propertyName          The name for the property to consider
   *                               appending.  It must not be {@code null}.
   * @param  propertyValue         The value for the property to consider
   *                               appending.  It may be {@code null} if the
   *                               name-value pair should not be appended.  If
   *                               it is non-{@code null}, then it must have a
   *                               type of {@code Boolean} or {@code String}.
   * @param  appendedPreviousPair  Indicates whether a previous name-value pair
   *                               has already been appended to the buffer.  If
   *                               the provided name-value pair should not be
   *                               appended, then this will be returned.  If the
   *                               provided name-value pair should be appended,
   *                               then this will be used to indicate whether it
   *                               should be preceded by a comma.
   *
   * @return  {@code true} if this or a previous name-value pair has been
   *          appended to the buffer, or {@code false} if no name-value pair has
   *          yet been appended to the buffer.
   */
  private static boolean appendNameValuePair(
               @NotNull final StringBuilder buffer,
               @NotNull final String propertyName,
               @Nullable final Object propertyValue,
               final boolean appendedPreviousPair)
  {
    if (propertyValue == null)
    {
      return appendedPreviousPair;
    }

    if (appendedPreviousPair)
    {
      buffer.append(", ");
    }

    buffer.append(propertyName);
    buffer.append('=');

    if (propertyValue instanceof Boolean)
    {
      buffer.append(((Boolean) propertyValue).booleanValue());
    }
    else
    {
      buffer.append('"');
      buffer.append(propertyValue);
      buffer.append('"');
    }

    return true;
  }
}
