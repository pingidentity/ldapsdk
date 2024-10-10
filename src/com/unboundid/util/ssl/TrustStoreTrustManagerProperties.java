/*
 * Copyright 2024 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2024 Ping Identity Corporation
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
 * Copyright (C) 2024 Ping Identity Corporation
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
package com.unboundid.util.ssl;



import java.io.File;
import java.io.Serializable;
import java.security.Provider;

import com.unboundid.util.Mutable;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.Validator;



/**
 * This class provides a data structure with information about properties to
 * use when accessing the {@link TrustStoreTrustManager}.
 */
@Mutable()
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class TrustStoreTrustManagerProperties
       implements Serializable
{
  /**
   * The serial version UID for this serializable class.
   */
  private static final long serialVersionUID = 4782995125532803023L;



  // Indicates whether to allow accessing a non-FIPS-compliant trust store
  // when running in FIPS-compliant mode.
  private boolean allowNonFIPSInFIPSMode;

  // Indicates whether to reject certificates if the current time is outside
  // the validity window for the certificate chain.
  private boolean examineValidityDates;

  // The PIN needed to access the contents of the trust store.
  @Nullable private char[] trustStorePIN;

  // The security provider to use to access the trust store.
  @Nullable private Provider provider;

  // The path to the trust store file.
  @NotNull private String trustStorePath;

  // The format to use for the trust store file.
  @Nullable private String trustStoreFormat;



  /**
   * Creates a new set of trust manage provider properties for the specified
   * trust store file.
   *
   * @param  trustStoreFile  The target trust store file.  It must not be
   *                         {@code null}.
   */
  public TrustStoreTrustManagerProperties(@NotNull final File trustStoreFile)
  {
    this(trustStoreFile.getAbsolutePath());
  }



  /**
   * Creates a new set of trust manage provider properties for the specified
   * trust store file.
   *
   * @param  trustStorePath  The path to the target trust store file.  It must
   *                         not be {@code null}.
   */
  public TrustStoreTrustManagerProperties(@NotNull final String trustStorePath)
  {
    Validator.ensureNotNull(trustStorePath);

    this.trustStorePath = trustStorePath;

    trustStorePIN = null;
    trustStoreFormat = null;
    provider = null;
    examineValidityDates = true;
    allowNonFIPSInFIPSMode = false;
  }



  /**
   * Retrieves the path to the target trust store file.
   *
   * @return  The path to the target trust store file.
   */
  @NotNull()
  public String getTrustStorePath()
  {
    return trustStorePath;
  }



  /**
   * Specifies the target trust store file.
   *
   * @param  trustStoreFile  The target trust store file.  It must not be
   *                         {@code null}.
   */
  public void setTrustStoreFile(@NotNull final File trustStoreFile)
  {
    Validator.ensureNotNull(trustStoreFile);
    trustStorePath = trustStoreFile.getAbsolutePath();
  }



  /**
   * Specifies the path to the target trust store file.
   *
   * @param  trustStorePath  The path to the target trust store file.  It must
   *                         not be {@code null}.
   */
  public void setTrustStorePath(@NotNull final String trustStorePath)
  {
    Validator.ensureNotNull(trustStorePath);
    this.trustStorePath = trustStorePath;
  }



  /**
   * Retrieves the PIN needed to access the contents of the trust store, if
   * specified.
   *
   * @return  The PIN needed to access the contents of the trust store, or
   *          {@code null} if none has been specified.
   */
  @Nullable()
  public char[] getTrustStorePIN()
  {
    return trustStorePIN;
  }



  /**
   * Specifies the PIN needed to access the contents of the trust store.
   *
   * @param  trustStorePIN  The PIN needed to access the contents of the trust
   *                        store.  It may be {@code null} if no PIN is needed.
   */
  public void setTrustStorePIN(@Nullable final char[] trustStorePIN)
  {
    this.trustStorePIN = trustStorePIN;
  }



  /**
   * Specifies the PIN needed to access the contents of the trust store.
   *
   * @param  trustStorePIN  The PIN needed to access the contents of the trust
   *                        store.  It may be {@code null} if no PIN is needed.
   */
  public void setTrustStorePIN(@Nullable final String trustStorePIN)
  {
    if (trustStorePIN == null)
    {
      this.trustStorePIN = null;
    }
    else
    {
      this.trustStorePIN = trustStorePIN.toCharArray();
    }

  }



  /**
   * Retrieves the format for the target trust store, if specified.
   *
   * @return  The format for the target trust store, or {@code null} if a
   *          default format should be used.
   */
  @Nullable()
  public String getTrustStoreFormat()
  {
    return trustStoreFormat;
  }



  /**
   * Specifies the format for the target trust store.
   *
   * @param  trustStoreFormat  The format for the target trust store.  It may be
   *                           {@code null} if a default format should be used.
   */
  public void setTrustStoreFormat(@Nullable final String trustStoreFormat)
  {
    this.trustStoreFormat = trustStoreFormat;
  }



  /**
   * Indicates whether to reject a presented certificate chain if the current
   * time is outside the validity window for any of the certificates in the
   * chain.
   *
   * @return  {@code true} if the trust manager should reject the certificate
   *          chain if the current time is outside the validity window for any
   *          of the certificates in the chain, or {@code false} if not.
   */
  public boolean examineValidityDates()
  {
    return examineValidityDates;
  }



  /**
   * Specifies whether to reject a presented certificate chain if the current
   * time is outside the validity window for any of the certificates in the
   * chain.
   *
   * @param  examineValidityDates  Indicates whether to reject a presented
   *                               certificate chain if the current time is
   *                               outside the validity window for any of the
   *                               certificates in the chain.
   */
  public void setExamineValidityDates(final boolean examineValidityDates)
  {
    this.examineValidityDates = examineValidityDates;
  }



  /**
   * Retrieves the security provider to use to access the trust store, if a
   * non-default provider should be used.
   *
   * @return  The security provider to use to access the trust store, or
   *          {@code null} if a default provider should be used.
   */
  @Nullable()
  public Provider getProvider()
  {
    return provider;
  }



  /**
   * Specifies the security provider to use to access the trust store.
   *
   * @param  provider  The security provider to use to access the trust store.
   *                   It may be {@code null} if a default provider should be
   *                   used.
   */
  public void setProvider(@Nullable final Provider provider)
  {
    this.provider = provider;
  }



  /**
   * Indicates whether to allow access to a non-FIPS-compliant trust store even
   * when operating in FIPS-compliant mode.
   *
   * @return  {@code true} if access to a non-FIPS-compliant trust store should
   *          be allowed even when operating in FIPS-compliant mode, or
   *          {@code false} if not.
   */
  public boolean allowNonFIPSInFIPSMode()
  {
    return allowNonFIPSInFIPSMode;
  }



  /**
   * Specifies whether to allow access to a non-FIPS-compliant trust store even
   * when operating in FIPS-compliant mode.
   *
   * @param  allowNonFIPSInFIPSMode  Indicates whether to allow access to a
   *                                 non-FIPS-compliant trust store even when
   *                                 operating in FIPS-compliant mode.
   */
  public void setAllowNonFIPSInFIPSMode(final boolean allowNonFIPSInFIPSMode)
  {
    this.allowNonFIPSInFIPSMode = allowNonFIPSInFIPSMode;
  }



  /**
   * Retrieves a string representation of these properties.
   *
   * @return  A string representation of these properties.
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
   * Appends a string representation of these properties to the provided buffer.
   *
   * @param  buffer  The buffer to which the information should be appended.
   *                 It must not be {@code null}.
   */
  public void toString(@NotNull final StringBuilder buffer)
  {
    buffer.append("TrustStoreTrustManagerProperties(trustStorePath='");
    buffer.append(trustStorePath);
    buffer.append('\'');
    buffer.append(", trustStorePINProvided=");
    buffer.append(trustStorePIN != null);

    if (trustStoreFormat != null)
    {
      buffer.append(", trustStoreFormat='");
      buffer.append(trustStoreFormat);
      buffer.append('\'');
    }

    buffer.append(", examineValidityDates=");
    buffer.append(examineValidityDates);

    if (provider != null)
    {
      buffer.append(", providerClass='");
      buffer.append(provider.getClass().getName());
      buffer.append('\'');
    }

    buffer.append(", allowNonFIPSInFIPSMode=");
    buffer.append(allowNonFIPSInFIPSMode);
    buffer.append(')');
  }
}
