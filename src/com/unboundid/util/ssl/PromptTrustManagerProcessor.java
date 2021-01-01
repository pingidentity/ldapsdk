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
package com.unboundid.util.ssl;



import java.net.InetAddress;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.unboundid.ldap.sdk.LDAPConnectionOptions;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.args.IPAddressArgumentValueValidator;
import com.unboundid.util.ssl.cert.BasicConstraintsExtension;
import com.unboundid.util.ssl.cert.CertException;
import com.unboundid.util.ssl.cert.ExtendedKeyUsageExtension;
import com.unboundid.util.ssl.cert.ExtendedKeyUsageID;
import com.unboundid.util.ssl.cert.KeyUsageExtension;
import com.unboundid.util.ssl.cert.SubjectAlternativeNameExtension;
import com.unboundid.util.ssl.cert.X509Certificate;
import com.unboundid.util.ssl.cert.X509CertificateExtension;

import static com.unboundid.util.ssl.SSLMessages.*;



/**
 * This class performs the backend processing for the
 * {@link PromptTrustManagerProcessor}.  It uses the LDAP SDK's version of the
 * {@link X509Certificate} class rather than Java's representation.
 */
final class PromptTrustManagerProcessor
{
  /**
   * Prevent this utility class from being instantiated.
   */
  private PromptTrustManagerProcessor()
  {
    // No implementation is required.
  }



  /**
   * Indicates whether the trust manager should prompt about whether to trust
   * the provided certificate chain.
   *
   * @param  cacheKey                 The key that should be used to identify
   *                                  this certificate chain in the cache.  It
   *                                  should be an all-lowercase hexadecimal
   *                                  representation of the end certificate's
   *                                  subject.
   * @param  chain                    The certificate chain to be examined.  It
   *                                  must not be {@code null} or empty.
   * @param  isServerChain            Indicates whether the provided certificate
   *                                  chain was provided by a server (if
   *                                  {@code true}) or a client (if
   *                                  {@code false}).
   * @param  examineValidityDates     Indicates whether to examine the
   *                                  certificate's validity dates in the course
   *                                  of determining about whether to prompt
   *                                  about whether to trust the given
   *                                  certificate chain.
   * @param  acceptedCertificates     A cache of the certificates that have
   *                                  already been accepted.  The entries in the
   *                                  cache will be mapped from an all-lowercase
   *                                  hex representation of a previously-trusted
   *                                  certificate's signature to a Boolean value
   *                                  that indicates whether the certificate has
   *                                  been declared trusted even if the
   *                                  certificate is outside the validity
   *                                  window.
   * @param  expectedServerAddresses  A list containing the addresses that the
   *                                  client is expected to use to connect to a
   *                                  target server.  If this is {@code null} or
   *                                  empty, then no address validation will be
   *                                  performed.  This will be ignored if
   *                                  {@code isServerChain} is {@code false}.
   *
   * @return  An object pair in which the first element is a {@code Boolean}
   *          indicating whether the trust manager should prompt about whether
   *          to trust the certificate chain, and the second element is a
   *          (possibly empty) list of warning messages about the certificate
   *          chain that should be displayed to the user if they should be
   *          prompted.
   */
  @NotNull()
  static ObjectPair<Boolean,List<String>> shouldPrompt(
              @NotNull final String cacheKey,
              @NotNull final X509Certificate[] chain,
              final boolean isServerChain,
              final boolean examineValidityDates,
              @NotNull final Map<String,Boolean> acceptedCertificates,
              @Nullable final List<String> expectedServerAddresses)
  {
    // See if any of the certificates is outside the validity window.
    boolean outsideValidityWindow = false;
    final List<String> warningMessages = new ArrayList<>(5);
    final long currentTime = System.currentTimeMillis();
    for (int i=0; i < chain.length; i++)
    {
      if (! chain[i].isWithinValidityWindow(currentTime))
      {
        outsideValidityWindow = true;

        final String identifier;
        if (i == 0)
        {
          if (isServerChain)
          {
            identifier = WARN_PROMPT_PROCESSOR_LABEL_SERVER.get();
          }
          else
          {
            identifier = WARN_PROMPT_PROCESSOR_LABEL_CLIENT.get();
          }
        }
        else
        {
          identifier = WARN_PROMPT_PROCESSOR_LABEL_ISSUER.get();
        }

        if (currentTime > chain[i].getNotAfterTime())
        {
          final long expiredSecondsAgo = Math.round(
               ((currentTime - chain[i].getNotAfterTime()) / 1000.0d));
          warningMessages.add(WARN_PROMPT_PROCESSOR_CERT_EXPIRED.get(
               identifier, String.valueOf(chain[i].getSubjectDN()),
               formatDate(chain[i].getNotAfterDate()),
               StaticUtils.secondsToHumanReadableDuration(expiredSecondsAgo)));
        }
        else
        {
          final long secondsUntilValid = Math.round(
               ((chain[i].getNotBeforeTime() - currentTime) / 1000.0d));
          warningMessages.add(WARN_PROMPT_PROCESSOR_CERT_NOT_YET_VALID.get(
               identifier, String.valueOf(chain[i].getSubjectDN()),
               formatDate(chain[i].getNotBeforeDate()),
               StaticUtils.secondsToHumanReadableDuration(
                    secondsUntilValid)));
        }
      }
    }


    // If the certificate at the head of the chain has an extended key usage
    // extension, then make sure it includes either the serverAuth usage (for a
    // server certificate) or the clientAuth usage (for a client certificate).
    SubjectAlternativeNameExtension san = null;
    for (final X509CertificateExtension extension : chain[0].getExtensions())
    {
      if (extension instanceof ExtendedKeyUsageExtension)
      {
        final ExtendedKeyUsageExtension eku =
             (ExtendedKeyUsageExtension) extension;
        if (isServerChain)
        {
          if (! eku.getKeyPurposeIDs().contains(
               ExtendedKeyUsageID.TLS_SERVER_AUTHENTICATION.getOID()))
          {
            warningMessages.add(
                 WARN_PROMPT_PROCESSOR_EKU_MISSING_SERVER_AUTH.get(
                      chain[0].getSubjectDN()));
          }
        }
        else
        {
          if (! eku.getKeyPurposeIDs().contains(
               ExtendedKeyUsageID.TLS_CLIENT_AUTHENTICATION.getOID()))
          {
            warningMessages.add(
                 WARN_PROMPT_PROCESSOR_EKU_MISSING_CLIENT_AUTH.get(
                      chain[0].getSubjectDN()));
          }
        }
      }
      else if (extension instanceof SubjectAlternativeNameExtension)
      {
        san = (SubjectAlternativeNameExtension) extension;
      }
    }


    // Validate the certificate chain.  Make sure that each certificate's
    // signature is valid, that each subsequent certificate is the issuer of the
    // previous one, and that the last certificate in the chain is self-signed.
    // If there is only one certificate in the chain and it is self-signed,
    // then warn about that.  Also validate any basic constraints and key usage
    // extensions in the issuer certificates.
    if (chain.length == 1)
    {
      if (chain[0].isSelfSigned())
      {
        warningMessages.add(WARN_PROMPT_PROCESSOR_CERT_IS_SELF_SIGNED.get());

        try
        {
          chain[0].verifySignature(chain[0]);
        }
        catch (final CertException ce)
        {
          Debug.debugException(ce);
          warningMessages.add(ce.getMessage());
        }
      }
      else
      {
        warningMessages.add(WARN_PROMPT_PROCESSOR_CHAIN_NOT_COMPLETE.get(
             chain[0].getSubjectDN()));
      }
    }
    else
    {
      for (int i=1; i < chain.length; i++)
      {
        if (chain[i].isIssuerFor(chain[i-1]))
        {
          try
          {
            chain[i-1].verifySignature(chain[i]);
          }
          catch (final CertException ce)
          {
            Debug.debugException(ce);
            warningMessages.add(ce.getMessage());
          }
        }
        else
        {
          warningMessages.add(WARN_PROMPT_PROCESSOR_CHAIN_ISSUER_MISMATCH.get(
               chain[i].getSubjectDN(), chain[i-1].getSubjectDN()));
        }


        BasicConstraintsExtension bc = null;
        KeyUsageExtension ku = null;
        for (final X509CertificateExtension extension :
             chain[i].getExtensions())
        {
          if (extension instanceof BasicConstraintsExtension)
          {
            bc = (BasicConstraintsExtension) extension;
          }
          else if (extension instanceof KeyUsageExtension)
          {
            ku = (KeyUsageExtension) extension;
          }
        }

        if (bc == null)
        {
          warningMessages.add(WARN_PROMPT_PROCESSOR_NO_BC_EXTENSION.get(
               chain[i].getSubjectDN()));
        }
        else if (! bc.isCA())
        {
          warningMessages.add(WARN_PROMPT_PROCESSOR_BC_NOT_CA.get(
               chain[i].getSubjectDN()));
        }
        else if ((bc.getPathLengthConstraint() != null) &&
             ((i-1) > bc.getPathLengthConstraint()))
        {
          if (bc.getPathLengthConstraint() == 0)
          {
            warningMessages.add(
                 WARN_PROMPT_PROCESSOR_BC_DISALLOWED_INTERMEDIATE.get(
                      chain[i].getSubjectDN()));
          }
          else
          {
            warningMessages.add(
                 WARN_PROMPT_PROCESSOR_BC_TOO_MANY_INTERMEDIATES.get(
                      chain[i].getSubjectDN(), bc.getPathLengthConstraint(),
                      (i-1)));
          }
        }

        if ((ku != null) && (! ku.isKeyCertSignBitSet()))
        {
          warningMessages.add(WARN_PROMPT_PROCESSOR_KU_NO_KEY_CERT_SIGN.get(
               chain[i].getSubjectDN()));
        }
      }

      if (chain[chain.length-1].isSelfSigned())
      {
        try
        {
          chain[chain.length-1].verifySignature(chain[chain.length-1]);
        }
        catch (final CertException ce)
        {
          Debug.debugException(ce);
          warningMessages.add(ce.getMessage());
        }
      }
      else
      {
        warningMessages.add(WARN_PROMPT_PROCESSOR_CHAIN_NOT_COMPLETE.get(
             chain[chain.length-1].getSubjectDN()));
      }
    }


    // If it is a server certificate chain, and if we have a set of expected
    // addresses, then verify that the certificate is for one of those
    // addresses.
    if (isServerChain && (expectedServerAddresses != null) &&
         (! expectedServerAddresses.isEmpty()))
    {
      // Get the CN attribute from the certificate subject.
      boolean hasAllowedAddress = false;
      final StringBuilder addressBuffer = new StringBuilder();
      for (final RDN rdn : chain[0].getSubjectDN().getRDNs())
      {
        final String[] names = rdn.getAttributeNames();
        for (int i=0; i < names.length; i++)
        {
          if (names[i].equalsIgnoreCase("cn") ||
               names[i].equalsIgnoreCase("commonName") ||
               names[i].equalsIgnoreCase("2.5.4.3"))
          {
            final String cnValue = rdn.getAttributeValues()[i];
            final String lowerCNValue = StaticUtils.toLowerCase(cnValue);
            if (isHostnameOrIPAddress(lowerCNValue))
            {
              commaAppend(addressBuffer, cnValue);
              if (isAllowedHostnameOrIPAddress(lowerCNValue,
                   expectedServerAddresses))
              {
                hasAllowedAddress = true;
                break;
              }
            }
          }
        }

        if (hasAllowedAddress)
        {
          break;
        }
      }

      // If the certificate has a subject alternative name extension, then
      // check its DNS names.
      if ((! hasAllowedAddress) && (san != null))
      {
        for (final String dnsName : san.getDNSNames())
        {
          commaAppend(addressBuffer, dnsName);
          if (isAllowedHostnameOrIPAddress(dnsName, expectedServerAddresses))
          {
            hasAllowedAddress = true;
            break;
          }
        }

        if (! hasAllowedAddress)
        {
          for (final InetAddress ipAddress : san.getIPAddresses())
          {
            commaAppend(addressBuffer, ipAddress.getHostAddress());
            if (isAllowedIPAddress(ipAddress, expectedServerAddresses))
            {
              hasAllowedAddress = true;
              break;
            }
          }
        }
      }

      if (! hasAllowedAddress)
      {
        if (addressBuffer.length() == 0)
        {
          // The certificate doesn't indicate the server with which it should be
          // used.  This isn't desirable, but we won't warn about it.
        }
        else if (addressBuffer.indexOf(",") > 0)
        {
          warningMessages.add(
               WARN_PROMPT_PROCESSOR_MULTIPLE_ADDRESSES_NOT_MATCHED.get(
                    chain[0].getSubjectDN(), addressBuffer));
        }
        else
        {
          warningMessages.add(
               WARN_PROMPT_PROCESSOR_SINGLE_ADDRESS_NOT_MATCHED.get(
                    chain[0].getSubjectDN(), addressBuffer));
        }
      }
    }


    // See if the provided certificate is in the cache.  If not, then we will
    // definitely prompt.  If the cache indicates that the certificate has been
    // accepted even outside the validity window, then we will not prompt.
    // Otherwise, we'll prompt only if the certificate is outside the validity
    // window.
    final Boolean acceptedEvenWithBadValidity =
         acceptedCertificates.get(cacheKey);
    if (acceptedEvenWithBadValidity == null)
    {
      return new ObjectPair<>(Boolean.TRUE, warningMessages);
    }
    else if (acceptedEvenWithBadValidity)
    {
      return new ObjectPair<>(Boolean.FALSE, warningMessages);
    }
    else
    {
      return new ObjectPair<>(outsideValidityWindow, warningMessages);
    }
  }



  /**
   * Retrieves a user-friendly string representation of the provided date.
   *
   * @param  d  The date to format.
   *
   * @return  The user-friendly string representation of the provided date.
   */
  @NotNull()
  static String formatDate(@NotNull final Date d)
  {
    // Example:  Sunday, January 1, 2017
    final String dateFormatString = "EEEE, MMMM d, yyyy";
    final String formattedDate =
         new SimpleDateFormat(dateFormatString).format(d);

    // Example:  12:34:56 AM CDT
    final String timeFormatString = "hh:mm:ss aa z";
    final String formattedTime =
         new SimpleDateFormat(timeFormatString).format(d);

    return WARN_PROMPT_PROCESSOR_DATE_TIME.get(formattedDate, formattedTime);
  }



  /**
   * Indicates whether the provided string appears to be a hostname or IP
   * address.  Wildcard values will be accepted.
   *
   * @param  s  The string for which to make the determination.  It should be
   *            formatted in all lowercase characters.
   *
   * @return  {@code true} if the provided string appears to be a hostname, or
   *          {@code false] if not.
   */
  static boolean isHostnameOrIPAddress(@NotNull final String s)
  {
    if (s.isEmpty())
    {
      return false;
    }

    if (IPAddressArgumentValueValidator.isValidNumericIPAddress(s))
    {
      return true;
    }

    boolean lastWasPeriod = false;
    for (int i=0; i < s.length(); i++)
    {
      final char c = s.charAt(i);
      if ((c >= 'a') && (c <= 'z'))
      {
        // This will always be allowed anywhere in the string.
        lastWasPeriod = false;
      }
      else if ((c >= '0') && (c <= '9'))
      {
        // Digits are not allowed at the beginning of the string or immediately
        // after a period.
        if ((i == 0) || lastWasPeriod)
        {
          return false;
        }

        lastWasPeriod = false;
      }
      else if (c == '.')
      {
        // Periods are not allowed at the beginning of the string or immediately
        // after another period.
        if ((i == 0) || lastWasPeriod)
        {
          return false;
        }

        lastWasPeriod = true;
      }
      else if (c == '*')
      {
        // The asterisk will only be allowed if it is the first character and if
        // it is immediately followed by a period.
        if (i > 0)
        {
          return false;
        }

        if ((s.length() == 1) || (s.charAt(1) != '.'))
        {
          return false;
        }

        lastWasPeriod = false;
      }
    }

    return (! lastWasPeriod);
  }



  /**
   * Indicates whether the provided string represents a hostname or IP address
   * that is in the set of expected addresses.
   *
   * @param  s                  The string to compare.
   * @param  expectedAddresses  The set of expected addresses
   *
   * @return  {@code true} if the provided string represents an address in the
   *          set of expected addresses, or {@code false} if not.
   */
  private static boolean isAllowedHostnameOrIPAddress(@NotNull final String s,
                              @NotNull final List<String> expectedAddresses)
  {
    if (IPAddressArgumentValueValidator.isValidNumericIPAddress(s))
    {
      final InetAddress ip;
      try
      {
        ip = LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.getByName(s);

        for (final String expectedAddress : expectedAddresses)
        {
          if (IPAddressArgumentValueValidator.isValidNumericIPAddress(
               expectedAddress))
          {
            if (ip.equals(LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
                 getByName(expectedAddress)))
            {
              return true;
            }
          }
        }
      }
      catch (final Exception e)
      {
        // This should never happen.
        Debug.debugException(e);
      }
    }

    for (final String expectedAddress : expectedAddresses)
    {
      if (s.equalsIgnoreCase(expectedAddress))
      {
        return true;
      }

      if (s.startsWith("*."))
      {
        final int periodPos = expectedAddress.indexOf('.');
        if (periodPos > 0)
        {
          final String endOfS = s.substring(2);
          final String endOfExpectedAddress =
               expectedAddress.substring(periodPos + 1);
          if (endOfS.equalsIgnoreCase(endOfExpectedAddress))
          {
            return true;
          }
        }
      }
    }

    return false;
  }



  /**
   * Indicates whether the provided address represents one that is in the set of
   * expected addresses.
   *
   * @param  a                  The address to compare.
   * @param  expectedAddresses  The set of expected addresses.
   *
   * @return  {@code true} if the provided address represents one that is in the
   *          set of expected addresses, or {@code false} if not.
   */
  private static boolean isAllowedIPAddress(@NotNull final InetAddress a,
                              @NotNull final List<String> expectedAddresses)
  {
    for (final String s : expectedAddresses)
    {
      try
      {
        if (IPAddressArgumentValueValidator.isValidNumericIPAddress(s))
        {
          if (a.equals(LDAPConnectionOptions.DEFAULT_NAME_RESOLVER.
               getByName(s)))
          {
            return true;
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }

    return false;
  }



  /**
   * Appends the provided string to the given buffer, prepending it with a
   * comma and a space if the buffer is not empty.
   *
   * @param  b  The buffer to which the string should be appended.
   * @param  s  The string to append to the buffer.
   */
  private static void commaAppend(@NotNull final StringBuilder b,
                                  @NotNull final String s)
  {
    if (b.length() > 0)
    {
      b.append(", ");
    }

    b.append(s);
  }
}
