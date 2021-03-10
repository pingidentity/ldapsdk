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



import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.Entry;
import com.unboundid.ldap.sdk.RDN;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReaderEntryTranslator;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CryptoHelper;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides the base class for all LDIF reader entry translators that
 * will be used to determine where an entry should be written.
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
@ThreadSafety(level=ThreadSafetyLevel.COMPLETELY_THREADSAFE)
abstract class SplitLDIFTranslator
         implements LDIFReaderEntryTranslator
{
  // The split base DN.
  @NotNull private final DN splitBaseDN;

  // The RDNs that comprise the split base DN.
  @NotNull private final RDN[] splitBaseRDNs;

  // The sets in which entries should be placed if an error occurs.
  @NotNull private final Set<String> errorSetNames;

  // A set of thread-local buffers to use to encode entries.
  @NotNull private final ThreadLocal<ByteStringBuffer> ldifBuffers;

  // A set of thread-local MD5 message digest generators.
  @NotNull private final ThreadLocal<MessageDigest> messageDigests;



  /**
   * Creates a new instance of this translator.
   *
   * @param  splitBaseDN  The base DN below which entries are to be split.  It
   *                      must not be {@code null}.
   */
  SplitLDIFTranslator(@NotNull final DN splitBaseDN)
  {
    this.splitBaseDN = splitBaseDN;

    splitBaseRDNs = splitBaseDN.getRDNs();
    errorSetNames = Collections.singleton(SplitLDIFEntry.SET_NAME_ERRORS);
    ldifBuffers = new ThreadLocal<>();
    messageDigests = new ThreadLocal<>();
  }



  /**
   * Retrieves the base DN below which entries are to be split.
   *
   * @return  The base DN below which entries are to be split.
   */
  @NotNull()
  final DN getSplitBaseDN()
  {
    return splitBaseDN;
  }



  /**
   * Retrieves an array of the RDN components that comprise the split base DN.
   *
   * @return  An array of the RDN components that comprise the split base DN.
   */
  @NotNull()
  final RDN[] getSplitBaseRDNs()
  {
    return splitBaseRDNs;
  }



  /**
   * Retrieves the set that should be used for SplitLDIF entries for which an
   * error was encountered during processing.
   *
   * @return  The set that should be used for SplitLDIF entries for which an
   *          error was encountered during processing.
   */
  @NotNull()
  final Set<String> getErrorSetNames()
  {
    return errorSetNames;
  }



  /**
   * Retrieves a thread-local MD5 digest generator.
   *
   * @return  A thread-local MD5 digest generator.
   *
   * @throws  NoSuchAlgorithmException  If the JVM doesn't support MD5.  This
   *                                    should never happen.
   */
  @NotNull()
  MessageDigest getMD5()
                throws NoSuchAlgorithmException
  {
    MessageDigest md5 = messageDigests.get();
    if (md5 == null)
    {
      md5 = CryptoHelper.getMessageDigest("MD5");
      messageDigests.set(md5);
    }

    return md5;
  }



  /**
   * Returns a SplitLDIF entry that contains the bytes of the encoded
   * representation of the provided entry and indicates that it should be
   * written to the provided sets.
   *
   * @param  e     The entry to be processed.
   * @param  sets  The sets to which the entry should be written.  It may be
   *               {@code null} if the collection of target sets has not yet
   *               been determined.
   *
   * @return  The SplitLDIF entry that was created.
   */
  @NotNull()
  SplitLDIFEntry createEntry(@NotNull final Entry e,
                             @NotNull final Set<String> sets)
  {
    return createEntry(e, null, sets);
  }



  /**
   * Returns a SplitLDIF entry that contains the bytes of the encoded
   * representation of the provided entry and indicates that it should be
   * written to the provided sets.
   *
   * @param  e        The entry to be processed.
   * @param  comment  An optional comment to include before the LDIF
   *                  representation of the entry.  It may be {@code null} if no
   *                  comment is needed.
   * @param  sets     The sets to which the entry should be written.  It may be
   *                  {@code null} if the collection of target sets has not yet
   *                  been determined.
   *
   * @return  The SplitLDIF entry that was created.
   */
  @NotNull()
  SplitLDIFEntry createEntry(@NotNull final Entry e,
                             @Nullable final String comment,
                             @NotNull final Set<String> sets)
  {
    // Get a byte string buffer to use when encoding the entry to LDIF.
    // Get a buffer to use during the encoding process.
    ByteStringBuffer buffer = ldifBuffers.get();
    if (buffer == null)
    {
      buffer = new ByteStringBuffer();
      ldifBuffers.set(buffer);
    }
    else
    {
      buffer.clear();
    }


    // If there is a comment, add it to the buffer.
    if (comment != null)
    {
      buffer.append("# ");
      buffer.append(comment);
      buffer.append(StaticUtils.EOL_BYTES);
    }


    // Add the LDIF representation of the entry to the buffer, and follow it
    // with a blank line.
    e.toLDIF(buffer, 0);
    buffer.append(StaticUtils.EOL_BYTES);


    // Return the appropriate SplitLDIFEntry object that encapsulates all of the
    // necessary information.
    return new SplitLDIFEntry(e, buffer.toByteArray(), sets);
  }



  /**
   * Creates a split LDIF entry that will be placed into an appropriate set
   * by computing a hash on the DN component that is immediately below the split
   * base DN.
   *
   * @param  e         The entry to process.  It must not be {@code null}, and
   *                   it must be a descendant of the
   * @param  dn        The parsed DN of the provided entry.  It must not be
   *                   {@code null}.
   * @param  setNames  The
   *
   * @return  The SplitLDIF entry that was created.
   */
  @NotNull()
  SplitLDIFEntry createFromRDNHash(@NotNull final Entry e,
                      @NotNull final DN dn,
                      @NotNull final Map<Integer,Set<String>> setNames)
  {
    // Determine which RDN should be used to generate the checksum and get the
    // bytes that comprise the normalized representation of that RDN.
    final RDN[] rdns = dn.getRDNs();
    final int targetRDNIndex = rdns.length - splitBaseRDNs.length - 1;
    final byte[] normalizedRDNBytes =
         StaticUtils.getBytes(rdns[targetRDNIndex].toNormalizedString());


    // Get an MD5 digest generator.
    final MessageDigest md5Digest;
    try
    {
      md5Digest = getMD5();
    }
    catch (final Exception ex)
    {
      // This should never happen.
      Debug.debugException(ex);
      return createEntry(e,
           ERR_SPLIT_LDIF_TRANSLATOR_CANNOT_GET_MD5.get(
                StaticUtils.getExceptionMessage(ex)),
           errorSetNames);
    }


    // Generate an MD5 digest for the normalized RDN, and use the first four
    // bytes of the MD5 digest to compute an integer checksum (but don't use the
    // most significant bit of the first byte to avoid the possibility of a
    // negative number).  Then use a modulus operation to convert that checksum
    // into a value that we can use to get the corresponding set names.
    final byte[] md5Bytes = md5Digest.digest(normalizedRDNBytes);
    final int checksum =
         ((md5Bytes[0] & 0x7F) << 24) |
         ((md5Bytes[1] & 0xFF) << 16) |
         ((md5Bytes[2] & 0xFF) << 8) |
         (md5Bytes[3] & 0xFF);
    final int setNumber = checksum % setNames.size();


    // Create and return the processed entry with the appropriate mapping.
    return createEntry(e, setNames.get(setNumber));
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public abstract SplitLDIFEntry translate(@NotNull Entry original,
                                           long firstLineNumber)
         throws LDIFException;
}
