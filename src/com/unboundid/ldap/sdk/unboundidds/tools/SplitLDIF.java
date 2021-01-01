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



import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.zip.GZIPOutputStream;

import com.unboundid.ldap.sdk.Filter;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.ldap.sdk.schema.Schema;
import com.unboundid.ldif.LDIFException;
import com.unboundid.ldif.LDIFReader;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.ObjectPair;
import com.unboundid.util.PassphraseEncryptedOutputStream;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.FilterArgument;
import com.unboundid.util.args.IntegerArgument;
import com.unboundid.util.args.SubCommand;
import com.unboundid.util.args.StringArgument;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides a command-line tool that can be used to split an LDIF
 * file below a specified base DN.  This can be used to help initialize an
 * entry-balancing deployment for use with the Directory Proxy Server.
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
 * <BR>
 * It supports a number of algorithms for determining how to split the data,
 * including:
 * <UL>
 *   <LI>
 *     split-using-hash-on-rdn -- The tool will compute a digest of the DN
 *     component that is immediately below the split base DN, and will use a
 *     modulus to select a backend set for a given entry.  Since the split is
 *     based purely on computation involving the DN, the there is no need for
 *     caching to ensure that children are placed in the same sets as their
 *     parent, which allows it to run effectively with a small memory footprint.
 *   </LI>
 *   <LI>
 *     split-using-hash-on-attribute -- The tool will compute a digest of the
 *     value(s) of a specified attribute, and will use a modulus to select a
 *     backend set for a given entry.  This hash will only be computed for
 *     entries immediately below the split base DN, and a cache will be used to
 *     ensure that entries more than one level below the split base DN are
 *     placed in the same backend set as their parent.
 *   </LI>
 *   <LI>
 *     split-using-fewest-entries -- When examining an entry immediately below
 *     the split base DN, the tool will place that entry in the set that has the
 *     fewest entries.  For flat DITs in which entries only exist one level
 *     below the split base DN, this will effectively ensure a round-robin
 *     distribution.  But for cases in which there are branches of varying sizes
 *     below the split base DN, this can help ensure that entries are more
 *     evenly distributed across backend sets.  A cache will be used to ensure
 *     that entries more than one level below the split base DN are placed in
 *     the same backend set as their parent.
 *   </LI>
 *   <LI>
 *     split-using-filter -- When examining an entry immediately below the split
 *     base DN, a series of filters will be evaluated against that entry, which
 *     each filter associated with a specific backend set.  If an entry doesn't
 *     match any of the provided filters, an RDN hash can be used to select the
 *     set.  A cache will be used to ensure that entries more than one level
 *     below the split base DN are placed in the same backend set as their
 *     parent.
 *   </LI>
 * </UL>
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class SplitLDIF
     extends CommandLineTool
{
  /**
   * The maximum length of any message to write to standard output or standard
   * error.
   */
  private static final int MAX_OUTPUT_LINE_LENGTH =
       StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  // The global arguments used by this tool.
  @Nullable private BooleanArgument addEntriesOutsideSplitBaseDNToAllSets =
       null;
  @Nullable private BooleanArgument addEntriesOutsideSplitBaseDNToDedicatedSet =
       null;
  @Nullable private BooleanArgument compressTarget = null;
  @Nullable private BooleanArgument encryptTarget = null;
  @Nullable private BooleanArgument sourceCompressed = null;
  @Nullable private DNArgument splitBaseDN = null;
  @Nullable private FileArgument encryptionPassphraseFile = null;
  @Nullable private FileArgument schemaPath = null;
  @Nullable private FileArgument sourceLDIF = null;
  @Nullable private FileArgument targetLDIFBasePath = null;
  @Nullable private IntegerArgument numThreads = null;

  // The arguments used to split using a hash of the RDN.
  @Nullable private IntegerArgument splitUsingHashOnRDNNumSets = null;
  @Nullable private SubCommand splitUsingHashOnRDN = null;

  // The arguments used to split using a hash on a specified attribute.
  @Nullable private BooleanArgument splitUsingHashOnAttributeAssumeFlatDIT =
       null;
  @Nullable private BooleanArgument splitUsingHashOnAttributeUseAllValues =
       null;
  @Nullable private IntegerArgument splitUsingHashOnAttributeNumSets = null;
  @Nullable private StringArgument splitUsingHashOnAttributeAttributeName =
       null;
  @Nullable private SubCommand splitUsingHashOnAttribute = null;

  // The arguments used to choose the set with the fewest entries.
  @Nullable private BooleanArgument splitUsingFewestEntriesAssumeFlatDIT = null;
  @Nullable private IntegerArgument splitUsingFewestEntriesNumSets = null;
  @Nullable private SubCommand splitUsingFewestEntries = null;

  // The arguments used to choose the set using a provided set of filters.
  @Nullable private BooleanArgument splitUsingFilterAssumeFlatDIT = null;
  @Nullable private FilterArgument splitUsingFilterFilter = null;
  @Nullable private SubCommand splitUsingFilter = null;



  /**
   * Runs the tool with the provided set of command-line arguments.
   *
   * @param  args  The command-line arguments provided to this tool.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Runs the tool with the provided set of command-line arguments.
   *
   * @param  out   The output stream used for standard output.  It may be
   *               {@code null} if standard output should be suppressed.
   * @param  err   The output stream used for standard error.  It may be
   *               {@code null} if standard error should be suppressed.
   * @param  args  The command-line arguments provided to this tool.
   *
   * @return  A result code with information about the processing performed.
   *          Any result code other than {@link ResultCode#SUCCESS} indicates
   *          that an error occurred.
   */
  @NotNull()
  public static ResultCode main(@Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final SplitLDIF tool = new SplitLDIF(out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided information.
   *
   * @param  out  The output stream used for standard output.  It may be
   *              {@code null} if standard output should be suppressed.
   * @param  err  The output stream used for standard error.  It may be
   *              {@code null} if standard error should be suppressed.
   */
  public SplitLDIF(@Nullable final OutputStream out,
                   @Nullable final OutputStream err)
  {
    super(out, err);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "split-ldif";
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return INFO_SPLIT_LDIF_TOOL_DESCRIPTION.get();
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    // Add the global arguments.
    sourceLDIF = new FileArgument('l', "sourceLDIF", true, 0, null,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_SOURCE_LDIF.get(), true, false, true,
         false);
    sourceLDIF.addLongIdentifier("inputLDIF", true);
    sourceLDIF.addLongIdentifier("source-ldif", true);
    sourceLDIF.addLongIdentifier("input-ldif", true);
    parser.addArgument(sourceLDIF);

    sourceCompressed = new BooleanArgument('C', "sourceCompressed",
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_SOURCE_COMPRESSED.get());
    sourceCompressed.addLongIdentifier("inputCompressed", true);
    sourceCompressed.addLongIdentifier("source-compressed", true);
    sourceCompressed.addLongIdentifier("input-compressed", true);
    parser.addArgument(sourceCompressed);

    targetLDIFBasePath = new FileArgument('o', "targetLDIFBasePath", false, 1,
         null, INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_TARGET_LDIF_BASE.get(), false,
         true, true, false);
    targetLDIFBasePath.addLongIdentifier("outputLDIFBasePath", true);
    targetLDIFBasePath.addLongIdentifier("target-ldif-base-path", true);
    targetLDIFBasePath.addLongIdentifier("output-ldif-base-path", true);
    parser.addArgument(targetLDIFBasePath);

    compressTarget = new BooleanArgument('c', "compressTarget",
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_COMPRESS_TARGET.get());
    compressTarget.addLongIdentifier("compressOutput", true);
    compressTarget.addLongIdentifier("compress", true);
    compressTarget.addLongIdentifier("compress-target", true);
    compressTarget.addLongIdentifier("compress-output", true);
    parser.addArgument(compressTarget);

    encryptTarget = new BooleanArgument(null, "encryptTarget",
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_ENCRYPT_TARGET.get());
    encryptTarget.addLongIdentifier("encryptOutput", true);
    encryptTarget.addLongIdentifier("encrypt", true);
    encryptTarget.addLongIdentifier("encrypt-target", true);
    encryptTarget.addLongIdentifier("encrypt-output", true);
    parser.addArgument(encryptTarget);

    encryptionPassphraseFile = new FileArgument(null,
         "encryptionPassphraseFile", false, 1, null,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_ENCRYPT_PW_FILE.get(), true, true,
         true, false);
    encryptionPassphraseFile.addLongIdentifier("encryptionPasswordFile", true);
    encryptionPassphraseFile.addLongIdentifier("encryption-passphrase-file",
         true);
    encryptionPassphraseFile.addLongIdentifier("encryption-password-file",
         true);
    parser.addArgument(encryptionPassphraseFile);

    splitBaseDN = new DNArgument('b', "splitBaseDN", true, 1, null,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_SPLIT_BASE_DN.get());
    splitBaseDN.addLongIdentifier("baseDN", true);
    splitBaseDN.addLongIdentifier("split-base-dn", true);
    splitBaseDN.addLongIdentifier("base-dn", true);
    parser.addArgument(splitBaseDN);

    addEntriesOutsideSplitBaseDNToAllSets = new BooleanArgument(null,
         "addEntriesOutsideSplitBaseDNToAllSets", 1,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_OUTSIDE_TO_ALL_SETS.get());
    addEntriesOutsideSplitBaseDNToAllSets.addLongIdentifier(
         "add-entries-outside-split-base-dn-to-all-sets", true);
    parser.addArgument(addEntriesOutsideSplitBaseDNToAllSets);

    addEntriesOutsideSplitBaseDNToDedicatedSet = new BooleanArgument(null,
         "addEntriesOutsideSplitBaseDNToDedicatedSet", 1,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_OUTSIDE_TO_DEDICATED_SET.get());
    addEntriesOutsideSplitBaseDNToDedicatedSet.addLongIdentifier(
         "add-entries-outside-split-base-dn-to-dedicated-set", true);
    parser.addArgument(addEntriesOutsideSplitBaseDNToDedicatedSet);

    schemaPath = new FileArgument(null, "schemaPath", false, 0, null,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_SCHEMA_PATH.get(), true, false, false,
         false);
    schemaPath.addLongIdentifier("schemaFile", true);
    schemaPath.addLongIdentifier("schemaDirectory", true);
    schemaPath.addLongIdentifier("schema-path", true);
    schemaPath.addLongIdentifier("schema-file", true);
    schemaPath.addLongIdentifier("schema-directory", true);
    parser.addArgument(schemaPath);

    numThreads = new IntegerArgument('t', "numThreads", false, 1, null,
         INFO_SPLIT_LDIF_GLOBAL_ARG_DESC_NUM_THREADS.get(), 1,
         Integer.MAX_VALUE, 1);
    numThreads.addLongIdentifier("num-threads", true);
    parser.addArgument(numThreads);


    // Add the subcommand used to split entries using a hash on the RDN.
    final ArgumentParser splitUsingHashOnRDNParser = new ArgumentParser(
         "split-using-hash-on-rdn", INFO_SPLIT_LDIF_SC_HASH_ON_RDN_DESC.get());

    splitUsingHashOnRDNNumSets = new IntegerArgument(null, "numSets", true, 1,
         null, INFO_SPLIT_LDIF_SC_HASH_ON_RDN_ARG_DESC_NUM_SETS.get(), 2,
         Integer.MAX_VALUE);
    splitUsingHashOnRDNNumSets.addLongIdentifier("num-sets", true);
    splitUsingHashOnRDNParser.addArgument(splitUsingHashOnRDNNumSets);

    final LinkedHashMap<String[],String> splitUsingHashOnRDNExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    splitUsingHashOnRDNExamples.put(
         new String[]
         {
           "split-using-hash-on-rdn",
           "--sourceLDIF", "whole.ldif",
           "--targetLDIFBasePath", "split.ldif",
           "--splitBaseDN", "ou=People,dc=example,dc=com",
           "--numSets", "4",
           "--schemaPath", "config/schema",
           "--addEntriesOutsideSplitBaseDNToAllSets"
         },
         INFO_SPLIT_LDIF_SC_HASH_ON_RDN_EXAMPLE.get());

    splitUsingHashOnRDN = new SubCommand("split-using-hash-on-rdn",
         INFO_SPLIT_LDIF_SC_HASH_ON_RDN_DESC.get(), splitUsingHashOnRDNParser,
         splitUsingHashOnRDNExamples);
    splitUsingHashOnRDN.addName("hash-on-rdn", true);

    parser.addSubCommand(splitUsingHashOnRDN);


    // Add the subcommand used to split entries using a hash on a specified
    // attribute.
    final ArgumentParser splitUsingHashOnAttributeParser = new ArgumentParser(
         "split-using-hash-on-attribute",
         INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_DESC.get());

    splitUsingHashOnAttributeAttributeName = new StringArgument(null,
         "attributeName", true, 1, "{attr}",
         INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_ARG_DESC_ATTR_NAME.get());
    splitUsingHashOnAttributeAttributeName.addLongIdentifier("attribute-name",
         true);
    splitUsingHashOnAttributeParser.addArgument(
         splitUsingHashOnAttributeAttributeName);

    splitUsingHashOnAttributeNumSets = new IntegerArgument(null, "numSets",
         true, 1, null, INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_ARG_DESC_NUM_SETS.get(),
         2, Integer.MAX_VALUE);
    splitUsingHashOnAttributeNumSets.addLongIdentifier("num-sets", true);
    splitUsingHashOnAttributeParser.addArgument(
         splitUsingHashOnAttributeNumSets);

    splitUsingHashOnAttributeUseAllValues = new BooleanArgument(null,
         "useAllValues", 1,
         INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_ARG_DESC_ALL_VALUES.get());
    splitUsingHashOnAttributeUseAllValues.addLongIdentifier("use-all-values",
         true);
    splitUsingHashOnAttributeParser.addArgument(
         splitUsingHashOnAttributeUseAllValues);

    splitUsingHashOnAttributeAssumeFlatDIT = new BooleanArgument(null,
         "assumeFlatDIT", 1,
         INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_ARG_DESC_ASSUME_FLAT_DIT.get());
    splitUsingHashOnAttributeAssumeFlatDIT.addLongIdentifier("assume-flat-dit",
         true);
    splitUsingHashOnAttributeParser.addArgument(
         splitUsingHashOnAttributeAssumeFlatDIT);

    final LinkedHashMap<String[],String> splitUsingHashOnAttributeExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    splitUsingHashOnAttributeExamples.put(
         new String[]
         {
           "split-using-hash-on-attribute",
           "--sourceLDIF", "whole.ldif",
           "--targetLDIFBasePath", "split.ldif",
           "--splitBaseDN", "ou=People,dc=example,dc=com",
           "--attributeName", "uid",
           "--numSets", "4",
           "--schemaPath", "config/schema",
           "--addEntriesOutsideSplitBaseDNToAllSets"
         },
         INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_EXAMPLE.get());

    splitUsingHashOnAttribute = new SubCommand("split-using-hash-on-attribute",
         INFO_SPLIT_LDIF_SC_HASH_ON_ATTR_DESC.get(),
         splitUsingHashOnAttributeParser, splitUsingHashOnAttributeExamples);
    splitUsingHashOnAttribute.addName("hash-on-attribute", true);

    parser.addSubCommand(splitUsingHashOnAttribute);


    // Add the subcommand used to split entries by selecting the set with the
    // fewest entries.
    final ArgumentParser splitUsingFewestEntriesParser = new ArgumentParser(
         "split-using-fewest-entries",
         INFO_SPLIT_LDIF_SC_FEWEST_ENTRIES_DESC.get());

    splitUsingFewestEntriesNumSets = new IntegerArgument(null, "numSets",
         true, 1, null,
         INFO_SPLIT_LDIF_SC_FEWEST_ENTRIES_ARG_DESC_NUM_SETS.get(),
         2, Integer.MAX_VALUE);
    splitUsingFewestEntriesNumSets.addLongIdentifier("num-sets", true);
    splitUsingFewestEntriesParser.addArgument(splitUsingFewestEntriesNumSets);

    splitUsingFewestEntriesAssumeFlatDIT = new BooleanArgument(null,
         "assumeFlatDIT", 1,
         INFO_SPLIT_LDIF_SC_FEWEST_ENTRIES_ARG_DESC_ASSUME_FLAT_DIT.get());
    splitUsingFewestEntriesAssumeFlatDIT.addLongIdentifier("assume-flat-dit",
         true);
    splitUsingFewestEntriesParser.addArgument(
         splitUsingFewestEntriesAssumeFlatDIT);

    final LinkedHashMap<String[],String> splitUsingFewestEntriesExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    splitUsingFewestEntriesExamples.put(
         new String[]
         {
           "split-using-fewest-entries",
           "--sourceLDIF", "whole.ldif",
           "--targetLDIFBasePath", "split.ldif",
           "--splitBaseDN", "ou=People,dc=example,dc=com",
           "--numSets", "4",
           "--schemaPath", "config/schema",
           "--addEntriesOutsideSplitBaseDNToAllSets"
         },
         INFO_SPLIT_LDIF_SC_FEWEST_ENTRIES_EXAMPLE.get());

    splitUsingFewestEntries = new SubCommand("split-using-fewest-entries",
         INFO_SPLIT_LDIF_SC_FEWEST_ENTRIES_DESC.get(),
         splitUsingFewestEntriesParser, splitUsingFewestEntriesExamples);
    splitUsingFewestEntries.addName("fewest-entries", true);

    parser.addSubCommand(splitUsingFewestEntries);


    // Add the subcommand used to split entries by selecting the set based on a
    // filter.
    final ArgumentParser splitUsingFilterParser = new ArgumentParser(
         "split-using-filter", INFO_SPLIT_LDIF_SC_FILTER_DESC.get());

    splitUsingFilterFilter = new FilterArgument(null, "filter", true, 0, null,
         INFO_SPLIT_LDIF_SC_FILTER_ARG_DESC_FILTER.get());
    splitUsingFilterParser.addArgument(splitUsingFilterFilter);

    splitUsingFilterAssumeFlatDIT = new BooleanArgument(null, "assumeFlatDIT",
         1, INFO_SPLIT_LDIF_SC_FILTER_ARG_DESC_ASSUME_FLAT_DIT.get());
    splitUsingFilterAssumeFlatDIT.addLongIdentifier("assume-flat-dit", true);
    splitUsingFilterParser.addArgument(splitUsingFilterAssumeFlatDIT);

    final LinkedHashMap<String[],String> splitUsingFilterExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(1));
    splitUsingFilterExamples.put(
         new String[]
         {
           "split-using-filter",
           "--sourceLDIF", "whole.ldif",
           "--targetLDIFBasePath", "split.ldif",
           "--splitBaseDN", "ou=People,dc=example,dc=com",
           "--filter", "(timeZone=Eastern)",
           "--filter", "(timeZone=Central)",
           "--filter", "(timeZone=Mountain)",
           "--filter", "(timeZone=Pacific)",
           "--schemaPath", "config/schema",
           "--addEntriesOutsideSplitBaseDNToAllSets"
         },
         INFO_SPLIT_LDIF_SC_FILTER_EXAMPLE.get());

    splitUsingFilter = new SubCommand("split-using-filter",
         INFO_SPLIT_LDIF_SC_FILTER_DESC.get(),
         splitUsingFilterParser, splitUsingFilterExamples);
    splitUsingFilter.addName("filter", true);

    parser.addSubCommand(splitUsingFilter);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public void doExtendedArgumentValidation()
         throws ArgumentException
  {
    // If multiple sourceLDIF values were provided, then a target LDIF base path
    // must have been given.
    final List<File> sourceLDIFValues = sourceLDIF.getValues();
    if (sourceLDIFValues.size() > 1)
    {
      if (! targetLDIFBasePath.isPresent())
      {
        throw new ArgumentException(ERR_SPLIT_LDIF_NO_TARGET_BASE_PATH.get(
             sourceLDIF.getIdentifierString(),
             targetLDIFBasePath.getIdentifierString()));
      }
    }


    // If the split-using-filter subcommand was provided, then at least two
    // filters must have been provided, and none of the filters can be logically
    // equivalent to any of the others.
    if (splitUsingFilter.isPresent())
    {
      final List<Filter> filterList = splitUsingFilterFilter.getValues();
      final Set<Filter> filterSet = new LinkedHashSet<>(
           StaticUtils.computeMapCapacity(filterList.size()));
      for (final Filter f : filterList)
      {
        if (filterSet.contains(f))
        {
          throw new ArgumentException(ERR_SPLIT_LDIF_NON_UNIQUE_FILTER.get(
               splitUsingFilterFilter.getIdentifierString(), f.toString()));
        }
        else
        {
          filterSet.add(f);
        }
      }

      if (filterSet.size() < 2)
      {
        throw new ArgumentException(ERR_SPLIT_LDIF_NOT_ENOUGH_FILTERS.get(
             splitUsingFilter.getPrimaryName(),
             splitUsingFilterFilter.getIdentifierString()));
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get the schema to use during processing.
    final Schema schema;
    try
    {
      schema = getSchema();
    }
    catch (final LDAPException le)
    {
      wrapErr(0, MAX_OUTPUT_LINE_LENGTH, le.getMessage());
      return le.getResultCode();
    }


    // If an encryption passphrase file is provided, then get the passphrase
    // from it.
    String encryptionPassphrase = null;
    if (encryptionPassphraseFile.isPresent())
    {
      try
      {
        encryptionPassphrase = ToolUtils.readEncryptionPassphraseFromFile(
             encryptionPassphraseFile.getValue());
      }
      catch (final LDAPException e)
      {
        Debug.debugException(e);
        wrapErr(0, MAX_OUTPUT_LINE_LENGTH, e.getMessage());
        return e.getResultCode();
      }
    }


    // Figure out which subcommand was selected, and create the appropriate
    // translator to use to perform the processing.
    final SplitLDIFTranslator translator;
    if (splitUsingHashOnRDN.isPresent())
    {
      translator = new SplitLDIFRDNHashTranslator(splitBaseDN.getValue(),
           splitUsingHashOnRDNNumSets.getValue(),
           addEntriesOutsideSplitBaseDNToAllSets.isPresent(),
           addEntriesOutsideSplitBaseDNToDedicatedSet.isPresent());
    }
    else if (splitUsingHashOnAttribute.isPresent())
    {
      translator = new SplitLDIFAttributeHashTranslator(splitBaseDN.getValue(),
           splitUsingHashOnAttributeNumSets.getValue(),
           splitUsingHashOnAttributeAttributeName.getValue(),
           splitUsingHashOnAttributeUseAllValues.isPresent(),
           splitUsingHashOnAttributeAssumeFlatDIT.isPresent(),
           addEntriesOutsideSplitBaseDNToAllSets.isPresent(),
           addEntriesOutsideSplitBaseDNToDedicatedSet.isPresent());
    }
    else if (splitUsingFewestEntries.isPresent())
    {
      translator = new SplitLDIFFewestEntriesTranslator(splitBaseDN.getValue(),
           splitUsingFewestEntriesNumSets.getValue(),
           splitUsingFewestEntriesAssumeFlatDIT.isPresent(),
           addEntriesOutsideSplitBaseDNToAllSets.isPresent(),
           addEntriesOutsideSplitBaseDNToDedicatedSet.isPresent());
    }
    else if (splitUsingFilter.isPresent())
    {
      final List<Filter> filterList = splitUsingFilterFilter.getValues();
      final LinkedHashSet<Filter> filterSet = new LinkedHashSet<>(
           StaticUtils.computeMapCapacity(filterList.size()));
      for (final Filter f : filterList)
      {
        filterSet.add(f);
      }

      translator = new SplitLDIFFilterTranslator(splitBaseDN.getValue(),
           schema, filterSet, splitUsingFilterAssumeFlatDIT.isPresent(),
           addEntriesOutsideSplitBaseDNToAllSets.isPresent(),
           addEntriesOutsideSplitBaseDNToDedicatedSet.isPresent());
    }
    else
    {
      // This should never happen.
      wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
           ERR_SPLIT_LDIF_CANNOT_DETERMINE_SPLIT_ALGORITHM.get(
                splitUsingHashOnRDN.getPrimaryName() + ", " +
                splitUsingHashOnAttribute.getPrimaryName() + ", " +
                splitUsingFewestEntries.getPrimaryName() + ", " +
                splitUsingFilter.getPrimaryName()));
      return ResultCode.PARAM_ERROR;
    }


    // Create the LDIF reader.
    final LDIFReader ldifReader;
    try
    {
      final InputStream inputStream;
      if (sourceLDIF.isPresent())
      {
        final ObjectPair<InputStream,String> p =
             ToolUtils.getInputStreamForLDIFFiles(sourceLDIF.getValues(),
                  encryptionPassphrase, getOut(), getErr());
        inputStream = p.getFirst();
        if ((encryptionPassphrase == null) && (p.getSecond() != null))
        {
          encryptionPassphrase = p.getSecond();
        }
      }
      else
      {
        inputStream = System.in;
      }

      ldifReader = new LDIFReader(inputStream, numThreads.getValue(),
           translator);
      if (schema != null)
      {
        ldifReader.setSchema(schema);
      }
    }
    catch (final Exception e)
    {
      Debug.debugException(e);
      wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
           ERR_SPLIT_LDIF_ERROR_CREATING_LDIF_READER.get(
                StaticUtils.getExceptionMessage(e)));
      return ResultCode.LOCAL_ERROR;
    }


    // Iterate through and process all of the entries.
    ResultCode resultCode = ResultCode.SUCCESS;
    final LinkedHashMap<String,OutputStream> outputStreams =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(10));
    try
    {
      final AtomicLong entriesRead = new AtomicLong(0L);
      final AtomicLong entriesExcluded = new AtomicLong(0L);
      final TreeMap<String,AtomicLong> fileCounts = new TreeMap<>();

readLoop:
      while (true)
      {
        final SplitLDIFEntry entry;
        try
        {
          entry = (SplitLDIFEntry) ldifReader.readEntry();
        }
        catch (final LDIFException le)
        {
          Debug.debugException(le);
          resultCode = ResultCode.LOCAL_ERROR;

          final File f = getOutputFile(SplitLDIFEntry.SET_NAME_ERRORS);
          OutputStream s = outputStreams.get(SplitLDIFEntry.SET_NAME_ERRORS);
          if (s == null)
          {
            try
            {
              s = new FileOutputStream(f);

              if (encryptTarget.isPresent())
              {
                if (encryptionPassphrase == null)
                {
                  try
                  {
                    encryptionPassphrase =
                         ToolUtils.promptForEncryptionPassphrase(false, true,
                              getOut(), getErr());
                  }
                  catch (final LDAPException ex)
                  {
                    Debug.debugException(ex);
                    wrapErr(0, MAX_OUTPUT_LINE_LENGTH, ex.getMessage());
                    return ex.getResultCode();
                  }
                }

                s = new PassphraseEncryptedOutputStream(encryptionPassphrase,
                     s);
              }

              if (compressTarget.isPresent())
              {
                s = new GZIPOutputStream(s);
              }

              outputStreams.put(SplitLDIFEntry.SET_NAME_ERRORS, s);
              fileCounts.put(SplitLDIFEntry.SET_NAME_ERRORS,
                   new AtomicLong(0L));
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              resultCode = ResultCode.LOCAL_ERROR;
              wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                   ERR_SPLIT_LDIF_CANNOT_OPEN_OUTPUT_FILE.get(
                        f.getAbsolutePath(),
                        StaticUtils.getExceptionMessage(e)));
              break readLoop;
            }
          }

          final ByteStringBuffer buffer = new ByteStringBuffer();
          buffer.append("# ");
          buffer.append(le.getMessage());
          buffer.append(StaticUtils.EOL_BYTES);

          final List<String> dataLines = le.getDataLines();
          if (dataLines != null)
          {
            for (final String dataLine : dataLines)
            {
              buffer.append(dataLine);
              buffer.append(StaticUtils.EOL_BYTES);
            }
          }

          buffer.append(StaticUtils.EOL_BYTES);

          try
          {
            s.write(buffer.toByteArray());
          }
          catch (final Exception e)
          {
              Debug.debugException(e);
              resultCode = ResultCode.LOCAL_ERROR;
              wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                   ERR_SPLIT_LDIF_ERROR_WRITING_ERROR_TO_FILE.get(
                        le.getMessage(), f.getAbsolutePath(),
                        StaticUtils.getExceptionMessage(e)));
              break readLoop;
          }

          if (le.mayContinueReading())
          {
            wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                 ERR_SPLIT_LDIF_INVALID_LDIF_RECORD_RECOVERABLE.get(
                      StaticUtils.getExceptionMessage(le)));
            continue;
          }
          else
          {
            wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                 ERR_SPLIT_LDIF_INVALID_LDIF_RECORD_UNRECOVERABLE.get(
                      StaticUtils.getExceptionMessage(le)));
            break;
          }
        }
        catch (final IOException ioe)
        {
          Debug.debugException(ioe);
          resultCode = ResultCode.LOCAL_ERROR;
          wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
               ERR_SPLIT_LDIF_IO_READ_ERROR.get(
                    StaticUtils.getExceptionMessage(ioe)));
          break;
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          resultCode = ResultCode.LOCAL_ERROR;
          wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
               ERR_SPLIT_LDIF_UNEXPECTED_READ_ERROR.get(
                    StaticUtils.getExceptionMessage(e)));
          break;
        }

        if (entry == null)
        {
          break;
        }

        final long readCount = entriesRead.incrementAndGet();
        if ((readCount % 1000L) == 0)
        {
          // Even though we aren't done with this entry yet, we'll go ahead and
          // log a progress message now because it's easier to do that now than
          // to ensure that it's handled properly through all possible error
          // conditions that need to be handled below.
          wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
               INFO_SPLIT_LDIF_PROGRESS.get(readCount));
        }


        // Get the set(s) to which the entry should be written.  If this is
        // null (which could be the case as a result of a race condition when
        // using multiple threads where processing for a child completes before
        // processing for its parent, or as a result of a case in which a
        // child is included without or before its parent), then try to see if
        // we can get the sets by passing the entry through the translator.
        Set<String> sets = entry.getSets();
        byte[] ldifBytes = entry.getLDIFBytes();
        if (sets == null)
        {
          try
          {
            sets = translator.translate(entry, 0L).getSets();
          }
          catch (final Exception e)
          {
            Debug.debugException(e);
          }

          if (sets == null)
          {
            final SplitLDIFEntry errorEntry =  translator.createEntry(entry,
                 ERR_SPLIT_LDIF_ENTRY_WITHOUT_PARENT.get(
                      entry.getDN(), splitBaseDN.getStringValue()),
                 Collections.singleton(SplitLDIFEntry.SET_NAME_ERRORS));
            ldifBytes = errorEntry.getLDIFBytes();
            sets = errorEntry.getSets();
          }
        }


        // If the entry shouldn't be written into any sets, then we don't need
        // to do anything else.
        if (sets.isEmpty())
        {
          entriesExcluded.incrementAndGet();
          continue;
        }


        // Write the entry into each of the target sets, creating the output
        // files if necessary.
        for (final String set : sets)
        {
          if (set.equals(SplitLDIFEntry.SET_NAME_ERRORS))
          {
            // This indicates that an error was encountered during processing,
            // so we'll update the result code to reflect that.
            resultCode = ResultCode.LOCAL_ERROR;
          }

          final File f = getOutputFile(set);
          OutputStream s = outputStreams.get(set);
          if (s == null)
          {
            try
            {
              s = new FileOutputStream(f);

              if (encryptTarget.isPresent())
              {
                if (encryptionPassphrase == null)
                {
                  try
                  {
                    encryptionPassphrase =
                         ToolUtils.promptForEncryptionPassphrase(false, true,
                              getOut(), getErr());
                  }
                  catch (final LDAPException ex)
                  {
                    Debug.debugException(ex);
                    wrapErr(0, MAX_OUTPUT_LINE_LENGTH, ex.getMessage());
                    return ex.getResultCode();
                  }
                }

                s = new PassphraseEncryptedOutputStream(encryptionPassphrase,
                     s);
              }

              if (compressTarget.isPresent())
              {
                s = new GZIPOutputStream(s);
              }

              outputStreams.put(set, s);
              fileCounts.put(set, new AtomicLong(0L));
            }
            catch (final Exception e)
            {
              Debug.debugException(e);
              resultCode = ResultCode.LOCAL_ERROR;
              wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                   ERR_SPLIT_LDIF_CANNOT_OPEN_OUTPUT_FILE.get(
                        f.getAbsolutePath(),
                        StaticUtils.getExceptionMessage(e)));
              break readLoop;
            }
          }

          try
          {
            s.write(ldifBytes);
          }
          catch (final Exception e)
          {
              Debug.debugException(e);
              resultCode = ResultCode.LOCAL_ERROR;
              wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
                   ERR_SPLIT_LDIF_ERROR_WRITING_TO_FILE.get(
                        entry.getDN(), f.getAbsolutePath(),
                        StaticUtils.getExceptionMessage(e)));
              break readLoop;
          }

          fileCounts.get(set).incrementAndGet();
        }
      }


      // Processing is complete.  Summarize the processing that was performed.
      final long finalReadCount = entriesRead.get();
      if (finalReadCount > 1000L)
      {
        out();
      }

      wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
           INFO_SPLIT_LDIF_PROCESSING_COMPLETE.get(finalReadCount));

      final long excludedCount = entriesExcluded.get();
      if (excludedCount > 0L)
      {
        wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
             INFO_SPLIT_LDIF_EXCLUDED_COUNT.get(excludedCount));
      }

      for (final Map.Entry<String,AtomicLong> e : fileCounts.entrySet())
      {
        final File f = getOutputFile(e.getKey());
        wrapOut(0, MAX_OUTPUT_LINE_LENGTH,
             INFO_SPLIT_LDIF_COUNT_TO_FILE.get(e.getValue().get(),
                  f.getName()));
      }
    }
    finally
    {
      try
      {
        ldifReader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }

      for (final Map.Entry<String,OutputStream> e : outputStreams.entrySet())
      {
        try
        {
          e.getValue().close();
        }
        catch (final Exception ex)
        {
          Debug.debugException(ex);
          resultCode = ResultCode.LOCAL_ERROR;
          wrapErr(0, MAX_OUTPUT_LINE_LENGTH,
               ERR_SPLIT_LDIF_ERROR_CLOSING_FILE.get(
                    getOutputFile(e.getKey()),
                    StaticUtils.getExceptionMessage(ex)));
        }
      }
    }

    return resultCode;
  }



  /**
   * Retrieves the schema that should be used for processing.
   *
   * @return  The schema that was created.
   *
   * @throws  LDAPException  If a problem is encountered while retrieving the
   *                         schema.
   */
  @Nullable()
  private Schema getSchema()
          throws LDAPException
  {
    // If any schema paths were specified, then load the schema only from those
    // paths.
    if (schemaPath.isPresent())
    {
      final ArrayList<File> schemaFiles = new ArrayList<>(10);
      for (final File path : schemaPath.getValues())
      {
        if (path.isFile())
        {
          schemaFiles.add(path);
        }
        else
        {
          final TreeMap<String,File> fileMap = new TreeMap<>();
          for (final File schemaDirFile : path.listFiles())
          {
            final String name = schemaDirFile.getName();
            if (schemaDirFile.isFile() && name.toLowerCase().endsWith(".ldif"))
            {
              fileMap.put(name, schemaDirFile);
            }
          }
          schemaFiles.addAll(fileMap.values());
        }
      }

      if (schemaFiles.isEmpty())
      {
        throw new LDAPException(ResultCode.PARAM_ERROR,
             ERR_SPLIT_LDIF_NO_SCHEMA_FILES.get(
                  schemaPath.getIdentifierString()));
      }
      else
      {
        try
        {
          return Schema.getSchema(schemaFiles);
        }
        catch (final Exception e)
        {
          Debug.debugException(e);
          throw new LDAPException(ResultCode.LOCAL_ERROR,
               ERR_SPLIT_LDIF_ERROR_LOADING_SCHEMA.get(
                    StaticUtils.getExceptionMessage(e)));
        }
      }
    }
    else
    {
      // If the INSTANCE_ROOT environment variable is set and it refers to a
      // directory that has a config/schema subdirectory that has one or more
      // schema files in it, then read the schema from that directory.
      try
      {
        final String instanceRootStr =
             StaticUtils.getEnvironmentVariable("INSTANCE_ROOT");
        if (instanceRootStr != null)
        {
          final File instanceRoot = new File(instanceRootStr);
          final File configDir = new File(instanceRoot, "config");
          final File schemaDir = new File(configDir, "schema");
          if (schemaDir.exists())
          {
            final TreeMap<String,File> fileMap = new TreeMap<>();
            for (final File schemaDirFile : schemaDir.listFiles())
            {
              final String name = schemaDirFile.getName();
              if (schemaDirFile.isFile() &&
                  name.toLowerCase().endsWith(".ldif"))
              {
                fileMap.put(name, schemaDirFile);
              }
            }

            if (! fileMap.isEmpty())
            {
              return Schema.getSchema(new ArrayList<>(fileMap.values()));
            }
          }
        }
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
      }
    }


    // If we've gotten here, then just return null and the tool will try to use
    // the default standard schema.
    return null;
  }



  /**
   * Retrieves a file object that refers to an output file with the provided
   * extension.
   *
   * @param  extension  The extension to use for the file.
   *
   * @return  A file object that refers to an output file with the provided
   *          extension.
   */
  @NotNull()
  private File getOutputFile(@NotNull final String extension)
  {
    final File baseFile;
    if (targetLDIFBasePath.isPresent())
    {
      baseFile = targetLDIFBasePath.getValue();
    }
    else
    {
      baseFile = sourceLDIF.getValue();
    }

    return new File(baseFile.getAbsolutePath() + extension);
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> exampleMap =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(4));

    for (final Map.Entry<String[],String> e :
         splitUsingHashOnRDN.getExampleUsages().entrySet())
    {
      exampleMap.put(e.getKey(), e.getValue());
    }

    for (final Map.Entry<String[],String> e :
         splitUsingHashOnAttribute.getExampleUsages().entrySet())
    {
      exampleMap.put(e.getKey(), e.getValue());
    }

    for (final Map.Entry<String[],String> e :
         splitUsingFewestEntries.getExampleUsages().entrySet())
    {
      exampleMap.put(e.getKey(), e.getValue());
    }

    for (final Map.Entry<String[],String> e :
         splitUsingFilter.getExampleUsages().entrySet())
    {
      exampleMap.put(e.getKey(), e.getValue());
    }

    return exampleMap;
  }
}
