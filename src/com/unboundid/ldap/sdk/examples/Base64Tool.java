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
package com.unboundid.ldap.sdk.examples;



import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.LinkedHashMap;

import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.ldap.sdk.Version;
import com.unboundid.util.Base64;
import com.unboundid.util.ByteStringBuffer;
import com.unboundid.util.CommandLineTool;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.BooleanArgument;
import com.unboundid.util.args.FileArgument;
import com.unboundid.util.args.StringArgument;
import com.unboundid.util.args.SubCommand;



/**
 * This class provides a tool that can be used to perform base64 encoding and
 * decoding from the command line.  It provides two subcommands:  encode and
 * decode.  Each of those subcommands offers the following arguments:
 * <UL>
 *   <LI>
 *     "--data {data}" -- specifies the data to be encoded or decoded.
 *   </LI>
 *   <LI>
 *     "--inputFile {data}" -- specifies the path to a file containing the data
 *     to be encoded or decoded.
 *   </LI>
 *   <LI>
 *     "--outputFile {data}" -- specifies the path to a file to which the
 *     encoded or decoded data should be written.
 *   </LI>
 * </UL>
 * The "--data" and "--inputFile" arguments are mutually exclusive, and if
 * neither is provided, the data to encode will be read from standard input.
 * If the "--outputFile" argument is not provided, then the result will be
 * written to standard output.
 */
@ThreadSafety(level=ThreadSafetyLevel.NOT_THREADSAFE)
public final class Base64Tool
       extends CommandLineTool
{
  /**
   * The column at which to wrap long lines of output.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  /**
   * The name of the argument used to indicate whether to add an end-of-line
   * marker to the end of the base64-encoded data.
   */
  @NotNull private static final String ARG_NAME_ADD_TRAILING_LINE_BREAK =
       "addTrailingLineBreak";



  /**
   * The name of the argument used to specify the data to encode or decode.
   */
  @NotNull private static final String ARG_NAME_DATA = "data";



  /**
   * The name of the argument used to indicate whether to ignore any end-of-line
   * marker that might be present at the end of the data to encode.
   */
  @NotNull private static final String ARG_NAME_IGNORE_TRAILING_LINE_BREAK =
       "ignoreTrailingLineBreak";



  /**
   * The name of the argument used to specify the path to the input file with
   * the data to encode or decode.
   */
  @NotNull private static final String ARG_NAME_INPUT_FILE = "inputFile";



  /**
   * The name of the argument used to specify the path to the output file into
   * which to write the encoded or decoded data.
   */
  @NotNull private static final String ARG_NAME_OUTPUT_FILE = "outputFile";



  /**
   * The name of the argument used to indicate that the encoding and decoding
   * should be performed using the base64url alphabet rather than the standard
   * base64 alphabet.
   */
  @NotNull private static final String ARG_NAME_URL = "url";



  /**
   * The name of the subcommand used to decode data.
   */
  @NotNull private static final String SUBCOMMAND_NAME_DECODE = "decode";



  /**
   * The name of the subcommand used to encode data.
   */
  @NotNull private static final String SUBCOMMAND_NAME_ENCODE = "encode";



  // The argument parser for this tool.
  @Nullable private volatile ArgumentParser parser;

  // The input stream to use as standard input.
  @Nullable private final InputStream in;



  /**
   * Runs the tool with the provided set of arguments.
   *
   * @param  args  The command line arguments provided to this program.
   */
  public static void main(@NotNull final String... args)
  {
    final ResultCode resultCode = main(System.in, System.out, System.err, args);
    if (resultCode != ResultCode.SUCCESS)
    {
      System.exit(resultCode.intValue());
    }
  }



  /**
   * Runs the tool with the provided information.
   *
   * @param  in    The input stream to use for standard input.  It may be
   *               {@code null} if no standard input is needed.
   * @param  out   The output stream to which standard out should be written.
   *               It may be {@code null} if standard output should be
   *               suppressed.
   * @param  err   The output stream to which standard error should be written.
   *               It may be {@code null} if standard error should be
   *               suppressed.
   * @param  args  The command line arguments provided to this program.
   *
   * @return  The result code obtained from running the tool.  A result code
   *          other than {@link ResultCode#SUCCESS} will indicate that an error
   *          occurred.
   */
  @NotNull()
  public static ResultCode main(@Nullable final InputStream in,
                                @Nullable final OutputStream out,
                                @Nullable final OutputStream err,
                                @NotNull final String... args)
  {
    final Base64Tool tool = new Base64Tool(in, out, err);
    return tool.runTool(args);
  }



  /**
   * Creates a new instance of this tool with the provided information.
   * Standard input will not be available.
   *
   * @param  out  The output stream to which standard out should be written.
   *              It may be {@code null} if standard output should be
   *              suppressed.
   * @param  err  The output stream to which standard error should be written.
   *              It may be {@code null} if standard error should be suppressed.
   */
  public Base64Tool(@Nullable final OutputStream out,
                    @Nullable final OutputStream err)
  {
    this(null, out, err);
  }



  /**
   * Creates a new instance of this tool with the provided information.
   *
   * @param  in   The input stream to use for standard input.  It may be
   *              {@code null} if no standard input is needed.
   * @param  out  The output stream to which standard out should be written.
   *              It may be {@code null} if standard output should be
   *              suppressed.
   * @param  err  The output stream to which standard error should be written.
   *              It may be {@code null} if standard error should be suppressed.
   */
  public Base64Tool(@Nullable final InputStream in,
                    @Nullable final OutputStream out,
                    @Nullable final OutputStream err)
  {
    super(out, err);

    this.in = in;

    parser = null;
  }



  /**
   * Retrieves the name of this tool.  It should be the name of the command used
   * to invoke this tool.
   *
   * @return  The name for this tool.
   */
  @Override()
  @NotNull()
  public String getToolName()
  {
    return "base64";
  }



  /**
   * Retrieves a human-readable description for this tool.
   *
   * @return  A human-readable description for this tool.
   */
  @Override()
  @NotNull()
  public String getToolDescription()
  {
    return "Encode raw data using the base64 algorithm or decode " +
         "base64-encoded data back to its raw representation.";
  }



  /**
   * Retrieves a version string for this tool, if available.
   *
   * @return  A version string for this tool, or {@code null} if none is
   *          available.
   */
  @Override()
  @NotNull()
  public String getToolVersion()
  {
    return Version.NUMERIC_VERSION_STRING;
  }



  /**
   * Indicates whether this tool should provide support for an interactive mode,
   * in which the tool offers a mode in which the arguments can be provided in
   * a text-driven menu rather than requiring them to be given on the command
   * line.  If interactive mode is supported, it may be invoked using the
   * "--interactive" argument.  Alternately, if interactive mode is supported
   * and {@link #defaultsToInteractiveMode()} returns {@code true}, then
   * interactive mode may be invoked by simply launching the tool without any
   * arguments.
   *
   * @return  {@code true} if this tool supports interactive mode, or
   *          {@code false} if not.
   */
  @Override()
  public boolean supportsInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool defaults to launching in interactive mode if
   * the tool is invoked without any command-line arguments.  This will only be
   * used if {@link #supportsInteractiveMode()} returns {@code true}.
   *
   * @return  {@code true} if this tool defaults to using interactive mode if
   *          launched without any command-line arguments, or {@code false} if
   *          not.
   */
  @Override()
  public boolean defaultsToInteractiveMode()
  {
    return true;
  }



  /**
   * Indicates whether this tool supports the use of a properties file for
   * specifying default values for arguments that aren't specified on the
   * command line.
   *
   * @return  {@code true} if this tool supports the use of a properties file
   *          for specifying default values for arguments that aren't specified
   *          on the command line, or {@code false} if not.
   */
  @Override()
  public boolean supportsPropertiesFile()
  {
    return true;
  }



  /**
   * Indicates whether this tool should provide arguments for redirecting output
   * to a file.  If this method returns {@code true}, then the tool will offer
   * an "--outputFile" argument that will specify the path to a file to which
   * all standard output and standard error content will be written, and it will
   * also offer a "--teeToStandardOut" argument that can only be used if the
   * "--outputFile" argument is present and will cause all output to be written
   * to both the specified output file and to standard output.
   *
   * @return  {@code true} if this tool should provide arguments for redirecting
   *          output to a file, or {@code false} if not.
   */
  @Override()
  protected boolean supportsOutputFile()
  {
    // This tool provides its own output file support.
    return false;
  }



  /**
   * Adds the command-line arguments supported for use with this tool to the
   * provided argument parser.  The tool may need to retain references to the
   * arguments (and/or the argument parser, if trailing arguments are allowed)
   * to it in order to obtain their values for use in later processing.
   *
   * @param  parser  The argument parser to which the arguments are to be added.
   *
   * @throws  ArgumentException  If a problem occurs while adding any of the
   *                             tool-specific arguments to the provided
   *                             argument parser.
   */
  @Override()
  public void addToolArguments(@NotNull final ArgumentParser parser)
         throws ArgumentException
  {
    this.parser = parser;


    // Create the subcommand for encoding data.
    final ArgumentParser encodeParser =
         new ArgumentParser("encode", "Base64-encodes raw data.");

    final StringArgument encodeDataArgument = new StringArgument('d',
         ARG_NAME_DATA, false, 1, "{data}",
         "The raw data to be encoded.  If neither the --" + ARG_NAME_DATA +
              " nor the --" + ARG_NAME_INPUT_FILE + " argument is provided, " +
              "then the data will be read from standard input.");
    encodeDataArgument.addLongIdentifier("rawData", true);
    encodeDataArgument.addLongIdentifier("raw-data", true);
    encodeParser.addArgument(encodeDataArgument);

    final FileArgument encodeDataFileArgument = new FileArgument('f',
         ARG_NAME_INPUT_FILE, false, 1, null,
         "The path to a file containing the raw data to be encoded.  If " +
              "neither the --" + ARG_NAME_DATA + " nor the --" +
              ARG_NAME_INPUT_FILE + " argument is provided, then the data " +
              "will be read from standard input.",
         true, true, true, false);
    encodeDataFileArgument.addLongIdentifier("rawDataFile", true);
    encodeDataFileArgument.addLongIdentifier("input-file", true);
    encodeDataFileArgument.addLongIdentifier("raw-data-file", true);
    encodeParser.addArgument(encodeDataFileArgument);

    final FileArgument encodeOutputFileArgument = new FileArgument('o',
         ARG_NAME_OUTPUT_FILE, false, 1, null,
         "The path to a file to which the encoded data should be written.  " +
              "If this is not provided, the encoded data will be written to " +
              "standard output.",
         false, true, true, false);
    encodeOutputFileArgument.addLongIdentifier("toEncodedFile", true);
    encodeOutputFileArgument.addLongIdentifier("output-file", true);
    encodeOutputFileArgument.addLongIdentifier("to-encoded-file", true);
    encodeParser.addArgument(encodeOutputFileArgument);

    final BooleanArgument encodeURLArgument = new BooleanArgument(null,
         ARG_NAME_URL,
         "Encode the data with the base64url mechanism rather than the " +
              "standard base64 mechanism.");
    encodeParser.addArgument(encodeURLArgument);

    final BooleanArgument encodeIgnoreTrailingEOLArgument = new BooleanArgument(
         null, ARG_NAME_IGNORE_TRAILING_LINE_BREAK,
         "Ignore any end-of-line marker that may be present at the end of " +
              "the data to encode.");
    encodeIgnoreTrailingEOLArgument.addLongIdentifier(
         "ignore-trailing-line-break", true);
    encodeParser.addArgument(encodeIgnoreTrailingEOLArgument);

    encodeParser.addExclusiveArgumentSet(encodeDataArgument,
         encodeDataFileArgument);

    final LinkedHashMap<String[],String> encodeExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));
    encodeExamples.put(
         new String[]
         {
           "encode",
           "--data", "Hello"
         },
         "Base64-encodes the string 'Hello' and writes the result to " +
              "standard output.");
    encodeExamples.put(
         new String[]
         {
           "encode",
           "--inputFile", "raw-data.txt",
           "--outputFile", "encoded-data.txt",
         },
         "Base64-encodes the data contained in the 'raw-data.txt' file and " +
              "writes the result to the 'encoded-data.txt' file.");
    encodeExamples.put(
         new String[]
         {
           "encode"
         },
         "Base64-encodes data read from standard input and writes the result " +
              "to standard output.");

    final SubCommand encodeSubCommand = new SubCommand(SUBCOMMAND_NAME_ENCODE,
         "Base64-encodes raw data.", encodeParser, encodeExamples);
    parser.addSubCommand(encodeSubCommand);


    // Create the subcommand for decoding data.
    final ArgumentParser decodeParser =
         new ArgumentParser("decode", "Decodes base64-encoded data.");

    final StringArgument decodeDataArgument = new StringArgument('d',
         ARG_NAME_DATA, false, 1, "{data}",
         "The base64-encoded data to be decoded.  If neither the --" +
              ARG_NAME_DATA + " nor the --" + ARG_NAME_INPUT_FILE +
              " argument is provided, then the data will be read from " +
              "standard input.");
    decodeDataArgument.addLongIdentifier("encodedData", true);
    decodeDataArgument.addLongIdentifier("encoded-data", true);
    decodeParser.addArgument(decodeDataArgument);

    final FileArgument decodeDataFileArgument = new FileArgument('f',
         ARG_NAME_INPUT_FILE, false, 1, null,
         "The path to a file containing the base64-encoded data to be " +
              "decoded.  If neither the --" + ARG_NAME_DATA + " nor the --" +
              ARG_NAME_INPUT_FILE + " argument is provided, then the data " +
              "will be read from standard input.",
         true, true, true, false);
    decodeDataFileArgument.addLongIdentifier("encodedDataFile", true);
    decodeDataFileArgument.addLongIdentifier("input-file", true);
    decodeDataFileArgument.addLongIdentifier("encoded-data-file", true);
    decodeParser.addArgument(decodeDataFileArgument);

    final FileArgument decodeOutputFileArgument = new FileArgument('o',
         ARG_NAME_OUTPUT_FILE, false, 1, null,
         "The path to a file to which the decoded data should be written.  " +
              "If this is not provided, the decoded data will be written to " +
              "standard output.",
         false, true, true, false);
    decodeOutputFileArgument.addLongIdentifier("toRawFile", true);
    decodeOutputFileArgument.addLongIdentifier("output-file", true);
    decodeOutputFileArgument.addLongIdentifier("to-raw-file", true);
    decodeParser.addArgument(decodeOutputFileArgument);

    final BooleanArgument decodeURLArgument = new BooleanArgument(null,
         ARG_NAME_URL,
         "Decode the data with the base64url mechanism rather than the " +
              "standard base64 mechanism.");
    decodeParser.addArgument(decodeURLArgument);

    final BooleanArgument decodeAddTrailingLineBreak = new BooleanArgument(
         null, ARG_NAME_ADD_TRAILING_LINE_BREAK,
         "Add a line break to the end of the decoded data.");
    decodeAddTrailingLineBreak.addLongIdentifier("add-trailing-line-break",
         true);
    decodeParser.addArgument(decodeAddTrailingLineBreak);

    decodeParser.addExclusiveArgumentSet(decodeDataArgument,
         decodeDataFileArgument);

    final LinkedHashMap<String[],String> decodeExamples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(3));
    decodeExamples.put(
         new String[]
         {
           "decode",
           "--data", "SGVsbG8="
         },
         "Base64-decodes the string 'SGVsbG8=' and writes the result to " +
              "standard output.");
    decodeExamples.put(
         new String[]
         {
           "decode",
           "--inputFile", "encoded-data.txt",
           "--outputFile", "decoded-data.txt",
         },
         "Base64-decodes the data contained in the 'encoded-data.txt' file " +
              "and writes the result to the 'raw-data.txt' file.");
    decodeExamples.put(
         new String[]
         {
           "decode"
         },
         "Base64-decodes data read from standard input and writes the result " +
              "to standard output.");

    final SubCommand decodeSubCommand = new SubCommand(SUBCOMMAND_NAME_DECODE,
         "Decodes base64-encoded data.", decodeParser, decodeExamples);
    parser.addSubCommand(decodeSubCommand);
  }



  /**
   * Performs the core set of processing for this tool.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @Override()
  @NotNull()
  public ResultCode doToolProcessing()
  {
    // Get the subcommand selected by the user.
    final SubCommand subCommand = parser.getSelectedSubCommand();
    if (subCommand == null)
    {
      // This should never happen.
      wrapErr(0, WRAP_COLUMN, "No subcommand was selected.");
      return ResultCode.PARAM_ERROR;
    }


    // Take the appropriate action based on the selected subcommand.
    if (subCommand.hasName(SUBCOMMAND_NAME_ENCODE))
    {
      return doEncode(subCommand.getArgumentParser());
    }
    else
    {
      return doDecode(subCommand.getArgumentParser());
    }
  }



  /**
   * Performs the necessary work for base64 encoding.
   *
   * @param  p  The argument parser for the encode subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doEncode(@NotNull final ArgumentParser p)
  {
    // Get the data to encode.
    final ByteStringBuffer rawDataBuffer = new ByteStringBuffer();
    final StringArgument dataArg = p.getStringArgument(ARG_NAME_DATA);
    if ((dataArg != null) && dataArg.isPresent())
    {
      rawDataBuffer.append(dataArg.getValue());
    }
    else
    {
      try
      {
        final InputStream inputStream;
        final FileArgument inputFileArg =
             p.getFileArgument(ARG_NAME_INPUT_FILE);
        if ((inputFileArg != null) && inputFileArg.isPresent())
        {
          inputStream = new FileInputStream(inputFileArg.getValue());
        }
        else
        {
          inputStream = in;
        }

        final byte[] buffer = new byte[8192];
        while (true)
        {
          final int bytesRead = inputStream.read(buffer);
          if (bytesRead <= 0)
          {
            break;
          }

          rawDataBuffer.append(buffer, 0, bytesRead);
        }

        inputStream.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             "An error occurred while attempting to read the data to encode:  ",
             StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // If we should ignore any trailing end-of-line markers, then do that now.
    final BooleanArgument ignoreEOLArg =
         p.getBooleanArgument(ARG_NAME_IGNORE_TRAILING_LINE_BREAK);
    if ((ignoreEOLArg != null) && ignoreEOLArg.isPresent())
    {
stripEOLLoop:
      while (rawDataBuffer.length() > 0)
      {
        switch (rawDataBuffer.getBackingArray()[rawDataBuffer.length() - 1])
        {
          case '\n':
          case '\r':
            rawDataBuffer.delete(rawDataBuffer.length() - 1, 1);
            break;
          default:
            break stripEOLLoop;
        }
      }
    }


    // Base64-encode the data.
    final byte[] rawDataArray = rawDataBuffer.toByteArray();
    final ByteStringBuffer encodedDataBuffer =
         new ByteStringBuffer(4 * rawDataBuffer.length() / 3 + 3);
    final BooleanArgument urlArg = p.getBooleanArgument(ARG_NAME_URL);
    if ((urlArg != null) && urlArg.isPresent())
    {
      Base64.urlEncode(rawDataArray, 0, rawDataArray.length, encodedDataBuffer,
           false);
    }
    else
    {
      Base64.encode(rawDataArray, encodedDataBuffer);
    }


    // Write the encoded data.
    final FileArgument outputFileArg = p.getFileArgument(ARG_NAME_OUTPUT_FILE);
    if ((outputFileArg != null) && outputFileArg.isPresent())
    {
      try
      {
        final FileOutputStream outputStream =
             new FileOutputStream(outputFileArg.getValue(), false);
        encodedDataBuffer.write(outputStream);
        outputStream.write(StaticUtils.EOL_BYTES);
        outputStream.flush();
        outputStream.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             "An error occurred while attempting to write the base64-encoded " +
                  "data to output file ",
             outputFileArg.getValue().getAbsolutePath(), ":  ",
             StaticUtils.getExceptionMessage(e));
        err("Base64-encoded data:");
        err(encodedDataBuffer.toString());
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      out(encodedDataBuffer.toString());
    }


    return ResultCode.SUCCESS;
  }



  /**
   * Performs the necessary work for base64 decoding.
   *
   * @param  p  The argument parser for the decode subcommand.
   *
   * @return  A result code that indicates whether the processing completed
   *          successfully.
   */
  @NotNull()
  private ResultCode doDecode(@NotNull final ArgumentParser p)
  {
    // Get the data to decode.  We'll always ignore the following:
    // - Line breaks
    // - Blank lines
    // - Lines that start with an octothorpe (#)
    //
    // Unless the --url argument was provided, then we'll also ignore lines that
    // start with a dash (like those used as start and end markers in a
    // PEM-encoded certificate).  Since dashes are part of the base64url
    // alphabet, we can't ignore dashes if the --url argument was provided.
    final ByteStringBuffer encodedDataBuffer = new ByteStringBuffer();
    final BooleanArgument urlArg = p.getBooleanArgument(ARG_NAME_URL);
    final StringArgument dataArg = p.getStringArgument(ARG_NAME_DATA);
    if ((dataArg != null) && dataArg.isPresent())
    {
      encodedDataBuffer.append(dataArg.getValue());
    }
    else
    {
      try
      {
        final BufferedReader reader;
        final FileArgument inputFileArg =
             p.getFileArgument(ARG_NAME_INPUT_FILE);
        if ((inputFileArg != null) && inputFileArg.isPresent())
        {
          reader = new BufferedReader(new FileReader(inputFileArg.getValue()));
        }
        else
        {
          reader = new BufferedReader(new InputStreamReader(in));
        }

        while (true)
        {
          final String line = reader.readLine();
          if (line == null)
          {
            break;
          }

          if ((line.length() == 0) || line.startsWith("#"))
          {
            continue;
          }

          if (line.startsWith("-") &&
              ((urlArg == null) || (! urlArg.isPresent())))
          {
            continue;
          }

          encodedDataBuffer.append(line);
        }

        reader.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             "An error occurred while attempting to read the data to decode:  ",
             StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // Base64-decode the data.
    final ByteStringBuffer rawDataBuffer = new
         ByteStringBuffer(encodedDataBuffer.length());
    if ((urlArg != null) && urlArg.isPresent())
    {
      try
      {
        rawDataBuffer.append(Base64.urlDecode(encodedDataBuffer.toString()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             "An error occurred while attempting to base64url-decode the " +
                  "provided data:  " + StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      try
      {
        rawDataBuffer.append(Base64.decode(encodedDataBuffer.toString()));
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             "An error occurred while attempting to base64-decode the " +
                  "provided data:  " + StaticUtils.getExceptionMessage(e));
        return ResultCode.LOCAL_ERROR;
      }
    }


    // If we should add a newline, then do that now.
    final BooleanArgument addEOLArg =
         p.getBooleanArgument(ARG_NAME_ADD_TRAILING_LINE_BREAK);
    if ((addEOLArg != null) && addEOLArg.isPresent())
    {
      rawDataBuffer.append(StaticUtils.EOL_BYTES);
    }


    // Write the decoded data.
    final FileArgument outputFileArg = p.getFileArgument(ARG_NAME_OUTPUT_FILE);
    if ((outputFileArg != null) && outputFileArg.isPresent())
    {
      try
      {
        final FileOutputStream outputStream =
             new FileOutputStream(outputFileArg.getValue(), false);
        rawDataBuffer.write(outputStream);
        outputStream.flush();
        outputStream.close();
      }
      catch (final Exception e)
      {
        Debug.debugException(e);
        wrapErr(0, WRAP_COLUMN,
             "An error occurred while attempting to write the base64-decoded " +
                  "data to output file ",
             outputFileArg.getValue().getAbsolutePath(), ":  ",
             StaticUtils.getExceptionMessage(e));
        err("Base64-decoded data:");
        err(encodedDataBuffer.toString());
        return ResultCode.LOCAL_ERROR;
      }
    }
    else
    {
      final byte[] rawDataArray = rawDataBuffer.toByteArray();
      getOut().write(rawDataArray, 0, rawDataArray.length);
      getOut().flush();
    }


    return ResultCode.SUCCESS;
  }



  /**
   * Retrieves a set of information that may be used to generate example usage
   * information.  Each element in the returned map should consist of a map
   * between an example set of arguments and a string that describes the
   * behavior of the tool when invoked with that set of arguments.
   *
   * @return  A set of information that may be used to generate example usage
   *          information.  It may be {@code null} or empty if no example usage
   *          information is available.
   */
  @Override()
  @NotNull()
  public LinkedHashMap<String[],String> getExampleUsages()
  {
    final LinkedHashMap<String[],String> examples =
         new LinkedHashMap<>(StaticUtils.computeMapCapacity(2));

    examples.put(
         new String[]
         {
           "encode",
           "--data", "Hello"
         },
         "Base64-encodes the string 'Hello' and writes the result to " +
              "standard output.");

    examples.put(
         new String[]
         {
           "decode",
           "--inputFile", "encoded-data.txt",
           "--outputFile", "decoded-data.txt",
         },
         "Base64-decodes the data contained in the 'encoded-data.txt' file " +
              "and writes the result to the 'raw-data.txt' file.");

    return examples;
  }
}
