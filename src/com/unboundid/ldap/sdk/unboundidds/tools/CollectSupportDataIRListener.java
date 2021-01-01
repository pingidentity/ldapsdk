/*
 * Copyright 2020-2021 Ping Identity Corporation
 * All Rights Reserved.
 */
/*
 * Copyright 2020-2021 Ping Identity Corporation
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
 * Copyright (C) 2020-2021 Ping Identity Corporation
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



import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.concurrent.atomic.AtomicReference;

import com.unboundid.ldap.sdk.IntermediateResponse;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataArchiveFragmentIntermediateResponse;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataIntermediateResponseListener;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataOutputIntermediateResponse;
import com.unboundid.ldap.sdk.unboundidds.extensions.
            CollectSupportDataOutputStream;
import com.unboundid.util.Debug;
import com.unboundid.util.NotNull;
import com.unboundid.util.Nullable;
import com.unboundid.util.StaticUtils;
import com.unboundid.util.ThreadSafety;
import com.unboundid.util.ThreadSafetyLevel;

import static com.unboundid.ldap.sdk.unboundidds.tools.ToolMessages.*;



/**
 * This class provides an intermediate response listener that will be used to
 * handle output, archive fragment, and other types of intermediate response
 * messages returned to the client in the course of processing a collect support
 * data extended operation.
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
final class CollectSupportDataIRListener
      implements CollectSupportDataIntermediateResponseListener, Closeable
{
  /**
   * The column at which to wrap long lines.
   */
  private static final int WRAP_COLUMN = StaticUtils.TERMINAL_WIDTH_COLUMNS - 1;



  // A reference to the output file that is being written.
  @NotNull private final AtomicReference<File> outputFileReference;

  // A reference to the first IOException caught while attempting to write the
  // support data archive.
  @NotNull private final AtomicReference<IOException> firstIOExceptionReference;

  // A reference to the output stream used to write the support data archive.
  @NotNull private final AtomicReference<OutputStream> outputStreamReference;

  // The associated collect-support-data command-line tool.
  @NotNull private final CollectSupportData collectSupportData;

  // The output path that should be used when writing the support data archive
  // file.
  @Nullable private final File outputPath;

  // The total number of bytes of the support data archive that have been
  // written to the output file.
  private long totalArchiveBytesWritten;



  /**
   * Creates a new collect support data intermediate response listener to
   * handle intermediate response messages for the provided tool.
   *
   * @param  collectSupportData  The associated collect-support-data tool
   *                             instance.  It must not be {@code null}.
   * @param  outputPath          The output path that should be used when
   *                             writing the support data archive.  It may be
   *                             {@code null} if the archive should be written
   *                             into the current working directory with a
   *                             server-generated filename.  It if it is
   *                             provided, then it may specify the path to a
   *                             directory (in which case the file will be
   *                             written into that directory with a
   *                             server-generated filename) or the path to a
   *                             file (in which case that path will be used).
   *                             If it is the path to a directory, then that
   *                             directory must already exist.  If it is the
   *                             path to a file, then at least the parent
   *                             directory must already exist.
   */
  CollectSupportDataIRListener(
       @NotNull final CollectSupportData collectSupportData,
       @Nullable final File outputPath)
  {
    this.collectSupportData = collectSupportData;
    this.outputPath = outputPath;

    outputFileReference = new AtomicReference<>();
    firstIOExceptionReference = new AtomicReference<>();
    outputStreamReference = new AtomicReference<>();
    totalArchiveBytesWritten = 0L;
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public synchronized void handleOutputIntermediateResponse(
       @NotNull final CollectSupportDataOutputIntermediateResponse response)
  {
    if (response.getOutputStream() ==
         CollectSupportDataOutputStream.STANDARD_OUTPUT)
    {
      collectSupportData.wrapOut(0, WRAP_COLUMN, response.getOutputMessage());
    }
    else
    {
      collectSupportData.wrapErr(0, WRAP_COLUMN, response.getOutputMessage());
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public synchronized void handleArchiveFragmentIntermediateResponse(
       @NotNull final CollectSupportDataArchiveFragmentIntermediateResponse
            response)
  {
    File outputFile = outputFileReference.get();
    if (outputFile == null)
    {
      if (outputPath == null)
      {
        outputFile = new File(response.getArchiveFileName()).getAbsoluteFile();
      }
      else if (outputPath.exists())
      {
        if (outputPath.isDirectory())
        {
          outputFile = new File(outputPath,
               response.getArchiveFileName()).getAbsoluteFile();
        }
        else
        {
          outputFile = outputPath.getAbsoluteFile();
        }
      }
      else
      {
        outputFile = outputPath.getAbsoluteFile();
      }

      outputFileReference.set(outputFile);
    }

    OutputStream outputStream = outputStreamReference.get();
    if (outputStream == null)
    {
      try
      {
        outputStream = new FileOutputStream(outputFile);
        outputStreamReference.set(outputStream);
        collectSupportData.out();
      }
      catch (final IOException e)
      {
        Debug.debugException(e);

        if (firstIOExceptionReference.get() == null)
        {
          final String message = ERR_CSD_LISTENER_CANNOT_CREATE_OUTPUT_FILE.get(
               outputFile.getAbsolutePath(),
               StaticUtils.getExceptionMessage(e));
          final IOException ioe = new IOException(message, e);
          if (firstIOExceptionReference.compareAndSet(null, ioe))
          {
            collectSupportData.wrapErr(0, WRAP_COLUMN, message);
          }
        }
        return;
      }
    }

    try
    {
      if (firstIOExceptionReference.get() == null)
      {
        outputStream.write(response.getFragmentData());
        outputStream.flush();

        totalArchiveBytesWritten += response.getFragmentData().length;
        collectSupportData.wrapOut(0, WRAP_COLUMN,
             INFO_CSD_LISTENER_WROTE_FRAGMENT.get(totalArchiveBytesWritten,
                  response.getTotalArchiveSizeBytes(),
                  outputFile.getName()));
      }
    }
    catch (final IOException e)
    {
      Debug.debugException(e);

      if (firstIOExceptionReference.get() == null)
      {
        final String message = ERR_CSD_LISTENER_WRITE_ERROR.get(
             outputFile.getAbsolutePath(),
             StaticUtils.getExceptionMessage(e));
        final IOException ioe = new IOException(message, e);
        if (firstIOExceptionReference.compareAndSet(null, ioe))
        {
          collectSupportData.wrapErr(0, WRAP_COLUMN, message);
        }
      }
    }
  }



  /**
   * {@inheritDoc}
   */
  @Override()
  public synchronized void handleOtherIntermediateResponse(
       @NotNull final IntermediateResponse response)
  {
    collectSupportData.err();
    collectSupportData.wrapErr(0, WRAP_COLUMN,
         WARN_CSD_LISTENER_UNEXPECTED_IR.get(response.getOID()));
  }


  /**
   * Ensures that the output stream used to write the support data archive to
   * the specified output file is properly closed.
   *
   * @throws  IOException  If an IOException occurred at any point while trying
   *                       to create, write to, or close the output stream.
   */
  @Override()
  public synchronized void close()
         throws IOException
  {
    final OutputStream outputStream = outputStreamReference.getAndSet(null);
    if (outputStream != null)
    {
      try
      {
        outputStream.close();
      }
      catch (final IOException e)
      {
        Debug.debugException(e);

        if (firstIOExceptionReference.get() == null)
        {
          final String message = ERR_CSD_LISTENER_CLOSE_ERROR.get(
               outputFileReference.get().getAbsolutePath(),
               StaticUtils.getExceptionMessage(e));
          final IOException ioe = new IOException(message, e);
          if (firstIOExceptionReference.compareAndSet(null, ioe))
          {
            collectSupportData.wrapErr(0, WRAP_COLUMN, message);
          }
        }
      }
    }

    final IOException firstIOException = firstIOExceptionReference.get();
    if (firstIOException != null)
    {
      throw firstIOException;
    }
  }



  /**
   * Retrieves a reference to the output stream.  This is primarily intended for
   * testing purposes.
   *
   * @return  A reference to the output stream.
   */
  @NotNull()
  AtomicReference<OutputStream> getOutputStreamReference()
  {
    return outputStreamReference;
  }



  /**
   * Retrieves a reference to the first {@code IOException} instance caught by
   * this listener.  This is primarily intended for testing purposes.
   *
   * @return  A reference to the first {@code IOException} instance caught by
   *          this listener.
   */
  @NotNull()
  AtomicReference<IOException> getFirstIOExceptionReference()
  {
    return firstIOExceptionReference;
  }
}
