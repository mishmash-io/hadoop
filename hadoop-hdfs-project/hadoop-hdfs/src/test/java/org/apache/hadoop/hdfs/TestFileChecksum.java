/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hdfs;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileChecksum;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Options.ChecksumCombineMode;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.fs.permission.FsPermission;
import org.apache.hadoop.hdfs.protocol.DatanodeInfo;
import org.apache.hadoop.hdfs.protocol.ErasureCodingPolicy;
import org.apache.hadoop.hdfs.protocol.LocatedBlock;
import org.apache.hadoop.hdfs.protocol.LocatedBlocks;
import org.apache.hadoop.hdfs.server.datanode.DataNode;
import org.apache.hadoop.hdfs.server.datanode.DataNodeFaultInjector;
import org.apache.hadoop.test.GenericTestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hadoop.hdfs.client.HdfsClientConfigKeys;
import org.slf4j.event.Level;

import java.io.IOException;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static org.apache.hadoop.hdfs.DFSConfigKeys.DFS_BLOCK_ACCESS_TOKEN_ENABLE_KEY;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

/**
 * This test serves a prototype to demo the idea proposed so far. It creates two
 * files using the same data, one is in replica mode, the other is in stripped
 * layout. For simple, it assumes 6 data blocks in both files and the block size
 * are the same.
 */
public class TestFileChecksum {
  private static final Logger LOG = LoggerFactory
      .getLogger(TestFileChecksum.class);
  private final ErasureCodingPolicy ecPolicy =
      StripedFileTestUtil.getDefaultECPolicy();
  private int dataBlocks = ecPolicy.getNumDataUnits();
  private int parityBlocks = ecPolicy.getNumParityUnits();

  private MiniDFSCluster cluster;
  private DistributedFileSystem fs;
  private Configuration conf;
  private DFSClient client;

  private int cellSize = ecPolicy.getCellSize();
  private int stripesPerBlock = 6;
  private int blockSize = cellSize * stripesPerBlock;
  private int numBlockGroups = 10;
  private int stripSize = cellSize * dataBlocks;
  private int blockGroupSize = stripesPerBlock * stripSize;
  private int fileSize = numBlockGroups * blockGroupSize;
  private int bytesPerCRC;

  private String ecDir = "/striped";
  private String stripedFile1 = ecDir + "/stripedFileChecksum1";
  private String stripedFile2 = ecDir + "/stripedFileChecksum2";
  private String replicatedFile = "/replicatedFileChecksum";

  private String checksumCombineMode;

  public void initTestFileChecksum(String checksumCombineMode) {
    this.checksumCombineMode = checksumCombineMode;
  }

  public static Object[] getParameters() {
    return new Object[] {
        ChecksumCombineMode.MD5MD5CRC.name(),
        ChecksumCombineMode.COMPOSITE_CRC.name()};
  }

  @BeforeEach
  public void setup() throws IOException {
    int numDNs = dataBlocks + parityBlocks + 2;
    conf = new Configuration();
    conf.setLong(DFSConfigKeys.DFS_BLOCK_SIZE_KEY, blockSize);
    conf.setInt(DFSConfigKeys.DFS_NAMENODE_REPLICATION_MAX_STREAMS_KEY, 0);
    conf.setBoolean(DFS_BLOCK_ACCESS_TOKEN_ENABLE_KEY, true);
    conf.set(HdfsClientConfigKeys.DFS_CHECKSUM_COMBINE_MODE_KEY,
        checksumCombineMode);
    cluster = new MiniDFSCluster.Builder(conf).numDataNodes(numDNs).build();
    Path ecPath = new Path(ecDir);
    cluster.getFileSystem().mkdir(ecPath, FsPermission.getDirDefault());
    cluster.getFileSystem().getClient().setErasureCodingPolicy(ecDir,
        StripedFileTestUtil.getDefaultECPolicy().getName());
    fs = cluster.getFileSystem();
    client = fs.getClient();
    fs.enableErasureCodingPolicy(
        StripedFileTestUtil.getDefaultECPolicy().getName());
    bytesPerCRC = conf.getInt(
        HdfsClientConfigKeys.DFS_BYTES_PER_CHECKSUM_KEY,
        HdfsClientConfigKeys.DFS_BYTES_PER_CHECKSUM_DEFAULT);
    GenericTestUtils.setLogLevel(FileChecksumHelper.LOG, Level.DEBUG);
  }

  @AfterEach
  public void tearDown() {
    if (cluster != null) {
      cluster.shutdown();
      cluster = null;
    }
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum1(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = 0;
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, length + 10);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum2(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = stripSize - 1;
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, length - 10);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum3(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = stripSize;
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, length - 10);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum4(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = stripSize + cellSize * 2;
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, length - 10);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum5(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = blockGroupSize;
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, length - 10);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum6(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = blockGroupSize + blockSize;
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, length - 10);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksum7(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int length = -1; // whole file
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    testStripedFileChecksum(length, fileSize);
  }

  private void testStripedFileChecksum(int range1, int range2)
      throws Exception {
    FileChecksum stripedFileChecksum1 = getFileChecksum(stripedFile1,
        range1, false);
    FileChecksum stripedFileChecksum2 = getFileChecksum(stripedFile2,
        range1, false);
    FileChecksum stripedFileChecksum3 = getFileChecksum(stripedFile2,
        range2, false);

    LOG.info("stripedFileChecksum1:" + stripedFileChecksum1);
    LOG.info("stripedFileChecksum2:" + stripedFileChecksum2);
    LOG.info("stripedFileChecksum3:" + stripedFileChecksum3);

    Assertions.assertTrue(stripedFileChecksum1.equals(stripedFileChecksum2));
    if (range1 >=0 && range1 != range2) {
      Assertions.assertFalse(stripedFileChecksum1.equals(stripedFileChecksum3));
    }
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedAndReplicatedFileChecksum(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    prepareTestFiles(fileSize, new String[] {stripedFile1, replicatedFile});
    FileChecksum stripedFileChecksum1 = getFileChecksum(stripedFile1,
        10, false);
    FileChecksum replicatedFileChecksum = getFileChecksum(replicatedFile,
        10, false);

    if (checksumCombineMode.equals(ChecksumCombineMode.COMPOSITE_CRC.name())) {
      Assertions.assertEquals(stripedFileChecksum1, replicatedFileChecksum);
    } else {
      Assertions.assertNotEquals(stripedFileChecksum1, replicatedFileChecksum);
    }
  }

  /**
   * Test the corner case of the COMPOSITE_CRC.
   * For Stripe File, last block size in the file is (int)(blockSize * 0.5),
   *    but the last block size in the check length is (int)(blockSize * 0.6).
   * For Replicate File, the last block size in the file is (int)(blockSize * 0.5),
   *    but the last block size in the check length is ((dataBlocks - 1) * blockSize
   *    + (int) (blockSize * 0.6))
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedAndReplicatedFileChecksum2(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    final int lastBlockSize = (int) (blockSize * 0.5);
    final int fullStripeLength = dataBlocks * blockSize;
    final int testFileSize = fullStripeLength + lastBlockSize;
    prepareTestFiles(testFileSize, new String[] {stripedFile1, replicatedFile});

    final int specialLength = (dataBlocks - 1) * blockSize
        + (int) (blockSize * 0.6);

    Assertions.assertTrue(specialLength % blockSize > lastBlockSize);
    Assertions.assertTrue(specialLength % fullStripeLength > lastBlockSize);

    FileChecksum stripedFileChecksum = getFileChecksum(stripedFile1,
        specialLength, false);
    FileChecksum replicatedFileChecksum = getFileChecksum(replicatedFile,
        specialLength, false);

    if (checksumCombineMode.equals(ChecksumCombineMode.COMPOSITE_CRC.name())) {
      Assertions.assertEquals(replicatedFileChecksum, stripedFileChecksum);
    } else {
      Assertions.assertNotEquals(replicatedFileChecksum, stripedFileChecksum);
    }
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testDifferentBlockSizeReplicatedFileChecksum(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    byte[] fileData = StripedFileTestUtil.generateBytes(fileSize);
    String replicatedFile1 = "/replicatedFile1";
    String replicatedFile2 = "/replicatedFile2";
    DFSTestUtil.writeFile(
        fs, new Path(replicatedFile1), fileData, blockSize);
    DFSTestUtil.writeFile(
        fs, new Path(replicatedFile2), fileData, blockSize / 2);
    FileChecksum checksum1 = getFileChecksum(replicatedFile1, -1, false);
    FileChecksum checksum2 = getFileChecksum(replicatedFile2, -1, false);

    if (checksumCombineMode.equals(ChecksumCombineMode.COMPOSITE_CRC.name())) {
      Assertions.assertEquals(checksum1, checksum2);
    } else {
      Assertions.assertNotEquals(checksum1, checksum2);
    }
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocks1(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    prepareTestFiles(fileSize, new String[] {stripedFile1});
    FileChecksum stripedFileChecksum1 = getFileChecksum(stripedFile1, fileSize,
        false);
    FileChecksum stripedFileChecksumRecon = getFileChecksum(stripedFile1,
        fileSize, true);

    LOG.info("stripedFileChecksum1:" + stripedFileChecksum1);
    LOG.info("stripedFileChecksumRecon:" + stripedFileChecksumRecon);

    Assertions.assertTrue(stripedFileChecksum1.equals(stripedFileChecksumRecon),
        "Checksum mismatches!");
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocks2(String checksumCombineMode) throws Exception {
    initTestFileChecksum(checksumCombineMode);
    prepareTestFiles(fileSize, new String[] {stripedFile1, stripedFile2});
    FileChecksum stripedFileChecksum1 = getFileChecksum(stripedFile1, -1,
        false);
    FileChecksum stripedFileChecksum2 = getFileChecksum(stripedFile2, -1,
        false);
    FileChecksum stripedFileChecksum2Recon = getFileChecksum(stripedFile2, -1,
        true);

    LOG.info("stripedFileChecksum1:" + stripedFileChecksum1);
    LOG.info("stripedFileChecksum2:" + stripedFileChecksum1);
    LOG.info("stripedFileChecksum2Recon:" + stripedFileChecksum2Recon);

    Assertions.assertTrue(stripedFileChecksum1.equals(stripedFileChecksum2),
        "Checksum mismatches!");
    Assertions.assertTrue(stripedFileChecksum1.equals(stripedFileChecksum2Recon),
        "Checksum mismatches!");
    Assertions.assertTrue(stripedFileChecksum2.equals(stripedFileChecksum2Recon),
        "Checksum mismatches!");
  }

  private void testStripedFileChecksumWithMissedDataBlocksRangeQuery(
      String stripedFile, int requestedLen) throws Exception {
    LOG.info("Checksum file:{}, requested length:{}", stripedFile,
        requestedLen);
    prepareTestFiles(fileSize, new String[] {stripedFile});
    FileChecksum stripedFileChecksum1 = getFileChecksum(stripedFile,
        requestedLen, false);
    FileChecksum stripedFileChecksumRecon = getFileChecksum(stripedFile,
        requestedLen, true);

    LOG.info("stripedFileChecksum1:" + stripedFileChecksum1);
    LOG.info("stripedFileChecksumRecon:" + stripedFileChecksumRecon);

    Assertions.assertTrue(stripedFileChecksum1.equals(stripedFileChecksumRecon),
        "Checksum mismatches!");
  }

  /**
   * Test to verify that the checksum can be computed for a small file less than
   * bytesPerCRC size.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery1(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1, 1);
  }

  /**
   * Test to verify that the checksum can be computed for a small file less than
   * bytesPerCRC size.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery2(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1, 10);
  }

  /**
   * Test to verify that the checksum can be computed by giving bytesPerCRC
   * length of file range for checksum calculation. 512 is the value of
   * bytesPerCRC.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery3(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        bytesPerCRC);
  }

  /**
   * Test to verify that the checksum can be computed by giving 'cellsize'
   * length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery4(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        cellSize);
  }

  /**
   * Test to verify that the checksum can be computed by giving less than
   * cellsize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery5(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        cellSize - 1);
  }

  /**
   * Test to verify that the checksum can be computed by giving greater than
   * cellsize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery6(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        cellSize + 1);
  }

  /**
   * Test to verify that the checksum can be computed by giving two times
   * cellsize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery7(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        cellSize * 2);
  }

  /**
   * Test to verify that the checksum can be computed by giving stripSize
   * length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery8(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        stripSize);
  }

  /**
   * Test to verify that the checksum can be computed by giving less than
   * stripSize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery9(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        stripSize - 1);
  }

  /**
   * Test to verify that the checksum can be computed by giving greater than
   * stripSize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery10(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        stripSize + 1);
  }

  /**
   * Test to verify that the checksum can be computed by giving less than
   * blockGroupSize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery11(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        blockGroupSize - 1);
  }

  /**
   * Test to verify that the checksum can be computed by giving greaterthan
   * blockGroupSize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery12(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        blockGroupSize + 1);
  }

  /**
   * Test to verify that the checksum can be computed by giving greater than
   * blockGroupSize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery13(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        blockGroupSize * numBlockGroups / 2);
  }

  /**
   * Test to verify that the checksum can be computed by giving lessthan
   * fileSize length of file range for checksum calculation.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery14(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        fileSize - 1);
  }

  /**
   * Test to verify that the checksum can be computed for a length greater than
   * file size.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery15(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile1,
        fileSize * 2);
  }

  /**
   * Test to verify that the checksum can be computed for a small file less than
   * bytesPerCRC size.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery16(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int fileLength = 100;
    String stripedFile3 = ecDir + "/stripedFileChecksum3";
    prepareTestFiles(fileLength, new String[] {stripedFile3});
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile3,
        fileLength - 1);
  }

  /**
   * Test to verify that the checksum can be computed for a small file less than
   * bytesPerCRC size.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery17(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int fileLength = 100;
    String stripedFile3 = ecDir + "/stripedFileChecksum3";
    prepareTestFiles(fileLength, new String[] {stripedFile3});
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile3, 1);
  }

  /**
   * Test to verify that the checksum can be computed for a small file less than
   * bytesPerCRC size.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery18(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int fileLength = 100;
    String stripedFile3 = ecDir + "/stripedFileChecksum3";
    prepareTestFiles(fileLength, new String[] {stripedFile3});
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile3, 10);
  }

  /**
   * Test to verify that the checksum can be computed with greater than file
   * length.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery19(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int fileLength = 100;
    String stripedFile3 = ecDir + "/stripedFileChecksum3";
    prepareTestFiles(fileLength, new String[] {stripedFile3});
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile3,
        fileLength * 2);
  }

  /**
   * Test to verify that the checksum can be computed for small file with less
   * than file length.
   */
  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithMissedDataBlocksRangeQuery20(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    int fileLength = bytesPerCRC;
    String stripedFile3 = ecDir + "/stripedFileChecksum3";
    prepareTestFiles(fileLength, new String[] {stripedFile3});
    testStripedFileChecksumWithMissedDataBlocksRangeQuery(stripedFile3,
        bytesPerCRC - 1);
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testStripedFileChecksumWithReconstructFail(String checksumCombineMode)
      throws Exception {
    initTestFileChecksum(checksumCombineMode);
    String stripedFile4 = ecDir + "/stripedFileChecksum4";
    prepareTestFiles(fileSize, new String[] {stripedFile4});

    // get checksum
    FileChecksum fileChecksum = getFileChecksum(stripedFile4, -1, false);

    DataNodeFaultInjector oldInjector = DataNodeFaultInjector.get();
    DataNodeFaultInjector newInjector = mock(DataNodeFaultInjector.class);
    doThrow(new IOException())
        .doNothing()
        .when(newInjector)
        .stripedBlockChecksumReconstruction();
    DataNodeFaultInjector.set(newInjector);

    try {
      // Get checksum again with reconstruction.
      // If the reconstruction task fails, a client try to get checksum from
      // another DN which has a block of the block group because of a failure of
      // getting result.
      FileChecksum fileChecksum1 = getFileChecksum(stripedFile4, -1, true);

      Assertions.assertEquals(fileChecksum,
          fileChecksum1,
          "checksum should be same");
    } finally {
      DataNodeFaultInjector.set(oldInjector);
    }
  }

  @MethodSource("getParameters")
  @ParameterizedTest
  @Timeout(value = 90000, unit = TimeUnit.MILLISECONDS)
  public void testMixedBytesPerChecksum(String checksumCombineMode) {
    assertThrows(IOException.class, () -> {
      initTestFileChecksum(checksumCombineMode);
      int fileLength = bytesPerCRC * 3;
      byte[] fileData = StripedFileTestUtil.generateBytes(fileLength);
      String replicatedFile1 = "/replicatedFile1";

      // Split file into two parts.
      byte[] fileDataPart1 = new byte[bytesPerCRC * 2];
      System.arraycopy(fileData, 0, fileDataPart1, 0, fileDataPart1.length);
      byte[] fileDataPart2 = new byte[fileData.length - fileDataPart1.length];
      System.arraycopy(
          fileData, fileDataPart1.length, fileDataPart2, 0, fileDataPart2.length);

      DFSTestUtil.writeFile(fs, new Path(replicatedFile1), fileDataPart1);

      // Modify bytesPerCRC for second part that we append as separate block.
      conf.setInt(
          HdfsClientConfigKeys.DFS_BYTES_PER_CHECKSUM_KEY, bytesPerCRC / 2);
      DFSTestUtil.appendFileNewBlock(
          ((DistributedFileSystem) FileSystem.newInstance(conf)),
          new Path(replicatedFile1), fileDataPart2);

      if (checksumCombineMode.equals(ChecksumCombineMode.COMPOSITE_CRC.name())) {
        String replicatedFile2 = "/replicatedFile2";
        DFSTestUtil.writeFile(fs, new Path(replicatedFile2), fileData);
        FileChecksum checksum1 = getFileChecksum(replicatedFile1, -1, false);
        FileChecksum checksum2 = getFileChecksum(replicatedFile2, -1, false);
        Assertions.assertEquals(checksum1, checksum2);
      } else {
        exception.expect(IOException.class);
        FileChecksum checksum = getFileChecksum(replicatedFile1, -1, false);
      }
    });
  }

  private FileChecksum getFileChecksum(String filePath, int range,
                                       boolean killDn) throws Exception {
    int dnIdxToDie = -1;
    if (killDn) {
      dnIdxToDie = getDataNodeToKill(filePath);
      DataNode dnToDie = cluster.getDataNodes().get(dnIdxToDie);
      shutdownDataNode(dnToDie);
    }

    Path testPath = new Path(filePath);
    FileChecksum fc;

    if (range >= 0) {
      fc = fs.getFileChecksum(testPath, range);
    } else {
      fc = fs.getFileChecksum(testPath);
    }

    if (dnIdxToDie != -1) {
      cluster.restartDataNode(dnIdxToDie);
    }

    return fc;
  }

  private void prepareTestFiles(int fileLength, String[] filePaths)
      throws IOException {
    byte[] fileData = StripedFileTestUtil.generateBytes(fileLength);

    for (String filePath : filePaths) {
      Path testPath = new Path(filePath);
      DFSTestUtil.writeFile(fs, testPath, fileData);
    }
  }

  void shutdownDataNode(DataNode dataNode) throws IOException {
    /*
     * Kill the datanode which contains one replica
     * We need to make sure it dead in namenode: clear its update time and
     * trigger NN to check heartbeat.
     */
    dataNode.shutdown();
    cluster.setDataNodeDead(dataNode.getDatanodeId());
  }

  /**
   * Determine the datanode that hosts the first block of the file. For simple
   * this just returns the first datanode as it's firstly tried.
   */
  int getDataNodeToKill(String filePath) throws IOException {
    LocatedBlocks locatedBlocks = client.getLocatedBlocks(filePath, 0);

    LocatedBlock locatedBlock = locatedBlocks.get(0);
    DatanodeInfo[] datanodes = locatedBlock.getLocations();
    DatanodeInfo chosenDn = datanodes[new Random().nextInt(datanodes.length)];

    int idx = 0;
    for (DataNode dn : cluster.getDataNodes()) {
      if (dn.getInfoPort() == chosenDn.getInfoPort()) {
        return idx;
      }
      idx++;
    }

    return -1;
  }
}
