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
package org.apache.hadoop.util.curator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.CommonConfigurationKeys;
import org.apache.hadoop.security.alias.CredentialProvider;
import org.apache.hadoop.security.alias.CredentialProviderFactory;
import org.apache.hadoop.security.alias.LocalJavaKeyStoreProvider;
import org.apache.hadoop.test.GenericTestUtils;
import org.apache.zookeeper.ZooDefs.Perms;
import org.apache.zookeeper.data.ACL;
import org.junit.jupiter.api.Test;
import org.apache.hadoop.thirdparty.com.google.common.io.Files;
import org.apache.hadoop.util.curator.ZKUtil.BadAclFormatException;
import org.apache.hadoop.util.curator.ZKUtil.ZKAuthInfo;

public class TestZKUtil {
  private static final String TEST_ROOT_DIR = GenericTestUtils.getTempPath(
      "TestZKUtil");
  private static final File TEST_FILE = new File(TEST_ROOT_DIR,
      "test-file");
  private static final String ZK_AUTH_VALUE = "a_scheme:a_password";
  
  /** A path which is expected not to exist */
  private static final String BOGUS_FILE =
      new File("/xxxx-this-does-not-exist").getPath();

  @Test
  public void testEmptyACL() {
    List<ACL> result = ZKUtil.parseACLs("");
    assertTrue(result.isEmpty());
  }
  
  @Test
  public void testNullACL() {
    List<ACL> result = ZKUtil.parseACLs(null);
    assertTrue(result.isEmpty());
  }
  
  @Test
  public void testInvalidACLs() {
    badAcl("a:b",
        "ACL 'a:b' not of expected form scheme:id:perm"); // not enough parts
    badAcl("a",
        "ACL 'a' not of expected form scheme:id:perm"); // not enough parts
    badAcl("password:foo:rx",
        "Invalid permission 'x' in permission string 'rx'");
  }
  
  private static void badAcl(String acls, String expectedErr) {
    try {
      ZKUtil.parseACLs(acls);
      fail("Should have failed to parse '" + acls + "'");
    } catch (BadAclFormatException e) {
      assertEquals(expectedErr, e.getMessage());
    }
  }

  @Test
  public void testRemoveSpecificPerms() {
    int perms = Perms.ALL;
    int remove = Perms.CREATE;
    int newPerms = ZKUtil.removeSpecificPerms(perms, remove);
    assertEquals(0, newPerms & Perms.CREATE, "Removal failed");
  }

  @Test
  public void testGoodACLs() {
    List<ACL> result = ZKUtil.parseACLs(
        "sasl:hdfs/host1@MY.DOMAIN:cdrwa, sasl:hdfs/host2@MY.DOMAIN:ca");
    ACL acl0 = result.get(0);
    assertEquals(Perms.CREATE | Perms.DELETE | Perms.READ |
        Perms.WRITE | Perms.ADMIN, acl0.getPerms());
    assertEquals("sasl", acl0.getId().getScheme());
    assertEquals("hdfs/host1@MY.DOMAIN", acl0.getId().getId());
    
    ACL acl1 = result.get(1);
    assertEquals(Perms.CREATE | Perms.ADMIN, acl1.getPerms());
    assertEquals("sasl", acl1.getId().getScheme());
    assertEquals("hdfs/host2@MY.DOMAIN", acl1.getId().getId());
  }
  
  @Test
  public void testEmptyAuth() {
    List<ZKAuthInfo> result = ZKUtil.parseAuth("");
    assertTrue(result.isEmpty());
  }
  
  @Test
  public void testNullAuth() {
    List<ZKAuthInfo> result = ZKUtil.parseAuth(null);
    assertTrue(result.isEmpty());
  }
  
  @Test
  public void testGoodAuths() {
    List<ZKAuthInfo> result = ZKUtil.parseAuth(
        "scheme:data,\n   scheme2:user:pass");
    assertEquals(2, result.size());
    ZKAuthInfo auth0 = result.get(0);
    assertEquals("scheme", auth0.getScheme());
    assertEquals("data", new String(auth0.getAuth()));
    
    ZKAuthInfo auth1 = result.get(1);
    assertEquals("scheme2", auth1.getScheme());
    assertEquals("user:pass", new String(auth1.getAuth()));
  }
  
  @Test
  public void testConfIndirection() throws IOException {
    assertNull(ZKUtil.resolveConfIndirection(null));
    assertEquals("x", ZKUtil.resolveConfIndirection("x"));
    
    TEST_FILE.getParentFile().mkdirs();
    Files.asCharSink(TEST_FILE, StandardCharsets.UTF_8).write("hello world");
    assertEquals("hello world", ZKUtil.resolveConfIndirection(
        "@" + TEST_FILE.getAbsolutePath()));
    
    try {
      ZKUtil.resolveConfIndirection("@" + BOGUS_FILE);
      fail("Did not throw for non-existent file reference");
    } catch (FileNotFoundException fnfe) {
      assertTrue(fnfe.getMessage().startsWith(BOGUS_FILE));
    }
  }

  @Test
  public void testAuthPlainPasswordProperty() throws Exception {
    Configuration conf = new Configuration();
    conf.set(CommonConfigurationKeys.ZK_AUTH, ZK_AUTH_VALUE);
    List<ZKAuthInfo> zkAuths = ZKUtil.getZKAuthInfos(conf,
        CommonConfigurationKeys.ZK_AUTH);
    assertEquals(1, zkAuths.size());
    ZKAuthInfo zkAuthInfo = zkAuths.get(0);
    assertEquals("a_scheme", zkAuthInfo.getScheme());
    assertArrayEquals("a_password".getBytes(), zkAuthInfo.getAuth());
  }

  @Test
  public void testAuthPlainTextFile() throws Exception {
    Configuration conf = new Configuration();
    File passwordTxtFile = File.createTempFile(
        getClass().getSimpleName() +  ".testAuthAtPathNotation-", ".txt");
    Files.asCharSink(passwordTxtFile, StandardCharsets.UTF_8)
        .write(ZK_AUTH_VALUE);
    try {
      conf.set(CommonConfigurationKeys.ZK_AUTH,
          "@" + passwordTxtFile.getAbsolutePath());
      List<ZKAuthInfo> zkAuths = ZKUtil.getZKAuthInfos(conf,
          CommonConfigurationKeys.ZK_AUTH);
      assertEquals(1, zkAuths.size());
      ZKAuthInfo zkAuthInfo = zkAuths.get(0);
      assertEquals("a_scheme", zkAuthInfo.getScheme());
      assertArrayEquals("a_password".getBytes(), zkAuthInfo.getAuth());
    } finally {
      boolean deleted = passwordTxtFile.delete();
      assertTrue(deleted);
    }
  }

  @Test
  public void testAuthLocalJceks() throws Exception {
    File localJceksFile = File.createTempFile(
        getClass().getSimpleName() +".testAuthLocalJceks-", ".localjceks");
    populateLocalJceksTestFile(localJceksFile.getAbsolutePath());
    try {
      String localJceksUri = "localjceks://file/" +
          localJceksFile.getAbsolutePath();
      Configuration conf = new Configuration();
      conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
          localJceksUri);
      List<ZKAuthInfo> zkAuths = ZKUtil.getZKAuthInfos(conf,
          CommonConfigurationKeys.ZK_AUTH);
      assertEquals(1, zkAuths.size());
      ZKAuthInfo zkAuthInfo = zkAuths.get(0);
      assertEquals("a_scheme", zkAuthInfo.getScheme());
      assertArrayEquals("a_password".getBytes(), zkAuthInfo.getAuth());
    } finally {
      boolean deleted = localJceksFile.delete();
      assertTrue(deleted);
    }
  }

  private void populateLocalJceksTestFile(String path) throws IOException {
    Configuration conf = new Configuration();
    conf.set(CredentialProviderFactory.CREDENTIAL_PROVIDER_PATH,
        "localjceks://file/" + path);
    CredentialProvider provider =
        CredentialProviderFactory.getProviders(conf).get(0);
    assertEquals(LocalJavaKeyStoreProvider.class.getName(),
        provider.getClass().getName());
    provider.createCredentialEntry(CommonConfigurationKeys.ZK_AUTH,
        ZK_AUTH_VALUE.toCharArray());
    provider.flush();
  }
}
