/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. See accompanying LICENSE file.
 */
package org.apache.hadoop.security.authentication.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.apache.hadoop.security.authentication.client.AuthenticatorTestCase.Scheme;
import org.apache.hadoop.security.authentication.client.KerberosAuthenticator.KerberosConfiguration;
import org.apache.hadoop.security.authentication.server.AuthenticationFilter;
import org.apache.hadoop.security.authentication.util.KerberosUtil;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.auth.AuthScope;
import org.apache.hc.client5.http.auth.Credentials;
import org.apache.hc.client5.http.auth.KerberosConfig;
import org.apache.hc.client5.http.auth.StandardAuthScheme;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.client5.http.impl.auth.SPNegoScheme;
import org.apache.hc.client5.http.impl.StateHolder;
import org.apache.hc.client5.http.impl.auth.BasicCredentialsProvider;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.protocol.HttpClientContext;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.ContentType;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.eclipse.jetty.ee10.servlet.FilterHolder;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.ee10.servlet.ServletHolder;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Serializable;
import java.io.InputStreamReader;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URL;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.EnumSet;
import java.util.List;
import java.util.Properties;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;

public class AuthenticatorTestCase {
  private Server server;
  private String host = null;
  private int port = -1;
  ServletContextHandler context;

  private static Properties authenticatorConfig;

  public AuthenticatorTestCase() {}

  protected static void setAuthenticationHandlerConfig(Properties config) {
    authenticatorConfig = config;
  }

  public static class TestFilter extends AuthenticationFilter {

    @Override
    protected Properties getConfiguration(String configPrefix, FilterConfig filterConfig) throws ServletException {
      return authenticatorConfig;
    }
  }

  @SuppressWarnings("serial")
  public static class TestServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      resp.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
      InputStream is = req.getInputStream();
      OutputStream os = resp.getOutputStream();
      int c = is.read();
      while (c > -1) {
        os.write(c);
        c = is.read();
      }
      is.close();
      os.close();
      resp.setStatus(HttpServletResponse.SC_OK);
    }
  }

  protected int getLocalPort() throws Exception {
    ServerSocket ss = new ServerSocket(0);
    int ret = ss.getLocalPort();
    ss.close();
    return ret;
  }

  protected void start() throws Exception {
    startJetty();
  }

  protected void startJetty() throws Exception {
    server = new Server();
    context = new ServletContextHandler();
    context.setContextPath("/foo");
    server.setHandler(context);
    context.addFilter(new FilterHolder(TestFilter.class), "/*",
        EnumSet.of(DispatcherType.REQUEST));
    context.addServlet(new ServletHolder(TestServlet.class), "/bar");
    host = "localhost";
    port = getLocalPort();
    ServerConnector connector = new ServerConnector(server);
    connector.setHost(host);
    connector.setPort(port);
    server.setConnectors(new Connector[] {connector});
    server.start();
    System.out.println("Running embedded servlet container at: http://" + host + ":" + port);
  }

  protected void stop() throws Exception {
    stopJetty();
  }

  protected void stopJetty() throws Exception {
    try {
      server.stop();
    } catch (Exception e) {
    }

    try {
      server.destroy();
    } catch (Exception e) {
    }
  }

  protected String getBaseURL() {
    return "http://" + host + ":" + port + "/foo/bar";
  }

  private static class TestConnectionConfigurator
      implements ConnectionConfigurator {
    boolean invoked;

    @Override
    public HttpURLConnection configure(HttpURLConnection conn)
        throws IOException {
      invoked = true;
      return conn;
    }
  }

  private String POST = "test";

  protected void _testAuthentication(Authenticator authenticator, boolean doPost) throws Exception {
    start();
    try {
      URL url = new URL(getBaseURL());
      AuthenticatedURL.Token token = new AuthenticatedURL.Token();
      assertFalse(token.isSet());
      TestConnectionConfigurator connConf = new TestConnectionConfigurator();
      AuthenticatedURL aUrl = new AuthenticatedURL(authenticator, connConf);
      HttpURLConnection conn = aUrl.openConnection(url, token);
      assertTrue(connConf.invoked);
      String tokenStr = token.toString();
      if (doPost) {
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
      }
      conn.connect();
      if (doPost) {
        Writer writer = new OutputStreamWriter(conn.getOutputStream());
        writer.write(POST);
        writer.close();
      }
      assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
      if (doPost) {
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String echo = reader.readLine();
        assertEquals(POST, echo);
        assertNull(reader.readLine());
      }
      aUrl = new AuthenticatedURL();
      conn = aUrl.openConnection(url, token);
      conn.connect();
      assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
      assertEquals(tokenStr, token.toString());
    } finally {
      stop();
    }
  }

  /**
   * This Authentication scheme is used by the Apache httpclient5 module and is based on
   * the {@link KerberosAuthenticator}. More specifically, on its doSpnegoSequence() metohd.
   *
   * As this scheme reuses the KerberosAuthenticator's inner KerberosConfiguration class -
   * it has to be public.
   */
  public static class Scheme extends SPNegoScheme implements StateHolder<Object>, Serializable {

    private static final long serialVersionUID = -5355304419188224993L;

    public Scheme() {
      super(
        KerberosConfig
          .custom()
          .setStripPort(true)
          .setUseCanonicalHostname(true)
          .build(),
        SystemDefaultDnsResolver.INSTANCE);
    }

    @Override
    protected byte[] generateGSSToken(byte[] input, Oid oid, String serviceName, String authServer)
            throws GSSException {
      try {
        AccessControlContext context = AccessController.getContext();
        Subject subject = Subject.getSubject(context);
        if (subject == null
            || (!KerberosUtil.hasKerberosKeyTab(subject)
                && !KerberosUtil.hasKerberosTicket(subject))) {
          subject = new Subject();
          LoginContext login = new LoginContext("", subject,
              null, new KerberosConfiguration());
          login.login();
        }

        return Subject.doAs(subject, new PrivilegedExceptionAction<byte[]> () {
          @Override
          public byte[] run() throws Exception {
            GSSContext gssContext = null;
            try {
              GSSManager gssManager = GSSManager.getInstance();
              String servicePrincipal = KerberosUtil.getServicePrincipal("HTTP",
                    "localhost");
              GSSName gssServiceName = gssManager.createName(servicePrincipal,
                                                  KerberosUtil.NT_GSS_KRB5_PRINCIPAL_OID);
              gssContext = gssManager.createContext(gssServiceName,
                                                  KerberosUtil.GSS_KRB5_MECH_OID,
                                                  null,
                                                  GSSContext.DEFAULT_LIFETIME);
              gssContext.requestCredDeleg(true);
              gssContext.requestMutualAuth(true);

              if (input != null) {
                return gssContext.initSecContext(input, 0, input.length);
              }

              return gssContext.initSecContext(new byte[] {}, 0, 0);
            } finally {
              if (gssContext != null) {
                gssContext.dispose();
              }
            }
          }
        });
      } catch (Exception e) {
        GSSException gsse = new GSSException(GSSException.FAILURE, 1000, e.getMessage());
        gsse.initCause(e);
        throw gsse;
      }
    }

    @Override
    public Object store() {
        // no-op
        return null;
    }

    @Override
    public void restore(Object state) {
        // no-op
    }
  }

  private HttpClientContext getHttpClientContext() throws Exception {
    HttpClientContext ctx = HttpClientContext.create();

    Credentials useJaasCreds = new Credentials() {
        public char[] getPassword() {
          return null;
        }
        public Principal getUserPrincipal() {
          return null;
        }
    };

    BasicCredentialsProvider jaasCredentialProvider
          = new BasicCredentialsProvider();
    jaasCredentialProvider.setCredentials(new AuthScope(null, host, port, null, null), useJaasCreds);
    // Set credential provider
    ctx.setCredentialsProvider(jaasCredentialProvider);
    ctx.setAuthSchemeRegistry(
            s-> httpContext -> new Scheme());
    // Configure Auth scheme preferences to include SPNEGO
    ctx.setRequestConfig(
            RequestConfig
                .copy(ctx.getRequestConfigOrDefault())
                .setAuthenticationEnabled(true)
                .setTargetPreferredAuthSchemes(List.of(StandardAuthScheme.SPNEGO)).build());

    return ctx;
  }

  private void doHttpClientRequest(CloseableHttpClient httpClient, HttpUriRequest request, HttpClientContext ctx) throws Exception {
    httpClient.execute(request, ctx, response -> {
        final int httpStatus = response.getCode();
        assertEquals(HttpURLConnection.HTTP_OK, httpStatus);
        EntityUtils.consumeQuietly(response.getEntity());
        return null;
    });
  }

  protected void _testAuthenticationHttpClient(Authenticator authenticator, boolean doPost) throws Exception {
    start();
    try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
      doHttpClientRequest(httpClient, new HttpGet(getBaseURL()), getHttpClientContext());

      // Always do a GET before POST to trigger the SPNego negotiation
      if (doPost) {
        HttpPost post = new HttpPost(getBaseURL());
        byte [] postBytes = POST.getBytes();
        ByteArrayInputStream bis = new ByteArrayInputStream(postBytes);
        InputStreamEntity entity = new InputStreamEntity(bis, postBytes.length, ContentType.APPLICATION_OCTET_STREAM);

        // Important that the entity is not repeatable -- this means if
        // we have to renegotiate (e.g. b/c the cookie wasn't handled properly)
        // the test will fail.
        assertFalse(entity.isRepeatable());
        post.setEntity(entity);
        doHttpClientRequest(httpClient, post, getHttpClientContext());
      }
    } finally {
      stop();
    }
  }
}
