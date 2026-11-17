/** Portions Copyright Payara Services Limited **/
package org.javaee7;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Various high level Java EE 7 samples specific operations to execute against
 * the various servers used for running the samples
 *
 * @author arjan
 *
 */
public class ServerOperations {

    private static final Logger logger = Logger.getLogger(ServerOperations.class.getName());

    /**
     * Add the default test user and credentials to the identity store of
     * supported containers
     */
    public static void addUsersToContainerIdentityStore() {

        // TODO: abstract adding container managed users to utility class
        // TODO: consider PR for sending CLI commands to Arquillian

        String javaEEServer = System.getProperty("javaEEServer");

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            System.out.println("Adding user for glassfish-remote");

            if ("payara-remote".equals(javaEEServer) && !isAdminPortListening()) {
                // E.g. a managed server that Arquillian starts after this has run. asadmin can't create the user
                // without a running server, so add it to the key file, which the server reads at startup
                addUserToPayaraKeyFile();
                return;
            }

            List<String> cmd = new ArrayList<>();

            cmd.add("create-file-user");
            cmd.add("--groups");
            cmd.add("g1");
            cmd.add("--passwordfile");
            cmd.add(Paths.get("").toAbsolutePath() + "/src/test/resources/password.txt");

            cmd.add("u1");

            CliCommands.payaraGlassFish(cmd);
        } else if ("payara-embedded".equals(javaEEServer)) {
            addUserToEmbeddedFileRealm("u1", "p1", "g1");
        } else {
            if (javaEEServer == null) {
                System.out.println("javaEEServer not specified");
            } else {
                System.out.println(javaEEServer + " not supported");
            }
        }

        // TODO: support other servers than Payara and GlassFish

        // WildFly ./bin/add-user.sh -a -u u1 -p p1 -g g1
    }

    // Entry as written by "asadmin create-file-user --groups g1 u1" for password p1. It includes its own salt.
    private static final String PAYARA_KEY_FILE_ENTRY_U1 = "u1;{SSHA256}GeKSR7Ub2ukaMCrJx/3BDyd321K6LknxwBUXGjcsCgecbni4VapZ2Q==;g1";

    private static boolean isAdminPortListening() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", 4848), 500);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Adds the default test user directly to the file realm key file of a Payara server that isn't running yet.
     */
    private static void addUserToPayaraKeyFile() {
        String gfHome = System.getProperty("payara.home");
        if (gfHome == null) {
            logger.info("payara.home not specified, can't add user to key file");
            return;
        }

        String domain = System.getProperty("payara_domain", "domain1");
        Path keyFile = Paths.get(gfHome, "glassfish", "domains", domain, "config", "keyfile");
        if (!keyFile.toFile().exists()) {
            logger.severe("The key file at " + keyFile.toAbsolutePath() + " does not exist. Is the domain \"" + domain + "\" correct?");
            return;
        }

        try {
            if (Files.readAllLines(keyFile, StandardCharsets.UTF_8).stream().anyMatch(line -> line.startsWith("u1;"))) {
                return;
            }

            Files.write(keyFile, (PAYARA_KEY_FILE_ENTRY_U1 + System.lineSeparator()).getBytes(StandardCharsets.UTF_8),
                        java.nio.file.StandardOpenOption.APPEND);
            logger.info("Added user u1 to " + keyFile.toAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException("Could not add user to key file " + keyFile, e);
        }
    }

    /**
     * The embedded server runs in the test JVM, so the file realm can be called directly. Reflection is used
     * as the embedded server is not a dependency of this module.
     */
    private static void addUserToEmbeddedFileRealm(String user, String password, String group) {
        try {
            Object realm = Class.forName("com.sun.enterprise.security.auth.realm.Realm")
                                .getMethod("getInstance", String.class)
                                .invoke(null, "file");

            realm.getClass()
                 .getMethod("addUser", String.class, char[].class, String[].class)
                 .invoke(realm, user, password.toCharArray(), new String[] { group });

            realm.getClass().getMethod("persist").invoke(realm);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Could not add user to embedded file realm", e);
        }
    }

    public static void addCertificateToContainerTrustStore(Certificate clientCertificate) {

        String javaEEServer = System.getProperty("javaEEServer");

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            String gfHome = System.getProperty("payara.home");
            if (gfHome == null) {
                logger.info("payara.home not specified");
                return;
            }

            Path gfHomePath = Paths.get(gfHome);
            if (!gfHomePath.toFile().exists()) {
                logger.severe("payara.home at " + gfHome + " does not exists");
                return;
            }

            if (!gfHomePath.toFile().isDirectory()) {
                logger.severe("payara.home at " + gfHome + " is not a directory");
                return;
            }

            String domain = System.getProperty("payara_domain");
            if (domain == null) {
                domain = getPayaraDomainFromServer();
                logger.info("Using domain \"" + domain + "\" obtained from server. If this is not correct use -Dpayara_domain to override.");
            }

            Path cacertsPath = gfHomePath.resolve("glassfish/domains/" + domain + "/config/cacerts.p12");

            if (!cacertsPath.toFile().exists()) {
                logger.severe("The container trust store at " + cacertsPath.toAbsolutePath() + " does not exists");
                logger.severe("Is the domain \"" + domain + "\" correct?");
                return;
            }

            logger.info("*** Adding certificate to container trust store: " + cacertsPath.toAbsolutePath());

            KeyStore keyStore = null;
            try (InputStream in = new FileInputStream(cacertsPath.toAbsolutePath().toFile())) {
                keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(in, "changeit".toCharArray());

                keyStore.setCertificateEntry("arquillianClientTestCert", clientCertificate);

                keyStore.store(new FileOutputStream(cacertsPath.toAbsolutePath().toFile()), "changeit".toCharArray());
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
                throw new IllegalStateException(e);
            }

            restartContainer(domain);
        } else {
            if (javaEEServer == null) {
                System.out.println("javaEEServer not specified");
            } else {
                System.out.println(javaEEServer + " not supported");
            }
        }

    }

    public static URL toContainerHttps(URL url) {
        if ("https".equals(url.getProtocol())) {
            return url;
        }

        String javaEEServer = System.getProperty("javaEEServer");

        // String protocol, String host, int port, String file

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            try {
                URL httpsUrl = new URL(
                    "https",
                    url.getHost(),
                    8181,
                    url.getFile()
                );

                System.out.println("Changing base URL from " + url + " into " + httpsUrl);

                return httpsUrl;

            } catch (MalformedURLException e) {
                System.out.println("Failure creating HTTPS URL");
                e.printStackTrace();
                logger.log(Level.SEVERE, "Failure creating HTTPS URL", e);
            }

        } else {
            if (javaEEServer == null) {
                System.out.println("javaEEServer not specified");
            } else {
                System.out.println(javaEEServer + " not supported");
            }
        }

        return null;
    }

    private static String getPayaraDomainFromServer() {
    	System.out.println("Getting Payara domain from server");

    	List<String> output = new ArrayList<>();
        List<String> cmd = new ArrayList<>();

        cmd.add("list-domains");

        CliCommands.payaraGlassFish(cmd, output);

        String domain = null;
        for (String line : output) {
            if (line.contains(" not running")) {
                continue;
            }

            if (line.contains(" running")) {
                domain = line.substring(0, line.lastIndexOf(" running"));
                break;
            }
        }

        if (domain == null) {
            throw new IllegalStateException("Running domain could not be obtained for target Payara. Please specify explicitly using -Dpayara_domain");
        }

        return domain;
    }

    public static void addContainerSystemProperty(String key, String value) {
        String javaEEServer = System.getProperty("javaEEServer");

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            System.out.println("Adding system property");

            List<String> cmd = new ArrayList<>();

            cmd.add("create-jvm-options");
            cmd.add("-D" + key + "=\"" + value + "\"");

            CliCommands.payaraGlassFish(cmd);

        } else {
            if (javaEEServer == null) {
                System.out.println("javaEEServer not specified");
            } else {
                System.out.println(javaEEServer + " not supported");
            }
        }
    }

    public static void restartContainer() {
        restartContainer(null);
    }

    public static void restartContainer(String domain) {
        // Arquillian connectors can stop/start already, but not on demand by code

        String javaEEServer = System.getProperty("javaEEServer");

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            System.out.println("Restarting domain");

            List<String> cmd = new ArrayList<>();

            cmd.add("restart-domain");

            String restartDomain = domain;
            if (restartDomain == null) {
                restartDomain = System.getProperty("payara_domain");
            }

            if (restartDomain == null) {
                restartDomain = getPayaraDomainFromServer();
            }

            cmd.add(restartDomain);

            CliCommands.payaraGlassFish(cmd);

            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

        } else {
            if (javaEEServer == null) {
                System.out.println("javaEEServer not specified");
            } else {
                System.out.println(javaEEServer + " not supported");
            }
        }
    }

    public static void restartContainerDebug() {
        // Arquillian connectors can stop/start already, but not on demand by code

        String javaEEServer = System.getProperty("javaEEServer");

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            System.out.println("Stopping domain");

            List<String> cmd = new ArrayList<>();

            cmd.add("stop-domain");

            CliCommands.payaraGlassFish(cmd);

            try {
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            System.out.println("Starting domain");

            cmd = new ArrayList<>();

            cmd.add("start-domain");

            CliCommands.payaraGlassFish(cmd);

            System.out.println("Command returned");

            try {
                Thread.sleep(10000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }

            System.out.println("After sleep");
        }
    }

    public static void setupContainerJDBCIDigestIdentityStore() {

        String javaEEServer = System.getProperty("javaEEServer");

        if ("glassfish-remote".equals(javaEEServer) || "payara-remote".equals(javaEEServer)) {

            System.out.println("Setting up container JDBC identity store for " + javaEEServer);

            if ("payara-remote".equals(javaEEServer) && !isAdminPortListening()) {
                // E.g. a managed server that Arquillian starts after this has run. asadmin can't create the realm
                // without a running server, so add it to domain.xml, which the server reads at startup
                addJDBCDigestRealmToPayaraDomainXml();
                return;
            }

            List<String> cmd = new ArrayList<>();

            cmd.add("create-auth-realm");
            cmd.add("--classname");
            cmd.add("com.sun.enterprise.security.auth.realm.jdbc.JDBCRealm");
            cmd.add("--property");
            cmd.add(
                "jaas-context=jdbcDigestRealm:" +
                "encoding=HASHED:" +
                "password-column=password:" +
                "datasource-jndi=java\\:comp/DefaultDataSource:" +
                "group-table=grouptable:"+
                "charset=UTF-8:" +
                "user-table=usertable:" +
                "group-name-column=groupname:" +
                "digest-algorithm=None:" +
                "user-name-column=username");

            cmd.add("eesamplesdigestrealm");

            CliCommands.payaraGlassFish(cmd);
        } else {
            if (javaEEServer == null) {
                System.out.println("javaEEServer not specified");
            } else {
                System.out.println(javaEEServer + " not supported");
            }
        }

        // TODO: support other servers than Payara and GlassFish

        // WildFly ./bin/add-user.sh -a -u u1 -p p1 -g g1
    }

    /**
     * Adds the JDBC realm used by the digest authentication sample to the domain.xml of a Payara server that
     * isn't running yet. Equivalent to the asadmin create-auth-realm command used for a running server.
     */
    private static void addJDBCDigestRealmToPayaraDomainXml() {
        String gfHome = System.getProperty("payara.home");
        if (gfHome == null) {
            logger.info("payara.home not specified, can't add realm to domain.xml");
            return;
        }

        String domain = System.getProperty("payara_domain", "domain1");
        Path domainXml = Paths.get(gfHome, "glassfish", "domains", domain, "config", "domain.xml");
        if (!domainXml.toFile().exists()) {
            logger.severe("The domain.xml at " + domainXml.toAbsolutePath() + " does not exist. Is the domain \"" + domain + "\" correct?");
            return;
        }

        try {
            String xml = new String(Files.readAllBytes(domainXml), StandardCharsets.UTF_8);
            if (xml.contains("name=\"eesamplesdigestrealm\"")) {
                return;
            }

            int config = xml.indexOf("<config name=\"server-config\">");
            int securityService = config < 0 ? -1 : xml.indexOf("<security-service>", config);
            if (securityService < 0) {
                logger.severe("Could not find the security-service of server-config in " + domainXml.toAbsolutePath());
                return;
            }

            int insertAt = securityService + "<security-service>".length();
            String realm =
                System.lineSeparator() +
                "        <auth-realm classname=\"com.sun.enterprise.security.auth.realm.jdbc.JDBCRealm\" name=\"eesamplesdigestrealm\">" + System.lineSeparator() +
                "          <property name=\"jaas-context\" value=\"jdbcDigestRealm\"></property>" + System.lineSeparator() +
                "          <property name=\"encoding\" value=\"HASHED\"></property>" + System.lineSeparator() +
                "          <property name=\"password-column\" value=\"password\"></property>" + System.lineSeparator() +
                "          <property name=\"datasource-jndi\" value=\"java:comp/DefaultDataSource\"></property>" + System.lineSeparator() +
                "          <property name=\"group-table\" value=\"grouptable\"></property>" + System.lineSeparator() +
                "          <property name=\"charset\" value=\"UTF-8\"></property>" + System.lineSeparator() +
                "          <property name=\"user-table\" value=\"usertable\"></property>" + System.lineSeparator() +
                "          <property name=\"group-name-column\" value=\"groupname\"></property>" + System.lineSeparator() +
                "          <property name=\"digest-algorithm\" value=\"None\"></property>" + System.lineSeparator() +
                "          <property name=\"user-name-column\" value=\"username\"></property>" + System.lineSeparator() +
                "        </auth-realm>";

            Files.write(domainXml, (xml.substring(0, insertAt) + realm + xml.substring(insertAt)).getBytes(StandardCharsets.UTF_8));
            logger.info("Added realm eesamplesdigestrealm to " + domainXml.toAbsolutePath());
        } catch (IOException e) {
            throw new IllegalStateException("Could not add realm to " + domainXml, e);
        }
    }
}
