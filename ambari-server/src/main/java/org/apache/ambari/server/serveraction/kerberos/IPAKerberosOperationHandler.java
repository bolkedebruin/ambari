/*
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

package org.apache.ambari.server.serveraction.kerberos;

import org.apache.ambari.server.security.credential.PrincipalKeyCredential;
import org.apache.ambari.server.utils.ShellCommandUtil;
import org.apache.directory.server.kerberos.shared.keytab.Keytab;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IPAKerberosOperationHandler is an implementation of a KerberosOperationHandler providing
 * functionality specifically for IPA managed KDC. See http://www.freeipa.org
 * <p/>
 * It is assumed that the IPA admin tools are installed and that the ipa shell command is
 * available
 */
public class IPAKerberosOperationHandler extends KerberosOperationHandler {
    private final static Logger LOG = LoggerFactory.getLogger(IPAKerberosOperationHandler.class);

    private String adminServerHost = null;

    /**
     * This is where user principals are members of. Important as the password should not expire
     * and thus a separate password policy should apply to this group
     */
    private String userPrincipalGroup = null;

    /**
     * The password expiry date for user principal accounts
     */
    private String PASSWORD_EXPIRY_DATE = "20370826073247Z";

    /**
     * A regular expression pattern to use to parse the key number from the text captured from the
     * kvno command
     */
    private final static Pattern PATTERN_GET_KEY_NUMBER = Pattern.compile("^.*?: kvno = (\\d+).*$", Pattern.DOTALL);

    /**
     * A String containing the resolved path to the ipa executable
     */
    private String executableIpaGetKeytab = null;

    /**
     * A String containing the resolved path to the ipa executable
     */
    private String executableIpa = null;

    /**
     * A String containing the resolved path to the kinit executable
     */
    private String executableKinit = null;

    /**
     * A String containing the resolved path to the ipa-getkeytab executable
     */
    private String executableKvno = null;

    /**
     * A boolean indicating if password expiry should be set
     */
    private boolean usePasswordExpiry = false;

    /**
     * Prepares and creates resources to be used by this KerberosOperationHandler
     * <p/>
     * It is expected that this KerberosOperationHandler will not be used before this call.
     * <p/>
     * The kerberosConfiguration Map is not being used.
     *
     * @param administratorCredentials a KerberosCredential containing the administrative credentials
     *                                 for the relevant IPA KDC
     * @param realm                    a String declaring the default Kerberos realm (or domain)
     * @param kerberosConfiguration    a Map of key/value pairs containing data from the kerberos-env configuration set
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    @Override
    public void open(PrincipalKeyCredential administratorCredentials, String realm,
                     Map<String, String> kerberosConfiguration)
            throws KerberosOperationException {

        setAdministratorCredential(administratorCredentials);
        setDefaultRealm(realm);

        if (kerberosConfiguration != null) {
            // todo: ignore if ipa managed krb5.conf?
            setKeyEncryptionTypes(translateEncryptionTypes(kerberosConfiguration.get(KERBEROS_ENV_ENCRYPTION_TYPES), "\\s+"));
            setExecutableSearchPaths(kerberosConfiguration.get(KERBEROS_ENV_EXECUTABLE_SEARCH_PATHS));
            setUserPrincipalGroup(kerberosConfiguration.get(KERBEROS_ENV_USER_PRINCIPAL_GROUP));
            setAdminServerHost(kerberosConfiguration.get(KERBEROS_ENV_ADMIN_SERVER_HOST));
            setUsePasswordExpiry(kerberosConfiguration.get(KERBEROS_ENV_SET_PASSWORD_EXPIRY));
        } else {
            setKeyEncryptionTypes(null);
            setAdminServerHost(null);
            setExecutableSearchPaths((String) null);
            setUserPrincipalGroup(null);
            setUsePasswordExpiry(null);
        }

        // Pre-determine the paths to relevant Kerberos executables
        executableIpa = getExecutable("ipa");
        executableKvno = getExecutable("kvno");
        executableKinit = getExecutable("kinit");
        executableIpaGetKeytab = getExecutable("ipa-getkeytab");

        setOpen(true);
    }

    private void setUsePasswordExpiry(String usePasswordExpiry) {
        if (usePasswordExpiry == null) {
            this.usePasswordExpiry = false;
            return;
        }

        if (usePasswordExpiry.equalsIgnoreCase("true")) {
            this.usePasswordExpiry = true;
        } else {
            this.usePasswordExpiry = false;
        }
    }

    @Override
    public void close() throws KerberosOperationException {
        // There is nothing to do here.
        setOpen(false);

        executableIpa = null;
        executableKvno = null;
        executableIpaGetKeytab = null;
        executableKinit = null;
    }

    /**
     * Test to see if the specified principal exists in a previously configured IPA KDC
     * <p/>
     * This implementation creates a query to send to the ipa shell command and then interrogates
     * the result from STDOUT to determine if the presence of the specified principal.
     *
     * @param principal a String containing the principal to test
     * @return true if the principal exists; false otherwise
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    @Override
    public boolean principalExists(String principal)
            throws KerberosOperationException {

        LOG.debug("Entering principal exists");

        if (!isOpen()) {
            throw new KerberosOperationException("This operation handler has not been opened");
        }

        if (principal == null) {
            return false;
        } else if (isServicePrincipal(principal)) {
            return true;
        } else {
            // TODO: fix exception check to only check for relevant exceptions
            try {
                DeconstructedPrincipal deconstructedPrincipal = createDeconstructPrincipal(principal);
                LOG.info("Running script");

                // Create the ipa query to execute:
                ShellCommandUtil.Result result = invokeIpa(String.format("user-show %s", deconstructedPrincipal.getPrimary()));
                if (result.isSuccessful()) {
                    return true;
                }
            } catch (KerberosOperationException e) {
                LOG.error("Cannot invoke IPA: " + e);
                throw e;
            }
        }

        return false;
    }


    /**
     * Creates a new principal in a previously configured MIT KDC
     * <p/>
     * This implementation creates a query to send to the kadmin shell command and then interrogates
     * the result from STDOUT to determine if the operation executed successfully.
     *
     * @param principal a String containing the principal add
     * @param password  a String containing the password to use when creating the principal
     * @param service   a boolean value indicating whether the principal is to be created as a service principal or not
     * @return an Integer declaring the generated key number
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     */
    @Override
    public Integer createPrincipal(String principal, String password, boolean service)
            throws KerberosOperationException {

        if (!isOpen()) {
            throw new KerberosOperationException("This operation handler has not been opened");
        }

        if ((principal == null) || principal.isEmpty()) {
            throw new KerberosOperationException("Failed to create new principal - no principal specified");
        } else if (((password == null) || password.isEmpty()) && service) {
            throw new KerberosOperationException("Failed to create new user principal - no password specified");
        } else {
            DeconstructedPrincipal deconstructedPrincipal = createDeconstructPrincipal(principal);

            if (service) {
                // Create the ipa query:  service-add --ok-as-delegate <principal>
                ShellCommandUtil.Result result = invokeIpa(String.format("service-add --ok-as-delegate=TRUE %s", principal));
                String stdOut = result.getStdout();
                if ((stdOut != null) && stdOut.contains(String.format("Added service \"%s\"", principal))) {
                    // IPA does not generate encryption types when no keytab has been generated
                    // So getKeyNumber(principal) cannot be used. This is ok as the createKeytab
                    // procedure ignores the key number anyway for IPA.
                    return 0;
                } else {
                    LOG.error("Failed to execute ipa query: service-add --ok-as-delegate=TRUE {}\nSTDOUT: {}\nSTDERR: {}",
                            principal, stdOut, result.getStderr());
                    throw new KerberosOperationException(String.format("Failed to create service principal for %s\nSTDOUT: %s\nSTDERR: %s",
                            principal, stdOut, result.getStderr()));
                }
            } else {
                // Create the ipa query: user-add <username> --principal=<principal_name> --first <primary> --last <primary>
                // set-attr userPassword="<password>"
                // first and last are required for IPA so we make it equal to the primary
                // the --principal arguments makes sure that Kerberos keys are available for use in getKeyNumber
                ShellCommandUtil.Result result = invokeIpa(String.format("user-add %s --principal=%s --first %s --last %s --setattr userPassword=%s",
                        deconstructedPrincipal.getPrimary(), deconstructedPrincipal.getPrincipalName(),
                        deconstructedPrincipal.getPrimary(), deconstructedPrincipal.getPrimary(), password));

                String stdOut = result.getStdout();
                if (!((stdOut != null) && stdOut.contains(String.format("Added user \"%s\"", deconstructedPrincipal.getPrincipalName())))) {
                    LOG.error("Failed to execute ipa query: user-add {}\nSTDOUT: {}\nSTDERR: {}",
                            principal, stdOut, result.getStderr());
                    throw new KerberosOperationException(String.format("Failed to create user principal for %s\nSTDOUT: %s\nSTDERR: %s",
                            principal, stdOut, result.getStderr()));
                }

                if (getUserPrincipalGroup() != null && !getUserPrincipalGroup().equals("")) {
                    result = invokeIpa(String.format("group-add-member %s --users=%s",
                            getUserPrincipalGroup(), deconstructedPrincipal.getPrimary()));
                    stdOut = result.getStdout();
                    if (!((stdOut != null) && stdOut.contains("added"))) {
                        throw new KerberosOperationException(String.format("Failed to create user principal for %s\nSTDOUT: %s\nSTDERR: %s",
                                principal, stdOut, result.getStderr()));
                    }
                }

                if (!usePasswordExpiry) {
                    updatePassword(deconstructedPrincipal.getPrimary(), password);
                    return getKeyNumber(principal);
                }

                result = invokeIpa(String.format("user-mod %s --setattr krbPasswordExpiration=%s",
                        deconstructedPrincipal.getPrimary(), PASSWORD_EXPIRY_DATE));
                stdOut = result.getStdout();
                if ((stdOut != null) && stdOut.contains("Modified")) {
                    return getKeyNumber(principal);
                }

                throw new KerberosOperationException(String.format("Unknown error while creating principal for %s\n" +
                                "STDOUT: %s\n" +
                                "STDERR: %s\n",
                        principal, stdOut, result.getStderr()));
            }
        }
    }

    /**
     * Updates the password for an existing user principal in a previously configured IPA KDC
     * <p/>
     * This implementation creates a query to send to the ipa shell command and then interrogates
     * the exit code to determine if the operation executed successfully.
     *
     * @param principal a String containing the principal to update
     * @param password  a String containing the password to set
     * @return an Integer declaring the new key number
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    @Override
    public Integer setPrincipalPassword(String principal, String password) throws KerberosOperationException {
        if (!isOpen()) {
            throw new KerberosOperationException("This operation handler has not been opened");
        }

        if ((principal == null) || principal.isEmpty()) {
            throw new KerberosOperationException("Failed to set password - no principal specified");
        } else if ((password == null) || password.isEmpty()) {
            throw new KerberosOperationException("Failed to set password - no password specified");
        } else if (!isServicePrincipal(principal)) {
            DeconstructedPrincipal deconstructedPrincipal = createDeconstructPrincipal(principal);

            if (usePasswordExpiry) {
                // Create the ipa query:  user-mod <user> --setattr userPassword=<password>
                invokeIpa(String.format("user-mod %s --setattr userPassword=%s", deconstructedPrincipal.getPrimary(), password));

                List<String> command = new ArrayList<>();
                command.add(executableIpa);
                command.add("user-mod");
                command.add(deconstructedPrincipal.getPrimary());
                command.add("--setattr");
                command.add(String.format("krbPasswordExpiration=%s", PASSWORD_EXPIRY_DATE));
                ShellCommandUtil.Result result = executeCommand(command.toArray(new String[command.size()]));
                if (!result.isSuccessful()) {
                    throw new KerberosOperationException("Failed to set password expiry");
                }
            } else {
                updatePassword(deconstructedPrincipal.getPrimary(), password);
            }
        }
        return getKeyNumber(principal);
    }

    /**
     * Removes an existing principal in a previously configured KDC
     * <p/>
     * The implementation is specific to a particular type of KDC.
     *
     * @param principal a String containing the principal to remove
     * @return true if the principal was successfully removed; otherwise false
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    @Override
    public boolean removePrincipal(String principal) throws KerberosOperationException {
        if (!isOpen()) {
            throw new KerberosOperationException("This operation handler has not been opened");
        }

        if ((principal == null) || principal.isEmpty()) {
            throw new KerberosOperationException("Failed to remove new principal - no principal specified");
        } else {
            ShellCommandUtil.Result result = null;
            if (isServicePrincipal(principal)) {
                result = invokeIpa(String.format("service-del %s", principal));
            } else {
                DeconstructedPrincipal deconstructedPrincipal = createDeconstructPrincipal(principal);
                result = invokeIpa(String.format("user-del %s", deconstructedPrincipal.getPrimary()));
            }
            // If there is data from STDOUT, see if the following string exists:
            //    Principal "<principal>" created
            // TODO: check ipa output
            String stdOut = result.getStdout();
            return (stdOut != null) && !stdOut.contains("Principal does not exist");
        }
    }

    /**
     * Sets the name of the group where user principals should be members of
     *
     * @param userPrincipalGroup the name of the group
     */
    public void setUserPrincipalGroup(String userPrincipalGroup) {
        this.userPrincipalGroup = userPrincipalGroup;
    }

    /**
     * Gets the name of the group where user principals should be members of
     *
     * @return name of the group where user principals should be members of
     */
    public String getUserPrincipalGroup() {
        return this.userPrincipalGroup;
    }

    /**
     * Sets the KDC administrator server host address
     *
     * @param adminServerHost the ip address or FQDN of the IPA administrator server
     */
    public void setAdminServerHost(String adminServerHost) {
        this.adminServerHost = adminServerHost;
    }

    /**
     * Gets the IP address or FQDN of the IPA administrator server
     *
     * @return the IP address or FQDN of the IPA administrator server
     */
    public String getAdminServerHost() {
        return this.adminServerHost;
    }

    /**
     * Reads data from a stream without blocking and when available. Allows some time for the
     * stream to become ready.
     *
     * @param in the BufferedReader to read from
     * @return a String with available data
     * @throws KerberosOperationException if a timeout happens
     * @throws IOException when somethings goes wrong with the underlying stream
     * @throws InterruptedException if the thread is interrupted
     */
    private String readData(BufferedReader in) throws KerberosOperationException, IOException, InterruptedException {
        char[] data = new char[1024];
        StringBuilder sb = new StringBuilder();

        int count = 0;
        while (!in.ready()) {
            Thread.sleep(1000L);
            if (count >= 5) {
                throw new KerberosOperationException("No answer data available from stream");
            }
            count++;
        }

        while (in.ready()) {
            in.read(data);
            sb.append(data);
        }

        return sb.toString();
    }

    /**
     * Updates a  password for a (user) principal. This is done by first setting a random password and
     * then invoking kInit to directly set the password. This is done to circumvent issues with expired
     * password in IPA, as IPA needs passwords set by the admin to be set again by the user. Note that
     * this resets the current principal to the principal specified here. To invoke further administrative
     * commands a new kInit to admin is required.
     *
     * @param principal The principal user name that needs to be updated
     * @param password The new password
     * @throws KerberosOperationException if something is not as expected
     */
    private void updatePassword(String principal, String password) throws KerberosOperationException {
        BufferedReader reader = null;
        OutputStreamWriter out = null;

        LOG.info("Updating password for: " + principal);
        try {
            ShellCommandUtil.Result result = invokeIpa(String.format("user-mod %s --random", principal));
            if (!result.isSuccessful()) {
                throw new KerberosOperationException(result.getStderr());
            }
            Pattern pattern = Pattern.compile("password: (.*)");
            Matcher matcher = pattern.matcher(result.getStdout());
            LOG.info("Command returned: " + result.getStdout());
            String old_password = matcher.group(1);

            Process process = Runtime.getRuntime().exec(new String[]{executableKinit, principal});
            reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            out = new OutputStreamWriter(process.getOutputStream());

            String data = readData(reader);
            if (!data.startsWith("Password")) {
                process.destroy();
                throw new KerberosOperationException("Unexpected response from kinit while trying to password for "
                + principal + " got: " + data);
            }
            LOG.debug("Sending old password");
            out.write(old_password);
            out.write('\n');

            data = readData(reader);
            if (!data.contains("Enter")) {
                process.destroy();
                throw new KerberosOperationException("Unexpected response from kinit while trying to password for "
                        + principal + " got: " + data);
            }
            LOG.debug("Sending new password");
            out.write(password);
            out.write('\n');

            data = readData(reader);
            if (!data.contains("again")) {
                process.destroy();
                throw new KerberosOperationException("Unexpected response from kinit while trying to password for "
                        + principal + " got: " + data);
            }
            LOG.debug("Sending new password again");
            out.write(password);
            out.write('\n');

            process.waitFor();
        } catch (IOException e) {
            LOG.error("Cannot read stream: " + e);
            throw new KerberosOperationException(e.getMessage());
        } catch (InterruptedException e) {
            LOG.error("Process interrupted: " + e);
            throw new KerberosOperationException(e.getMessage());
        } finally {
            try {
                if (out != null)
                    out.close();
                if (reader != null)
                    reader.close();
            } catch (IOException e) {
                LOG.warn("Cannot close streams: " + e);
            }
        }

    }

    /**
     * Does a kinit to obtain a ticket for the specified principal
     *
     * @param credentials Credentials to be used to obtain the ticket
     * @throws KerberosOperationException In case the ticket cannot be obtained
     */
    private void dokInit(PrincipalKeyCredential credentials) throws KerberosOperationException {
        Process process;
        BufferedReader reader = null;
        OutputStreamWriter osw = null;

        LOG.info("Entering doKinit");
        try {
            LOG.info("start subprocess " + executableKinit + " " + credentials.getPrincipal());
            process = Runtime.getRuntime().exec(new String[]{executableKinit, credentials.getPrincipal()});
            reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
            osw = new OutputStreamWriter(process.getOutputStream());

            char[] data = new char[1024];
            StringBuilder sb = new StringBuilder();

            int count = 0;
            while (!reader.ready()) {
                Thread.sleep(1000L);
                if (count >= 5) {
                    process.destroy();
                    throw new KerberosOperationException("No answer from kinit");
                }
                count++;
            }

            while (reader.ready()) {
                reader.read(data);
                sb.append(data);
            }

            String line = sb.toString();
            LOG.info("Reading a line: " + line);
            if (!line.startsWith("Password")) {
                throw new KerberosOperationException("Unexpected response from kinit while trying to get ticket for "
                        + credentials.getPrincipal() + " got: " + line);
            }
            osw.write(credentials.getKey());
            osw.write('\n');
            osw.close();

            process.waitFor();

            LOG.info("done subprocess");
        } catch (IOException e) {
            String message = String.format("Failed to execute the command: %s", e.getLocalizedMessage());
            LOG.error(message, e);
            throw new KerberosOperationException(message, e);
        } catch (InterruptedException e) {
            String message = String.format("Failed to execute the command: %s", e.getLocalizedMessage());
            LOG.error(message, e);
            throw new KerberosOperationException(message, e);
        } finally {
            if (osw != null) {
                try {
                    osw.close();
                } catch (IOException e) {
                }
            }

            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                }
            }
        }

        if (process.exitValue() != 0) {
            throw new KerberosOperationException("kinit failed for " + credentials.getPrincipal() + ". Wrong password?");
        }

    }

    /**
     * Invokes the ipa shell command with administrative credentials to issue queries
     *
     * @param query a String containing the query to send to the kdamin command
     * @return a ShellCommandUtil.Result containing the result of the operation
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    protected ShellCommandUtil.Result invokeIpa(String query)
            throws KerberosOperationException {
        ShellCommandUtil.Result result = null;

        if ((query == null) || query.isEmpty()) {
            throw new KerberosOperationException("Missing ipa query");
        }
        PrincipalKeyCredential administratorCredentials = getAdministratorCredential();
        String defaultRealm = getDefaultRealm();

        List<String> command = new ArrayList<String>();
        File tempKeytabFile = null;

        List<String> kinit = new ArrayList<String>();

        try {
            String adminPrincipal = (administratorCredentials == null)
                    ? null
                    : administratorCredentials.getPrincipal();

            if ((adminPrincipal == null) || adminPrincipal.isEmpty()) {
                    throw new KerberosOperationException("No admin principal for ipa available - " +
                            "this KerberosOperationHandler may not have been opened.");
            }

            if((executableIpa == null) || executableIpa.isEmpty()) {
                throw new KerberosOperationException("No path for ipa is available - " +
                        "this KerberosOperationHandler may not have been opened.");
            }

            dokInit(administratorCredentials);

            LOG.info("Passed doKinit");

            // Set the ipa interface to be ipa
            command.add(executableIpa);
            command.add(query);

            LOG.info("Executing %s", command);
            if(LOG.isDebugEnabled()) {
                LOG.debug(String.format("Executing: %s", createCleanCommand(command)));
            }

            List<String> fixedCommand = fixCommandList(command);
            result = executeCommand(fixedCommand.toArray(new String[fixedCommand.size()]));

        } finally {
            // If a temporary keytab file was created, clean it up.
            if (tempKeytabFile != null) {
                if (!tempKeytabFile.delete()) {
                    tempKeytabFile.deleteOnExit();
                }
            }
        }

        LOG.info("Done invokeipa");
        return result;
    }

    /**
     * Rebuilds the command line to make sure space are converted to arguments
     *
     * @param command a List of items making up the command
     * @return the fixed command
     */
    private List<String> fixCommandList(List<String> command) {
        List<String> fixedCommandList = new ArrayList<>();
        Iterator<String> iterator = command.iterator();

        if (iterator.hasNext()) {
            fixedCommandList.add(iterator.next());
        }

        while (iterator.hasNext()) {
            String part = iterator.next();

            // split arguments
            if (part.contains(" ")) {
                StringTokenizer st = new StringTokenizer(part, " ");
                while (st.hasMoreElements()) {
                    fixedCommandList.add(st.nextToken());
                }
            } else {
                fixedCommandList.add(part);
            }
        }

        return fixedCommandList;
    }
    /**
     * Build the ipa command string, replacing administrator password with "********"
     *
     * @param command a List of items making up the command
     * @return the cleaned command string
     */
    private String createCleanCommand(List<String> command) {
        StringBuilder cleanedCommand = new StringBuilder();
        Iterator<String> iterator = command.iterator();

        if (iterator.hasNext()) {
            cleanedCommand.append(iterator.next());
        }

        while (iterator.hasNext()) {
            String part = iterator.next();

            cleanedCommand.append(' ');
            cleanedCommand.append(part);

            if ("-w".equals(part)) {
                // Skip the password and use "********" instead
                if (iterator.hasNext()) {
                    iterator.next();
                }
                cleanedCommand.append(" ********");
            }
        }

        return cleanedCommand.toString();
    }

    /**
     * Determine is a principal is a service principal
     * @param principal
     * @return true if the principal is a (existing) service principal
     * @throws KerberosOperationException
     */
    private boolean isServicePrincipal(String principal)
            throws KerberosOperationException {

        if ((principal == null) || principal.isEmpty()) {
            throw new KerberosOperationException("Failed to determine principal type- no principal specified");
        } else if (!principal.contains("/")) {
            return false;
        }

        try {
            ShellCommandUtil.Result result = invokeIpa(String.format("service-show %s", principal));
            if (result.isSuccessful()) {
                return true;
            }
        } catch (KerberosOperationException e) {
            return false;
        }

        return false;
    }

    /**
     * Retrieves the current key number assigned to the identity identified by the specified principal
     *
     * @param principal a String declaring the principal to look up
     * @return an Integer declaring the current key number
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    private Integer getKeyNumber(String principal) throws KerberosOperationException {
        if (!isOpen()) {
            throw new KerberosOperationException("This operation handler has not been opened");
        }

        if ((principal == null) || principal.isEmpty()) {
            throw new KerberosOperationException("Failed to get key number for principal  - no principal specified");
        } else {
            // Create the kvno query:  <principal>
            List<String> command = new ArrayList<>();
            command.add(executableKvno);
            command.add(principal);

            ShellCommandUtil.Result result = executeCommand(command.toArray(new String[command.size()]));
            String stdOut = result.getStdout();
            if (stdOut == null) {
                String message = String.format("Failed to get key number for %s:\n\tExitCode: %s\n\tSTDOUT: NULL\n\tSTDERR: %s",
                        principal, result.getExitCode(), result.getStderr());
                LOG.warn(message);
                throw new KerberosOperationException(message);
            }

            Matcher matcher = PATTERN_GET_KEY_NUMBER.matcher(stdOut);
            if (matcher.matches()) {
                NumberFormat numberFormat = NumberFormat.getIntegerInstance();
                String keyNumber = matcher.group(1);

                numberFormat.setGroupingUsed(false);
                try {
                    Number number = numberFormat.parse(keyNumber);
                    return (number == null) ? 0 : number.intValue();
                } catch (ParseException e) {
                    String message = String.format("Failed to get key number for %s - invalid key number value (%s):\n\tExitCode: %s\n\tSTDOUT: NULL\n\tSTDERR: %s",
                            principal, keyNumber, result.getExitCode(), result.getStderr());
                    LOG.warn(message);
                    throw new KerberosOperationException(message);
                }
            } else {
                String message = String.format("Failed to get key number for %s - unexpected STDOUT data:\n\tExitCode: %s\n\tSTDOUT: NULL\n\tSTDERR: %s",
                        principal, result.getExitCode(), result.getStderr());
                LOG.warn(message);
                throw new KerberosOperationException(message);
            }

        }
    }

    /**
     * Creates a key tab by using the ipa commandline utilities. It ignores key number and password
     * as this will be handled by IPA
     *
     * @param principal a String containing the principal to test
     * @param password  (IGNORED) a String containing the password to use when creating the principal
     * @param keyNumber (IGNORED) a Integer indicating the key number for the keytab entries
     * @return
     * @throws KerberosOperationException
     */
    @Override
    protected Keytab createKeytab(String principal, String password, Integer keyNumber)
            throws KerberosOperationException {

        if ((principal == null) || principal.isEmpty()) {
            throw new KerberosOperationException("Failed to create keytab file, missing principal");
        }

        UUID uuid = UUID.randomUUID();

        String fileName = System.getProperty("java.io.tmpdir") +
                File.pathSeparator +
                "ambari." + uuid.toString();

        // TODO: add ciphers
        List<String> command = new ArrayList<>();
        command.add(executableIpaGetKeytab);
        command.add("-s");
        command.add(getAdminServerHost());
        command.add("-p");
        command.add(principal);
        command.add("-k");
        command.add(fileName);

        // TODO: is it really required to set the password?
        ShellCommandUtil.Result result = executeCommand(command.toArray(new String[command.size()]));
        if (!result.isSuccessful()) {
            String message = String.format("Failed to get key number for %s:\n\tExitCode: %s\n\tSTDOUT: %s\n\tSTDERR: %s",
                    principal, result.getExitCode(), result.getStdout(), result.getStderr());
            LOG.warn(message);
            throw new KerberosOperationException(message);
        }

        File keytabFile = new File(fileName);
        Keytab keytab = readKeytabFile(keytabFile);

        keytabFile.delete();

        return keytab;
    }
}
