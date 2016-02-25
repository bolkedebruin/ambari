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
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;
import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.kerberos.KeyTab;
import java.io.*;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * IPAKerberosOperationHandler is an implementation of a KerberosOperationHandler providing
 * functionality specifically for IPA managed KDC. See http://www.freeipa.org
 * <p/>
 * It is assumed that the IPA client is installed and that the ipa shell command is
 * available
 */
public class IPAKerberosOperationHandler extends KerberosOperationHandler {
    private static final Object WindowsProcessLaunchLock = new Object();
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
     * Prepares and creates resources to be used by this KerberosOperationHandler
     * <p/>
     * It is expected that this KerberosOperationHandler will not be used before this call.
     * <p/>
     * The kerberosConfiguration Map is not being used.
     *
     * @param administratorCredentials a KerberosCredential containing the administrative credentials
     *                                 for the relevant KDC
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
        } else {
            setKeyEncryptionTypes(null);
            setAdminServerHost(null);
            setExecutableSearchPaths((String) null);
            setUserPrincipalGroup(null);
        }

        // Pre-determine the paths to relevant Kerberos executables
        executableIpa = getExecutable("ipa");
        executableKvno = getExecutable("kvno");
        executableKinit = getExecutable("kinit");
        executableIpaGetKeytab = getExecutable("ipa-getkeytab");

        setOpen(true);
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
     * Test to see if the specified principal exists in a previously configured MIT KDC
     * <p/>
     * This implementation creates a query to send to the kadmin shell command and then interrogates
     * the result from STDOUT to determine if the presence of the specified principal.
     *
     * @param principal a String containing the principal to test
     * @return true if the principal exists; false otherwise
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
     * @throws KerberosOperationException           if an unexpected error occurred
     */
    @Override
    public boolean principalExists(String principal)
            throws KerberosOperationException {

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

                // Create the ipa query to execute:
                ShellCommandUtil.Result result = invokeIpa(String.format("user-show %s", deconstructedPrincipal.getPrimary()));
                if (result.isSuccessful()) {
                    return true;
                }
            } catch (KerberosOperationException e) {
                return false;
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
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
     * @throws KerberosOperationException           if an unexpected error occurred
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
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
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

            LOG.info("Setting password for {} does not make sense in IPA context as it " +
                    "triggers a password expiry. Continuing anyway.", principal);

            // Create the ipa query:  user-mod <user> --setattr userPassword=<password>
            invokeIpa(String.format("user-mod %s --setattr userPassword=%s", deconstructedPrincipal.getPrimary(), password));

            List<String> command = new ArrayList<>();
            command.add(executableIpa);
            command.add("user-mod");
            command.add(deconstructedPrincipal.getPrimary());
            command.add("--setattr");
            command.add(String.format("krbPasswordExpiration=%s",PASSWORD_EXPIRY_DATE));
            ShellCommandUtil.Result result = executeCommand(command.toArray(new String[command.size()]));
            if (!result.isSuccessful()) {
                throw new KerberosOperationException("Failed to set password expiry");
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

    private void dokInit(PrincipalKeyCredential credentials) throws KerberosOperationException {
        Process process;
        BufferedReader bfr = null;
        OutputStreamWriter osw = null;

        try {
            List<String> kinit = new ArrayList<>();

            kinit.add(executableKinit);
            kinit.add(credentials.getPrincipal());

            ProcessBuilder builder = new ProcessBuilder(kinit.toArray(new String[kinit.size()]));

            if (ShellCommandUtil.WINDOWS) {
                synchronized (WindowsProcessLaunchLock) {
                    process = builder.start();
                }
            } else {
                process = builder.start();
            }

            InputStreamReader isr = new InputStreamReader(process.getInputStream());
            bfr = new BufferedReader(isr);
            osw = new OutputStreamWriter(process.getOutputStream());

            String line = bfr.readLine();
            if (line == null) {
                throw new KerberosOperationException("No response from kinit while trying to get ticket for "
                        + credentials.getPrincipal());
            }

            if (!line.matches("/Password/")) {
                throw new KerberosOperationException("Unexpected response from kinit while trying to get ticket for "
                        + credentials.getPrincipal() + " got: " + line);
            }

            osw.write(credentials.getKey());
            osw.write('\n');

            process.waitFor();
        } catch (IOException e) {
            String message = String.format("Failed to execute the command: %s", e.getLocalizedMessage());
            LOG.error(message, e);
            throw new KerberosOperationException(message, e);
        } catch (InterruptedException e) {
            String message = String.format("Failed to wait for the command to complete: %s", e.getLocalizedMessage());
            LOG.error(message, e);
            throw new KerberosOperationException(message, e);
        } finally {
            if (osw != null) {
                try {
                    osw.close();
                } catch (IOException e) {
                }
            }

            if (bfr != null) {
                try {
                    bfr.close();
                } catch (IOException e) {
                }
            }
        }

        if (process.exitValue() != 0) {
            throw new KerberosOperationException("kinit failed for " + credentials.getPrincipal() + ". Wrong password?");
        }

    }

    /**
     * Invokes the ipa shell command to issue queries
     *
     * @param query a String containing the query to send to the kdamin command
     * @return a ShellCommandUtil.Result containing the result of the operation
     * @throws KerberosKDCConnectionException       if a connection to the KDC cannot be made
     * @throws KerberosAdminAuthenticationException if the administrator credentials fail to authenticate
     * @throws KerberosRealmException               if the realm does not map to a KDC
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

            // Set the ipa interface to be ipa
            command.add(executableIpa);
            command.add(query);

            if(LOG.isDebugEnabled()) {
                LOG.debug(String.format("Executing: %s", createCleanCommand(command)));
            }

            List<String> fixedCommand = fixCommandList(command);
            result = executeCommand(fixedCommand.toArray(new String[fixedCommand.size()]));

            if (!result.isSuccessful()) {
                String message = String.format("Failed to execute ipa:\n\tCommand: %s\n\tExitCode: %s\n\tSTDOUT: %s\n\tSTDERR: %s",
                        createCleanCommand(command), result.getExitCode(), result.getStdout(), result.getStderr());
                LOG.warn(message);

                // Test STDERR to see of any "expected" error conditions were encountered...
                String stdErr = result.getStderr();
                // Did admin credentials fail?
                if (stdErr.contains("Client not found in Kerberos database")) {
                    throw new KerberosAdminAuthenticationException(stdErr);
                } else if (stdErr.contains("Incorrect password while initializing")) {
                    throw new KerberosAdminAuthenticationException(stdErr);
                }
                // Did we fail to connect to the KDC?
                else if (stdErr.contains("Cannot contact any KDC")) {
                    throw new KerberosKDCConnectionException(stdErr);
                } else if (stdErr.contains("Cannot resolve network address for admin server in requested realm while initializing kadmin interface")) {
                    throw new KerberosKDCConnectionException(stdErr);
                }
                // Was the realm invalid?
                else if (stdErr.contains("Missing parameters in krb5.conf required for kadmin client")) {
                    throw new KerberosRealmException(stdErr);
                } else if (stdErr.contains("Cannot find KDC for requested realm while initializing kadmin interface")) {
                    throw new KerberosRealmException(stdErr);
                } else {
                    throw new KerberosOperationException("Unexpected error condition executing the ipa command");
                }
            }
        } finally {
            // If a temporary keytab file was created, clean it up.
            if (tempKeytabFile != null) {
                if (!tempKeytabFile.delete()) {
                    tempKeytabFile.deleteOnExit();
                }
            }
        }

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
