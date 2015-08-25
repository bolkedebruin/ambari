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

import org.apache.ambari.server.utils.ShellCommandUtil;
import org.apache.directory.shared.kerberos.exceptions.KerberosException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.*;

/**
 * IPAKerberosOperationHandler is an implementation of a KerberosOperationHandler providing
 * functionality specifically for IPA managed KDC. See http://www.freeipa.org
 * <p/>
 * It is assumed that the IPA client is installed and that the ipa shell command is
 * available
 */
public class IPAKerberosOperationHandler extends KerberosOperationHandler {

    private final static Logger LOG = LoggerFactory.getLogger(IPAKerberosOperationHandler.class);

    private String adminServerHost = null;

    private String adminKeyTab = null;

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
    private String executableIpaGetKeyTab = null;

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
    public void open(KerberosCredential administratorCredentials, String realm,
                     Map<String, String> kerberosConfiguration)
            throws KerberosOperationException {

        setAdministratorCredentials(administratorCredentials);
        setDefaultRealm(realm);

        if (kerberosConfiguration != null) {
            setKeyEncryptionTypes(translateEncryptionTypes(kerberosConfiguration.get(KERBEROS_ENV_ENCRYPTION_TYPES), "\\s+"));
            setAdminServerHost(kerberosConfiguration.get(KERBEROS_ENV_ADMIN_SERVER_HOST));
            setExecutableSearchPaths(kerberosConfiguration.get(KERBEROS_ENV_EXECUTABLE_SEARCH_PATHS));
            setAdminKeyTab(kerberosConfiguration.get(KERBEROS_ENV_ADMIN_KEYTAB));
        } else {
            setKeyEncryptionTypes(null);
            setAdminServerHost(null);
            setExecutableSearchPaths((String) null);
        }

        // Pre-determine the paths to relevant Kerberos executables
        executableIpa = getExecutable("ipa");
        executableIpaGetKeyTab = getExecutable("ipa-getkeytab");
        executableKinit = getExecutable("kinit");

        setOpen(true);
    }

    @Override
    public void close() throws KerberosOperationException {
        // There is nothing to do here.
        setOpen(false);

        executableIpa = null;
        executableIpaGetKeyTab = null;

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
                // Create the ipa query to execute:
                ShellCommandUtil.Result result = invokeIpa(String.format("user-show %s", principal));
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
                ShellCommandUtil.Result result = invokeIpa(String.format("user-add %s --principal=%s --first %s --last %s --setattr userPassword=\"%s\"",
                        deconstructedPrincipal.getPrimary(), deconstructedPrincipal.getPrincipalName(),
                        deconstructedPrincipal.getPrimary(), deconstructedPrincipal.getPrimary(), password));

                String stdOut = result.getStdout();
                if ((stdOut != null) && stdOut.contains(String.format("Added user \"%s\"", deconstructedPrincipal.getPrincipalName()))) {
                    return 0;
                } else {
                    LOG.error("Failed to execute ipa query: user-add {}\nSTDOUT: {}\nSTDERR: {}",
                            principal, stdOut, result.getStderr());
                    throw new KerberosOperationException(String.format("Failed to create user principal for %s\nSTDOUT: %s\nSTDERR: %s",
                            principal, stdOut, result.getStderr()));
                }
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

            // Create the ipa query:  user-mod <user> --setattr userPassword=<password>
            invokeIpa(String.format("user-mod %s --setattr userPassword=\"%s\"", deconstructedPrincipal.getPrimary(), password));
        }
        return 0;
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
     * Sets the KDC administrator server host address
     *
     * @param adminServerHost the ip address or FQDN of the KDC administrator server
     */
    public void setAdminServerHost(String adminServerHost) {
        this.adminServerHost = adminServerHost;
    }

    /**
     * Gets the IP address or FQDN of the KDC administrator server
     *
     * @return the IP address or FQDN of the KDC administrator server
     */
    public String getAdminServerHost() {
        return this.adminServerHost;
    }

    /**
     * Sets the administrator key tab file location
     *
     * @param adminKeyTab the location of the key tab file
     */
    public void setAdminKeyTab(String adminKeyTab) {
        this.adminKeyTab = adminKeyTab;
    }

    /**
     * Gets the location of the administrator key tab file
     *
     * @return the location of the administrator key tab file
     */
    public String getAdminKeyTab() {
        return this.adminKeyTab;
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
        KerberosCredential administratorCredentials = getAdministratorCredentials();
        String defaultRealm = getDefaultRealm();

        List<String> command = new ArrayList<String>();
        File tempKeytabFile = null;

        List<String> kinit = new ArrayList<String>();

        try {
            String adminPrincipal = (administratorCredentials == null)
                    ? null
                    : administratorCredentials.getPrincipal();

            if ((adminPrincipal == null) || adminPrincipal.isEmpty()) {
                    throw new KerberosOperationException("No admin principal for ipa available - this KerberosOperationHandler may not have been opened.");
            } else {
                if((executableIpa == null) || executableIpa.isEmpty()) {
                    throw new KerberosOperationException("No path for ipa is available - this KerberosOperationHandler may not have been opened.");
                }

                String adminKeyTab = administratorCredentials.getKeytab();

                /*if ((adminKeyTab == null || adminKeyTab.isEmpty())) {
                    throw new KerberosOperationException("No admin keytab for ipa available - this KerberosOperationHandler may not have been opened.");
                }*/

                //TODO: check logic for admin credentials and keytab
                //tempKeytabFile = createKeytabFile(adminKeyTab);
                kinit.add(executableKinit);
                kinit.add("-k");
                kinit.add("-t");
                kinit.add(getAdminKeyTab());
                kinit.add(administratorCredentials.getPrincipal());
                result = executeCommand(kinit.toArray(new String[kinit.size()]));

                if (!result.isSuccessful()) {
                    throw new KerberosOperationException(("Cannot kinit from keytab"));
                }

                // Set the ipa interface to be ipa
                command.add(executableIpa);

            }

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
}
