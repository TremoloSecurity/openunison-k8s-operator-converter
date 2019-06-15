/*
Copyright 2019 Tremolo Security, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package com.tremolosecurity.openunison;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.stream.Collectors;

import javax.crypto.SecretKey;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.script.ScriptContext;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

import com.tremolosecurity.kubernetes.artifacts.util.CertUtils;
import com.tremolosecurity.kubernetes.artifacts.util.K8sUtils;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.yaml.snakeyaml.Yaml;

/**
 * Convert
 */
public class Convert {

    public static String tokenPath;
    public static String rootCaPath;
    public static String configMaps;
    public static String kubernetesURL;

    public static String namespace;

    public static void main(String[] args) throws Exception {

        String instanceName = "orchestra";

        Options options = new Options();
        options.addOption("tokenPath", true, "The path to the token to use when communicating with the API server");
        options.addOption("rootCaPath", true,
                "The path to the certificate athority PEM file for the kubrnetes API server");
        options.addOption("configMaps", true,
                "The full path to a directory containing additional certificates to trust");
        options.addOption("kubernetesURL", true, "The URL for the kubernetes api server");

        options.addOption("namespace", true, "namespace");
        options.addOption("dryrun", true, "should this be a try run");

        options.addOption("help", false, "Prints this message");

        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = parser.parse(options, args, true);

        if (args.length == 0 || cmd.hasOption("help")) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("OpenUnison Convert to Operator Options", options);
        } else {
            boolean isDryRun = System.getenv().get("DRY_RUN").equalsIgnoreCase("true");

            tokenPath = loadOption(cmd, "tokenPath", options);
            rootCaPath = loadOption(cmd, "rootCaPath", options);
            configMaps = loadOption(cmd, "configMaps", options);
            kubernetesURL = loadOption(cmd, "kubernetesURL", options);

            namespace = loadOption(cmd, "namespace", options);

            String fromEnv = System.getenv(namespace);

            if (fromEnv != null) {
                namespace = fromEnv;
            }

            System.out.println("Loading k8s");
            K8sUtils k8s = new K8sUtils(tokenPath, rootCaPath, configMaps, kubernetesURL);

            Security.addProvider(new BouncyCastleProvider());
            // ScriptEngine engine = initializeJS(jsPath, namespace, k8s);

            k8s.setEngine(null);

            // first, pull the secret from the api server

            Map resp = k8s.callWS("/api/v1/namespaces/openunison/secrets/openunison-secrets");
            String fromServer = (String) resp.get("data");

            JSONParser jsonParser = new JSONParser();

            JSONObject secretRoot = (JSONObject) jsonParser.parse(fromServer);

            String keystoreB64 = (String) ((JSONObject) secretRoot.get("data")).get("unisonKeyStore.p12");

            String envDataB64 = (String) ((JSONObject) secretRoot.get("data")).get("ou.env");

            String envData = new String(Base64.getDecoder().decode(envDataB64));

            Properties env = new Properties();
            env.load(new ByteArrayInputStream(envData.getBytes("UTF-8")));

            KeyStore unisonKS = KeyStore.getInstance("PKCS12");
            unisonKS.load(new ByteArrayInputStream(Base64.getDecoder().decode(keystoreB64)),
                    env.getProperty("unisonKeystorePassword").toCharArray());

            Enumeration<String> aliases = unisonKS.aliases();
            Map<String, String> secretKeys = new HashMap<String, String>();
            Map<String, KeyPair> keyPairs = new HashMap<String, KeyPair>();
            Map<String, X509Certificate> certs = new HashMap<String, X509Certificate>();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();

                Key key = unisonKS.getKey(alias, env.getProperty("unisonKeystorePassword").toCharArray());
                System.out.println("alias : " + alias + " / " + key);

                if (key == null) {
                    certs.put(alias, (X509Certificate) unisonKS.getCertificate(alias));
                } else {
                    if (key instanceof SecretKey) {
                        secretKeys.put(alias, Base64.getEncoder().encodeToString(((SecretKey) key).getEncoded()));
                    } else {
                        keyPairs.put(alias, new KeyPair((X509Certificate) unisonKS.getCertificate(alias), key));
                    }
                }
            }

            JSONObject keyStore = new JSONObject();

            JSONArray staticKeys = new JSONArray();
            keyStore.put("static_keys", staticKeys);
            JSONObject secretData = new JSONObject();

            for (String alias : secretKeys.keySet()) {
                // create object for the CR
                JSONObject crObj = new JSONObject();
                crObj.put("name", alias);
                crObj.put("version", 1);
                staticKeys.add(crObj);

                JSONObject secretObj = new JSONObject();
                secretObj.put("name", alias);
                secretObj.put("version", 1);
                secretObj.put("key_data", secretKeys.get(alias));
                secretObj.put("still_used", true);
                secretData.put(alias, Base64.getEncoder().encodeToString(secretObj.toJSONString().getBytes("UTF-8")));

            }

            JSONObject staticSecret = generateSecret(instanceName + "-static-keys", secretData);

            System.out.println("Creating static key secret");
            if (isDryRun) {
                System.out.println("DRY RUN - Create /api/v1/namespaces/openunison/secrets/");
            } else {
                k8s.postWS("/api/v1/namespaces/openunison/secrets", staticSecret.toJSONString());
            }

            System.out.println("Static key secret created");

            JSONArray certsList = new JSONArray();
            for (String alias : certs.keySet()) {
                JSONObject certObj = new JSONObject();
                certObj.put("name", alias);
                certObj.put("pem_data", CertUtils.exportCert(certs.get(alias)));
                certsList.add(certObj);

            }

            JSONArray keyPairObjs = new JSONArray();
            for (String alias : keyPairs.keySet()) {
                addKeypair(isDryRun, k8s, env, unisonKS, keyPairs, keyPairObjs, alias,true,alias);

            }

            // URL scriptURL = new URL(installScriptURL);
            // engine.eval(new BufferedReader(new
            // InputStreamReader(scriptURL.openStream())));

            JSONObject openUnisonCR = new JSONObject();
            openUnisonCR.put("apiVersion", "openunison.tremolo.io/v1");
            openUnisonCR.put("kind", "OpenUnison");
            JSONObject crMetadata = new JSONObject();
            crMetadata.put("name", instanceName);
            openUnisonCR.put("metadata", crMetadata);
            JSONObject spec = new JSONObject();
            openUnisonCR.put("spec", spec);

            String ouyamlb64 = (String) ((JSONObject) secretRoot.get("data")).get("openunison.yaml");
            String ouyaml = new String(Base64.getDecoder().decode(ouyamlb64));

            Yaml yaml = new Yaml();
            Map<String, Object> map = (Map<String, Object>) yaml.load(ouyaml);

            JSONObject ouNetworking = new JSONObject(map);
            spec.put("openunison_network_configuration", ouNetworking);

            JSONObject keystoreJsonObject = new JSONObject();
            spec.put("key_store", keystoreJsonObject);

            keystoreJsonObject.put("static_keys", staticKeys);

            keystoreJsonObject.put("trusted_certificates", certsList);

            JSONObject keyPairsObj = new JSONObject();
            keystoreJsonObject.put("key_pairs", keyPairsObj);
            keyPairsObj.put("keys", keyPairObjs);

            JSONArray kpTemplate = new JSONArray();
            keyPairsObj.put("create_keypair_template", kpTemplate);

            JSONObject o = new JSONObject();
            o.put("name", "ou");
            o.put("value", env.getProperty("OU_CERT_OU"));
            kpTemplate.add(o);

            o = new JSONObject();
            o.put("name", "o");
            o.put("value", env.getProperty("OU_CERT_O"));
            kpTemplate.add(o);

            o = new JSONObject();
            o.put("name", "l");
            o.put("value", env.getProperty("OU_CERT_L"));
            kpTemplate.add(o);

            o = new JSONObject();
            o.put("name", "st");
            o.put("value", env.getProperty("OU_CERT_ST"));
            kpTemplate.add(o);

            o = new JSONObject();
            o.put("name", "c");
            o.put("value", env.getProperty("OU_CERT_C"));
            kpTemplate.add(o);

            // image and replicas

            String json = (String) k8s.callWS("/apis/extensions/v1beta1/namespaces/openunison/deployments/openunison")
                    .get("data");
            JSONObject deployment = (JSONObject) jsonParser.parse(json);

            JSONObject x = (JSONObject) deployment.get("spec");
            x = (JSONObject) x.get("template");
            x = (JSONObject) x.get("spec");
            JSONArray a = (JSONArray) x.get("containers");
            JSONObject container = (JSONObject) a.get(0);

            spec.put("image", container.get("image"));
            spec.put("replicas", ((JSONObject) deployment.get("spec")).get("replicas"));
            spec.put("dest_secret", "orchestra");
            spec.put("source_secret", "orchestra-secret-source");

            JSONArray specSecretData = new JSONArray();
            spec.put("secret_data", specSecretData);

            JSONArray specNonSecretData = new JSONArray();
            spec.put("non_secret_data", specNonSecretData);

            HashSet<String> ignore = new HashSet<String>();
            ignore.add("OU_HOST");
            ignore.add("K8S_DASHBOARD_HOST");
            ignore.add("OU_CERT_O");
            ignore.add("OU_CERT_L");
            ignore.add("OU_CERT_ST");
            ignore.add("OU_CERT_OU");
            ignore.add("OU_CERT_C");

            HashSet<String> keepSecret = new HashSet<String>();
            JSONObject secretProps = new JSONObject();
            StringTokenizer toker = new StringTokenizer(System.getenv("KEEP_SECRET"), ",", false);
            while (toker.hasMoreTokens()) {
                keepSecret.add(toker.nextToken());
            }

            for (Object ox : env.keySet()) {
                String prop = (String) ox;
                if (keepSecret.contains(prop)) {
                    specSecretData.add(prop);
                    secretProps.put(prop, Base64.getEncoder().encodeToString(env.getProperty(prop).getBytes("UTF-8")));
                } else if (!ignore.contains(prop)) {
                    JSONObject obj = new JSONObject();
                    obj.put("name", prop);
                    obj.put("value", env.getProperty(prop));
                    specNonSecretData.add(obj);
                }
            }

            JSONObject sourceSecret = generateSecret("orchestra-secret-source", secretProps);
            if (isDryRun) {
                System.out.println("Dry Run - Creating /api/v1/namespaces/openunison/secrets/orchestra-secret-source");
            } else {
                k8s.postWS("/api/v1/namespaces/openunison/secrets", sourceSecret.toJSONString());
            }

            JSONArray hosts = new JSONArray();
            spec.put("hosts", hosts);
            JSONObject host = new JSONObject();
            hosts.add(host);
            JSONArray names = new JSONArray();
            host.put("names", names);

            JSONObject name = new JSONObject();
            name.put("name", env.getProperty("OU_HOST"));
            name.put("env_var", "OU_HOST");
            names.add(name);

            name = new JSONObject();
            name.put("name", env.getProperty("K8S_DASHBOARD_HOST"));
            name.put("env_var", "K8S_DASHBOARD_HOST");
            names.add(name);

            host.put("ingress_name", "openunison");
            host.put("secret_name", "ou-tls-certificate");

            Map res = k8s.callWS("/apis/extensions/v1beta1/namespaces/openunison/deployments/amq", null, -1);
            boolean useAmq = false;

            String amqServiceBackup = null;

            if (((Integer) res.get("code")) == 404) {
                spec.put("enable_activemq", false);
                useAmq = false;
            } else {
                spec.put("enable_activemq", true);
                String jsonx = (String) res.get("data");
                JSONObject amqObj = (JSONObject) jsonParser.parse(jsonx);
                amqObj = (JSONObject) amqObj.get("spec");
                amqObj = (JSONObject) amqObj.get("template");
                amqObj = (JSONObject) amqObj.get("spec");
                amqObj = (JSONObject) ((JSONArray) amqObj.get("containers")).get(0);
                spec.put("activemq_image", amqObj.get("image"));

                // get the secret
                resp = k8s.callWS("/api/v1/namespaces/openunison/secrets/amq-secrets");
                fromServer = (String) resp.get("data");
                secretRoot = (JSONObject) jsonParser.parse(fromServer);
                keystoreB64 = (String) ((JSONObject) secretRoot.get("data")).get("amq.p12");
                KeyStore amqKS = KeyStore.getInstance("PKCS12");
                amqKS.load(new ByteArrayInputStream(Base64.getDecoder().decode(keystoreB64)),
                        env.getProperty("unisonKeystorePassword").toCharArray());

                keyPairs.put("broker", new KeyPair((X509Certificate) amqKS.getCertificate("broker"), amqKS.getKey("broker", env.getProperty("unisonKeystorePassword").toCharArray())));
                addKeypair(isDryRun, k8s, env, amqKS, keyPairs, keyPairObjs, "broker",false,"orchestra-amq-server");

                useAmq = true;

                res = k8s.callWS("/api/v1/namespaces/openunison/services/amq");
                amqServiceBackup = (String) res.get("data");

                if (isDryRun) {
                    System.out.println("Dry Run - Deleting AMQ service");
                } else {
                    System.out.println("Deleting AMQ service");
                    k8s.deleteWS("/api/v1/namespaces/openunison/services/amq");
                }
            }

            if (isDryRun) {
                System.out.println("Dry Run - CR : ");
                System.out.println(openUnisonCR.toJSONString());
            } else {
                System.out.println("Deploying CR");
                k8s.postWS("/apis/openunison.tremolo.io/v1/namespaces/openunison/openunisons",
                        openUnisonCR.toJSONString());
            }

            if (isDryRun) {
                System.out.println("Dry Run - scale down the openunison deployment to 0");
            } else {
                System.out.println("Scaling down the openunison deployment to 0");
                JSONObject patch = new JSONObject();
                JSONObject pspec = new JSONObject();
                patch.put("spec", pspec);
                pspec.put("replicas", 0);
                k8s.patchWS("/apis/extensions/v1beta1/namespaces/openunison/deployments/openunison",
                        patch.toJSONString());

            }

            if (isDryRun) {
                System.out.println("Dry Run - backing up old ingress object and deleting");
            } else {
                res = k8s.callWS("/apis/extensions/v1beta1/namespaces/openunison/ingresses/openunison-ingress");
                if (((Integer) res.get("code")) == 200) {
                    String jsondata = (String) res.get("data");
                    JSONObject cfgData = new JSONObject();
                    cfgData.put("legacyIngress.json", jsondata);
                    if (amqServiceBackup != null) {
                        cfgData.put("legacyamqservice.json", amqServiceBackup);
                    }
                    System.out.println("Saving legacy ingress to legacy-ingress configmap");
                    k8s.postWS("/api/v1/namespaces/openunison/configmaps",
                            generateConfigMap("lgeacy-ingress", cfgData).toJSONString());

                }
            }

            if (isDryRun) {
                System.out.println(
                        "Dry Run - Deleting /apis/extensions/v1beta1/namespaces/openunison/ingresses/openunison-ingress");
            } else {
                System.out.println(
                        "Deleting /apis/extensions/v1beta1/namespaces/openunison/ingresses/openunison-ingress");
                k8s.deleteWS("/apis/extensions/v1beta1/namespaces/openunison/ingresses/openunison-ingress");

            }

            if (useAmq) {
                if (isDryRun) {
                    System.out.println("Dry Run -- Scaling ActiveMQ to 0");
                } else {
                    System.out.println("Scaling ActiveMQ to 0");
                    JSONObject patch = new JSONObject();
                    JSONObject pspec = new JSONObject();
                    patch.put("spec", pspec);
                    pspec.put("replicas", 0);
                    k8s.patchWS("/apis/extensions/v1beta1/namespaces/openunison/deployments/amq", patch.toJSONString());
                }
            }

            System.out.println("Conversion Complete");

        }
    }

    private static void addKeypair(boolean isDryRun, K8sUtils k8s, Properties env, KeyStore unisonKS,
            Map<String, KeyPair> keyPairs, JSONArray keyPairObjs, String alias,boolean importToKs,String saveInCrName) throws UnsupportedEncodingException,
            Exception, KeyStoreException, InvalidNameException, CertificateParsingException {
        JSONObject secretObj = new JSONObject();
        secretObj.put("apiVersion", "v1");
        secretObj.put("kind", "Secret");
        secretObj.put("type", "kubernetes.io/tls");

        JSONObject dataObj = new JSONObject();
        dataObj.put("tls.key", Base64.getEncoder()
                .encodeToString(CertUtils.exportKey((PrivateKey) keyPairs.get(alias).key).getBytes("UTF-8")));
        dataObj.put("tls.crt",
                Base64.getEncoder().encodeToString(CertUtils.exportCert(keyPairs.get(alias).cert).getBytes("UTF-8")));
        secretObj.put("data", dataObj);

        JSONObject metadataObj = new JSONObject();
        metadataObj.put("name", alias);
        JSONObject labelObj = new JSONObject();
        labelObj.put("tremolo_operator_created", "true");
        labelObj.put("operated-by", "openunison-operator");
        metadataObj.put("labels", labelObj);

        secretObj.put("metadata", metadataObj);

        if (isDryRun) {
            System.out.println("Dry Run - /api/v1/namespaces/openunison/secrets/" + alias);
        } else {
            k8s.postWS("/api/v1/namespaces/openunison/secrets", secretObj.toJSONString());
        }

        JSONObject keypairObj = new JSONObject();
        keyPairObjs.add(keypairObj);
        keypairObj.put("name", saveInCrName);
        if (importToKs) {
            keypairObj.put("import_into_ks", "keypair");
        } else {
            keypairObj.put("import_into_ks", "certificate");
        }
        JSONObject createDataObj = new JSONObject();
        keypairObj.put("create_data", createDataObj);

        createDataObj.put("sign_by_k8s_ca",
                env.getProperty("USE_K8S_CM") != null && env.getProperty("USE_K8S_CM").equalsIgnoreCase("true"));

        X509Certificate cert = (X509Certificate) unisonKS.getCertificate(alias);

        String dn = cert.getSubjectX500Principal().getName();
        String serverName = null;
        LdapName ldapDN = new LdapName(dn);

        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equalsIgnoreCase("cn")) {
                serverName = rdn.getValue().toString();
            }
        }

        createDataObj.put("server_name", serverName);
        JSONArray sans = new JSONArray();
        createDataObj.put("subject_alternative_names", sans);
        if (cert.getSubjectAlternativeNames() != null) {
            java.util.Collection altNames = cert.getSubjectAlternativeNames();
            Iterator iter = altNames.iterator();
            while (iter.hasNext()) {
                java.util.List item = (java.util.List) iter.next();
                Integer type = (Integer) item.get(0);
                String san = item.get(1).toString();
                if (!san.equalsIgnoreCase(serverName)) {
                    sans.add(san);
                }

            }
        }

        createDataObj.put("key_size", ((RSAPublicKey) cert.getPublicKey()).getModulus().bitLength());

        createDataObj.put("ca_cert", cert.getKeyUsage() != null && cert.getKeyUsage()[5]);
    }

    private static JSONObject generateConfigMap(String name,JSONObject cfgData) {
        JSONObject staticSecret = new JSONObject();
        staticSecret.put("apiVersion", "v1");
        staticSecret.put("kind", "ConfigMap");
        staticSecret.put("type", "Opaque");
        staticSecret.put("data", cfgData);
        JSONObject metadata = new JSONObject();
        metadata.put("name", name);
        metadata.put("namespace", "openunison");
        staticSecret.put("metadata", metadata);
        return staticSecret;
    }

    private static JSONObject generateSecret(String name,JSONObject secretData) {
        JSONObject staticSecret = new JSONObject();
        staticSecret.put("apiVersion", "v1");
        staticSecret.put("kind", "Secret");
        staticSecret.put("type", "Opaque");
        staticSecret.put("data", secretData);
        JSONObject metadata = new JSONObject();
        metadata.put("name", name);
        metadata.put("namespace", "openunison");
        staticSecret.put("metadata", metadata);
        return staticSecret;
    }

    static String loadOption(CommandLine cmd,String name,Options options) {
		String val = cmd.getOptionValue(name);
		if (val == null) {
			System.err.println("Could not find option '" + name + "'");
			HelpFormatter formatter = new HelpFormatter();
			formatter.printHelp( "OpenUnison Kubernetes Artifact Deployer", options );
			System.exit(1);
			return null;
		} else {
			return val;
		}
	}
}