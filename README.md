# Convert OpenUnison to Run on the OpenUnison Operator

First, deploy the OpenUnison Operator into your `openunison` namespace - https://github.com/TremoloSecurity/openunison-k8s-operator#kubernetes-and-openshift-3x

Next, create a `ConfigMap` that will store a list of secrets and whether or not the converter should run in "Dry Run" mode.  Its recommended to run first in dry run mode to inspect the `OpenUnison` custom resource that is generated and see what actions the converter will take.

```
kubectl create configmap converter-map --from-literal=DRY_RUN=true --from-literal=KEEP_SECRET=unisonKeystorePassword,K8S_DB_SECRET,AD_BIND_PASSWORD,SMTP_PASSWORD,REG_CRED_PASSWORD,OU_JDBC_PASSWORD -n openunison
```

**NOTE** The `KEEP_SECRET` lists the values from `ou.env` that should remain in a secret as opposed to be tracked directly in the custom resource.  The above is the default list but if you added any more you should make sure to adjust.


