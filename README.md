## Kubernetes Security Best Practices

### Common Kubernetes Security Threats and Challenges
#### Kubernetes Pod-to-Pod Networking
* Kubernetes pod-to-pod networking—the ability for pods to communicate with each other—is crucial to the functioning of your applications. However, this communication can also pose a significant security risk.

* The default behavior in Kubernetes is to allow all pods to communicate freely with each other, regardless of their location within the cluster. This unrestricted communication can lead to a situation where a compromise in one pod can quickly lead to a compromise in others.

#### Configuration Management
* Configuration management is another area where Kubernetes security risks can arise. Misconfigurations can lead to security vulnerabilities, making your Kubernetes deployments susceptible to attacks.

* Common configuration missteps include the use of default settings, which often don’t prioritize security, granting root access to containers, and failure to limit privileges for Kubernetes API access. A misconfigured Kubernetes environment can leave your cluster exposed to unauthorized access, data breaches, and even denial-of-service attacks.

#### Software Supply Chain Risks
* Any Kubernetes deployment includes many software components, both within the Kubernetes distribution, included in container images, and running within live containers. All these components can be a source of security risks. 

* A primary risk in the software supply chain is the use of insecure or outdated software components. These components might contain known vulnerabilities that can be exploited by attackers. Additionally, the use of software from untrusted sources can lead to the introduction of malicious software into your Kubernetes deployments.

#### Runtime Threats
* Threats can affect nodes, pods, and containers at runtime. This makes runtime detection and response a critical aspect of Kubernetes security. It’s important to monitor Kubernetes deployments for suspicious activity and respond quickly to potential security incidents.

* Without effective runtime detection and response, attackers could gain access to a Kubernetes cluster, exfiltrate data, and disrupt critical services without being noticed.

#### Infrastructure Compromise
* Kubernetes nodes run on physical or virtual computers, which can be compromised by attackers if not properly secured. Network and storage systems used by Kubernetes clusters are also vulnerable to attack. Compromised Kubernetes infrastructure can lead to widespread disruption of Kubernetes workloads, data loss, and exposure of sensitive information.

### What Should You Secure in our Kubernetes Environment?
#### Node Security
* Nodes are the physical or virtual machines where containers are deployed and run. To ensure node security, it is essential to follow best practices such as keeping the operating system and Kubernetes components up to date with the latest security patches. Regular vulnerability scanning and penetration testing can help identify and fix any weaknesses in your nodes.

* Additionally, implementing strong access controls and authentication mechanisms is vital. Restricting access to the nodes and using secure communication protocols, such as SSH with public key authentication, can help prevent unauthorized access. Monitoring and logging node activity can also provide valuable insights into any potential security incidents.

#### Kubernetes API Security
* The Kubernetes API serves as the primary interface for managing and interacting with your cluster. As such, it is crucial to secure the API server to prevent unauthorized access and potential attacks. One fundamental step is to enable authentication and authorization mechanisms, such as role-based access control (RBAC), to control who can perform actions on the API server.

* It is also critical to secure communication with the API server. Enabling Transport Layer Security (TLS) encryption and using certificates for client-server authentication can protect sensitive data from interception and tampering. Regularly auditing the API server logs and monitoring for any suspicious activity can help detect and mitigate potential security breaches.

#### Kubernetes Network Security
* Network security is paramount in a Kubernetes environment, as containers communicate with each other and external services over the network. Implementing network policies can define the rules for inbound and outbound traffic, limiting access only to necessary services. Strong network segmentation and isolation can help contain potential security breaches.

* Additionally, encrypting network traffic using technologies like Virtual Private Networks (VPNs) or Secure Socket Layer (SSL) can protect data in transit. Deploying container firewalls within the Kubernetes environment provides another layer of protection.

#### Kubernetes Pod Security
* Pods are the smallest management unit in Kubernetes, representing one or more containers that share the same resources and network namespace. Securing pods is essential to protect the applications and data they contain. One step is to apply a security context that defines the desired security settings for pods. This can enforce restrictions on container communication, capabilities, and access to host resources.

* Regularly scanning container images for vulnerabilities and keeping them up to date can help mitigate the risk of compromised pods. Implementing container runtime security solutions can provide an additional layer of protection against threats targeting running pods.

#### Kubernetes Data Security
* Data security is a critical aspect of any Kubernetes environment, especially when dealing with sensitive or regulated data. Encrypting data at rest and in transit is essential to protect it from unauthorized access. Implementing strong access controls and encryption mechanisms, such as Kubernetes Secrets or external key management systems, can help safeguard sensitive data stored within your cluster.

* Monitoring and auditing data access and modifications is crucial to detect and respond to any potential security incidents promptly. Implementing backup and disaster recovery solutions can ensure data availability and integrity in the event of a security breach or data loss.

### 10 Kubernetes Security Best Practices 

#### 1. Enable Kubernetes Role-Based Access Control (RBAC)

* RBAC can help you define who has access to the Kubernetes API and what permissions they have. RBAC is usually enabled by default on Kubernetes 1.6 and higher (later on some hosted Kubernetes providers). Because Kubernetes combines authorization controllers, when you enable RBAC, you must also disable the legacy Attribute Based Access Control (ABAC).

* When using RBAC, prefer namespace-specific permissions instead of cluster-wide permissions. Even when debugging, do not grant cluster administrator privileges. It is safer to allow access only when necessary for your specific situation.

#### 2. Use Third-Party Authentication for API Server

* It is recommended to integrate Kubernetes with a third-party authentication provider (e.g. GitHub). This provides additional security features such as multi-factor authentication, and ensures that kube-apiserver does not change when users are added or removed. If possible, make sure that users are not managed at the API server level. You can also use OAuth 2.0 connectors like Dex.

#### 3. Protect etcd with TLS, Firewall and Encryption

* Since etcd stores the state of the cluster and its secrets, it is a sensitive resource and an attractive target for attackers. If unauthorized users gain access to etcd they can take over the entire cluster. Read access is also dangerous because malicious users can use it to elevate privileges.

##### To configure TLS for etcd for client-server communication, use the following configuration options:

* `cert-file=:` Certificate used for SSL/TLS connection with etcd

* `--key-file=:` Certificate key (not encrypted)

* `--client-cert-auth:` Specify that etcd should check incoming HTTPS requests to find a client certificate signed by a trusted CA

* `--trusted-ca-file=<path>:` Trusted certification authority

* `--auto-tls:` Use self-signed auto-generated certificate for client connections

##### To configure TLS for etcd for server-to-server communication, use the following configuration options:

* `--peer-cert-file=<path>:` Certificate used for SSL/TLS connections between peers

* `--peer-key-file=<path>:` Certificate key (not encrypted)

* `--peer-client-cert-auth:` When this option is set, etcd checks for valid signed client certificates on all incoming peer requests

* `--peer-trusted-ca-file=<path>:` Trusted certification authority

* `--peer-auto-tls:` Use auto-generated self-signed certificates for peer-to-peer connections

Also, set up a firewall between the API server and the etcd cluster. For example, run etcd on a separate node and use Calico to configure a firewall on that node.

###### Turn on encryption at rest for etcd secrets:

* Encryption is crucial for securing etcd, and is not turned on by default. You can enable it via kube-apiserver process, by passing the argument –encryption-provider-config. Within the configuration, you’ll need to select a provider to perform encryption, and define your secret keys. See the [documentation](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/) for more details.

#### 4. Isolate Kubernetes Nodes

* Kubernetes nodes must be on a separate network and should not be exposed directly to public networks. If possible, you should even avoid direct connections to the general corporate network. 

* This is only possible if Kubernetes control and data traffic are isolated. Otherwise, both flow through the same pipe, and open access to the data plane implies open access to the control plane. Ideally, nodes should be configured with an ingress controller, set to only allow connections from the master node on the specified port through the network access control list (ACL).

#### 5. Monitor Network Traffic to Limit Communications

* Containerized applications generally make extensive use of cluster networks. Observe active network traffic and compare it to the traffic allowed by Kubernetes network policy, to understand how your application interacts and identify anomalous communications.

* At the same time, if you compare active traffic to allowed traffic, you can identify network policies that are not actively used by cluster workloads. This information can be used to further strengthen the allowed network policy, removing unneeded connections to reduce the attack surface.

#### 6. Use Process Whitelisting

* Process whitelisting is an effective way to identify unexpected running processes. First, observe the application over a period of time to identify all processes running during normal application behavior. Then use this list as your whitelist for future application behavior.

* It is difficult to do runtime analysis at the process level. Several commercial security solutions are available that can help analyze and identify anomalies in running processes across clusters.

#### 7. Turn on Audit Logging

* Make sure that audit logging is enabled and you are monitoring unusual or unwanted API calls, especially authentication failures. These log entries display a “Forbidden” status message. Failure to authorize could mean that an attacker is trying to use stolen credentials. 

* When passing files to kube-apiserver, you can use the –audit-policy-file flag to turn on audit logging, and also define exactly which events should be logged. You can set one of four logging levels – None, Metadata only, Request which logs metadata and request but not responses, and RequestResponse which logs all three. For an example of an audit policy file, see the [documentation](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/).

* Managed Kubernetes providers can provide access to this data in their console, and set up notifications for authorization failures.

#### 8. Keep Kubernetes Version Up to Date

* You should always run the latest version of Kubernetes. Click for a [list of known Kubernetes vulnerabilities with severity scores](https://www.cvedetails.com/vulnerability-list/vendor_id-15867/product_id-34016/Kubernetes-Kubernetes.html).

Always plan to upgrade your Kubernetes version to the latest available version. Upgrading Kubernetes can be a complex process; if you are using a hosted Kubernetes provider, check if your provider handles automatic upgrades.

#### 9. Lock Down Kubelet

* The kubelet is an agent running on each node, which interacts with container runtime to launch pods and report metrics for nodes and pods. Each kubelet in the cluster exposes an API, which you can use to start and stop pods, and perform other operations. If an unauthorized user gains access to this API (on any node) and can run code on the cluster, they can compromise the entire cluster.

###### Here are configuration options you can use to lock the kubelet and reduce the attack surface:

* **Disable anonymous access with** `--anonymous-auth=false` so that unauthenticated requests get an error response. To do this, the API server needs to identify itself to the kubelet. This can be set by adding the flags `-kubelet-clientcertificate` and `--kubelet-client-key.`

* **Set** `--authorization` **mode** to a value other than AlwaysAllow to verify that requests are authorized. By default, the kubeadm installation tool sets this as a webhook, ensuring that kubelet calls SubjectAccessReview on the API server for authentication.

* **Include** `NodeRestriction` in the API server –admission-control setting, to restrict kubelet permissions. This only allows the kubelet to modify pods bound to its own node object.

* **Set** `–-read-only-port=0` to close read-only ports. This prevents anonymous users from accessing information about running workloads. This port does not allow hackers to control the cluster, but can be used during the reconnaissance phase of an attack.

* **Turn off cAdvisor**, which was used in old versions of Kubernetes to provide metrics, and has been replaced by Kubernetes API statistics. Set `-cadvisor-port=0` to avoid exposing information about running workloads. This is the default setting for Kubernetes v1.11. If you need to run cAdvisor, do so using a DaemonSet.