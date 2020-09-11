# tomcat-9-fips


There are two way we can enable FIPS for Tomcat.
The steps below use Bouncy Castle as the JCA/JCE provider.

1. By changing the JRE configuration:

This approach is typically useful when you have multiple Java applications using the same JRE and you want all the applications to run in FIPS compliant mode, using the same JCA/JCE provider. This way you just bundle up the security provider and update the JRE configuration and don't have to worry bundling up depencencies or changing/updating configuration per each Java application.

The downside of this approach is that we're customizing the JRE configuration here. This needs us to be extra careful when doing JRE upgrades. Specially if upgrding JRE isn't totally under our control, ensuring upgrade don't alter the configuration could be challenging.


Configure the JRE to use the FIPS compliant JCA/JCE provider. Steps here use the provider "BCFIPS” from Bouncy Castle.


Edit JRE_HOME/lib/java.security file and add below entries. The existing provider can stay there as it is but we need to ensure that the "BCFIPS" provider takes precedence, so add it in the list before any other providers.

We also need to modify the line that lists com.sun.net.ssl.internal.ssl.Provider to list the provider name of the FIPS 140 certified cryptographic provider. Please note that we have already added the class for the provider of the given name (BCFIPS in our case) in this file already.

security.provider.1=org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
security.provider.2=com.sun.net.ssl.internal.ssl.Provider BCFIPS
security.provider.3=sun.security.rsa.SunRsaSign
security.provider.4=sun.security.provider.Sun


We need to add the FIPS compliant cryptographic provider library under: JRE_HOME/lib/ext.

In this case, we put the bc-fips-1.0.2.jar under JRE_HOME/lib/ext.


Importing existing keystores can be done using keytool as below.

keytool -importkeystore -srckeystore <path to source key|trust store file> -srcstoretype <PKCS12|JKS|Or source key store's type> -deststoretype BCFKS -destkeystore <path to the destination key|trust store file> -srcstorepass <source key|trust store password> -srckeypass <destination key|trust store key password for importing private keys> -destkeypass <destination key|trust store key password of the imported private keys> -deststorepass  <destination key|trust store password> -providerpath "path to the bc-fips-1.0.2.jar" -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider


To import existing trust store (which has CA, trusted certificates), we need not mention the -srckeypass and -destkeypass arguments as trusted certificate entries are not password-protected.


To see if the key|trust store have been successfully imported to a BCFKS format.


keytool -list -keystore <Path to BCFKS key|trust store> -storepass <store password>-storetype BCFKS -providername BCFIPS -providerpath "path to the bc-fips-1.0.2.jar" -providerclass org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider
  

We could generate a new BCFIPS key store, trust store using the keytool, we need to use additional parameters -providername (BCFIPS), -providerpath (path to the bc-fips-1.0.2.jar) and -providerclass (org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider)
  

Edit Tomcat's server.xml file:

The Tomcat Web Server configuration needs to be updated to ensure FIPS compliant APIs are used by Tomcat all the time.

e.g. Below server.xml change is needed to ensure Tomcat uses a secure random number generator algorithm provided by BCFIPS. By default, Tomcat uses SHA1PRNG.

Service → Engine → Host → Context

```
<Context path="">
     <Manager className="org.apache.catalina.session.StandardManager" secureRandomProvider="BCFIPS" secureRandomAlgorithm="DEFAULT" />
</Context>
```

Also, all the connectors need to be updated to use a BCFIPS compatible key store and trust store (the compatible type, specifically is BCFKS).

```
<Connector SSLEnabled="true" URIEncoding="UTF-8" acceptCount="100"
allowTrace="false" compression="on" compressionMinSize="10"
connectionTimeout="20000"
disableUploadTimeout="true" enableLookups="false"
maxHttpHeaderSize="8192" noCompressionUserAgents="gozilla, traviata"
port="8773" protocol="org.apache.coyote.http11.Http11NioProtocol"
scheme="https" secure="true" useBodyEncodingForURI="true"
xpoweredBy="false">
   <SSLHostConfig certificateVerification="optional" truststoreFile="path to bcfks ktrust store created using above keytool commands" truststorePassword="****" truststoreType= "BCFKS" truststoreProvider="BCFIPS">
       <Certificate certificateKeystoreFile="path to bcfks key store create using above keytool commands" certificateKeystorePassword="****" certificateKeystoreType="BCFKS"
        certificateKeystoreProvider="BCFIPS"/>
    </SSLHostConfig>
</Connector>
```

In order to enforce BCFIPS is FIPS approved only more, we need to specify a JVM option.

To do that, create/edit setenv.bat|sh under TOMCAT_BASE/bin and add the following content (Please use correct syntax for *ix bash scripts).

set JAVA_OPTS=%JAVA_OPTS% -Djava.security.debug=all -org.bouncycastle.fips.approved_only=true


( -Djava.security.debug=all is just for debugging purposes - it helps us see/debug the security providers)

Now the Tomcat is all set to run in FIPS mode!

From the command prompt:

catalina.bat run

This starts the Tomcat!

Visit https://localhost:8773 to ensure we see the expected server certificate and upon accepting it, the Tomcat home page.
