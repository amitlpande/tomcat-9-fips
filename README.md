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
