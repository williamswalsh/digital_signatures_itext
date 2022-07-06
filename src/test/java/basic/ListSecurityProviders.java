package basic;

import org.junit.Test;

import java.security.*;

public class ListSecurityProviders {

    @Test
    public void printProvidersAndCiphers() {
        for (Provider provider: Security.getProviders()) {
            System.out.println(provider.getName());
            for (String key: provider.stringPropertyNames())
                System.out.println("\t" + key + "\t" + provider.getProperty(key));
        }
    }
}
