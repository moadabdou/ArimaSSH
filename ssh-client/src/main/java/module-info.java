module com.arima.ssh.client {
    requires transitive com.arima.ssh.common;
    requires org.slf4j;
    requires transitive org.jline;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix; 
    requires info.picocli;
    exports com.arima.ssh.client;
    exports com.arima.ssh.client.channel;
    opens com.arima.ssh.client;
} 
 