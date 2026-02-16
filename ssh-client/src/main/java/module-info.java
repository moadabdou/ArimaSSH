module com.arima.ssh.client {
    requires transitive com.arima.ssh.common;
    requires org.slf4j;
    requires org.jline;
    exports com.arima.ssh.client;
    opens com.arima.ssh.client;
} 
 