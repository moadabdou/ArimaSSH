module  com.arima.ssh.common{
    exports com.arima.ssh.common;
    exports com.arima.ssh.common.kex;
    exports com.arima.ssh.common.crypto;
    exports com.arima.ssh.common.channel;
    opens com.arima.ssh.common;
    opens com.arima.ssh.common.kex;
    opens com.arima.ssh.common.crypto;
    opens com.arima.ssh.common.channel;
    requires org.bouncycastle.provider;
    requires org.bouncycastle.pkix;
    requires org.slf4j;
}



