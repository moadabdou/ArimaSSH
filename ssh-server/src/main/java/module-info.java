@SuppressWarnings("module")
module com.arima.ssh.server {
    requires com.arima.ssh.common;
    requires org.slf4j;
    requires pty4j;
    requires org.bouncycastle.pkix;
    requires org.bouncycastle.provider;
    requires libpam4j;
    opens com.arima.ssh.server;
}
