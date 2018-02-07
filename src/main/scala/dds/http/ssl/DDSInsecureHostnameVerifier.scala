package dds.http.ssl

import javax.net.ssl.{SSLSession, HostnameVerifier}

class DDSInsecureHostnameVerifier extends HostnameVerifier {
	    override def verify(s: String, sslSession: SSLSession): Boolean = true
}