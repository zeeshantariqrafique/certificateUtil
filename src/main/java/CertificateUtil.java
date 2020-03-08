/*
 * The class is Utility class which can be used to read certificate out of HTTP request
 * */

import com.sun.istack.internal.Nullable;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class CertificateUtil {
    private X509Certificate x509Certificate;
    private static final String SSL_CLIENT_CERT_HEADER = "ssl_client_cert";

    public CertificateUtil() {
        //default constructor
    }

    public CertificateUtil(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public void setX509Certificate(X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    /*
     *@Description : Use this function to extract the X509 client cert (format *.crt / *.p12) from
     * Http request made to servlet or webservice.
     * @param : HttpServletRequest - received in servlet or Rest Controller
     * @Return : X509Certificate sent by client to server
     * */
    @Nullable
    public X509Certificate extractCertFromHTTPReqeustHeader(HttpServletRequest httpServletRequest) {
        /* Read the certificate information from the header 'ssl_client_cert' */
        String certificateInfo = httpServletRequest.getHeader(SSL_CLIENT_CERT_HEADER);

        if (certificateInfo == null || certificateInfo.isEmpty()) {
            return null;
        }

        try (InputStream is = new ByteArrayInputStream(Base64.getDecoder().decode(certificateInfo))) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
            return cert;
        } catch (Exception e) {
            return null;
        }
    }
}

