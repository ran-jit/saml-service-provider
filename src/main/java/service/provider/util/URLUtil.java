package service.provider.util;

import com.google.common.collect.Sets;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import service.provider.constants.SamlConstants.UtilConstants;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * author: Ranjith Manickam @ 30 July' 2018
 */
public class URLUtil {

    private final Pattern pattern;
    private final Set<String> domains;

    private static final Log LOGGER = LogFactory.getLog(URLUtil.class);

    public URLUtil(String domainsFilterFile) {
        this.domains = Sets.newHashSet();
        this.pattern = Pattern.compile("(\\d{1,3}\\.){3}(\\d{1,3})");
        this.init(domainsFilterFile);
    }

    private void init(String filePath) {
        try {
            InputStream resourceStream = null;
            try {
                resourceStream = (filePath != null && !filePath.isEmpty() && new File(filePath).exists())
                        ? new FileInputStream(filePath) : null;

                if (resourceStream == null) {
                    ClassLoader loader = Thread.currentThread().getContextClassLoader();
                    resourceStream = loader.getResourceAsStream(UtilConstants.DOMAINS_FILE_NAME);
                }

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setIgnoringComments(true);

                DocumentBuilder builder = factory.newDocumentBuilder();
                Document document = builder.parse(new InputSource(resourceStream));

                Element root = document.getDocumentElement();
                if (root != null && root.getTagName().equals(UtilConstants.DOMAINS_TAG_NAME)) {
                    UtilConstants.DOMAIN_TAGS.forEach(tagName -> this.read(root, tagName));
                } else {
                    throw new RuntimeException("xml file is not valid");
                }
            } finally {
                if (resourceStream != null) {
                    resourceStream.close();
                }
            }
        } catch (Exception ex) {
            LOGGER.error(ex.getMessage());
            throw new RuntimeException("Error in parsing domains xml file, " + ex.getMessage());
        }
    }

    private void addDomainSuffix(String tld) {
        this.domains.add(tld);
    }

    private boolean isDomainSuffix(String extension) {
        return this.domains.contains(extension);
    }


    private void read(Element element, String tagName) {
        NodeList children = element.getElementsByTagName(tagName);
        for (int i = 0; i < children.getLength(); ++i) {
            this.addDomainSuffix(((Element) children.item(i)).getAttribute(UtilConstants.DOMAIN_ATTRIBUTE_NAME));
        }
    }

    /**
     * Returns the domain name of the url. As an example,
     * <code>
     * getDomainName("http://ranjith.ranmanic.in/")
     * </code>
     * will return
     * <code>
     * ranmanic.in
     * </code>
     */
    public String getDomainName(String url) throws MalformedURLException {
        return getDomainName(new URL(url));
    }

    /**
     * Returns the domain name of the url. As an example,
     * <code>
     * getDomainName("new http://ranjith.ranmanic.in/")
     * </code>
     * will return
     * <code>
     * ranmanic.in
     * </code>
     */
    public String getDomainName(URL url) {
        String host = url.getHost();
        // it seems that java returns hostnames ending with .
        if (host.endsWith("."))
            host = host.substring(0, host.length() - 1);
        if (this.pattern.matcher(host).matches())
            return host;

        int index = 0;
        String candidate = host;
        for (; index >= 0; ) {
            index = candidate.indexOf('.');
            String subCandidate = candidate.substring(index + 1);
            if (isDomainSuffix(subCandidate)) {
                return candidate;
            }
            candidate = subCandidate;
        }
        return candidate;
    }

}
