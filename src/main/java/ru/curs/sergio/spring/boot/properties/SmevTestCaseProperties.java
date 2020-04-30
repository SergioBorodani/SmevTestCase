package ru.curs.sergio.spring.boot.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(SmevTestCaseProperties.PREFIX)
public class SmevTestCaseProperties {

    public static final String PREFIX = "smev.test.case";

    private String url;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    private String store;

    public String getStore() {
        return store;
    }

    public void setStore(String store) {
        this.store = store;
    }

    private String alias;

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    private String storePassword;

    public String getStorePassword() {
        return storePassword;
    }

    public void setStorePassword(String storePassword) {
        this.storePassword = storePassword;
    }

    private boolean testInteraction;

    public boolean isTestInteraction() {
        return testInteraction;
    }

    public void setTestInteraction(boolean testInteraction) {
        this.testInteraction = testInteraction;
    }

    private String xmlServiceDir;

    public String getXmlServiceDir() {
        return xmlServiceDir;
    }

    public void setXmlServiceDir(String xmlServiceDir) {
        this.xmlServiceDir = xmlServiceDir;
    }

    private String sg2Url;

    public String getSg2Url() {
        return sg2Url;
    }

    public void setSg2Url(String sg2Url) {
        this.sg2Url = sg2Url;
    }

    public SmevTestCaseProperties() {
    }

}
